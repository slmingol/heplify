// Package transport — ERSPAN output transport.
//
// Sends captured SIP/RTP encapsulated in GRE or ERSPAN (Type I/II/III) via
// a raw IP socket. The inner frame is a synthetic Ethernet+IP+UDP wrapper
// around the SIP payload using the original captured src/dst IPs and ports,
// matching what captagent's transport_erspan module produces.
//
// Wire formats:
//
//	Type I:   [outer IP][GRE 4B][inner Eth 14B][inner IP 20B][inner UDP 8B][payload]
//	Type II:  [outer IP][GRE 4B][SeqNum 4B][ERSPAN-II 8B][inner Eth][inner IP][inner UDP][payload]
//	Type III: [outer IP][GRE 4B][SeqNum 4B][ERSPAN-III 12B][inner Eth][inner IP][inner UDP][payload]
//
// Requires CAP_NET_RAW (or root) at runtime. Linux only.

package transport

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/rs/zerolog/log"
)

// ERSPANPacket carries the per-packet fields needed to build an ERSPAN frame.
type ERSPANPacket struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Payload []byte
}

// GRE/ERSPAN protocol constants (IANA / Cisco drafts).
const (
	ipProtoGRE   = 47
	greProtoTypeI   = 0x6558 // transparent Ethernet bridging
	greProtoTypeII  = 0x88BE // ERSPAN Type II
	greProtoTypeIII = 0x22EB // ERSPAN Type III
	greFlagSeq      = 0x1000 // sequence-number-present bit in GRE flags

	maxERSPANPayload = 65453 // 65535 - 20(IP) - 4(GRE) - 4(seq) - 12(ERSPAN-III) - 14(eth) - 20(IP) - 8(UDP)
)

// ERSPANClient sends ERSPAN-encapsulated packets via a raw socket.
type ERSPANClient struct {
	dstIP     [4]byte
	srcIP     [4]byte
	version   uint8  // 1, 2, or 3
	sessionID uint16 // 0-1023
	seq       atomic.Uint32
	fd        int
}

// newERSPANClient opens a raw GRE socket and returns a configured client.
func newERSPANClient(dstIPStr, srcIPStr string, version uint8, sessionID uint16) (*ERSPANClient, error) {
	if version < 1 || version > 3 {
		return nil, fmt.Errorf("erspan: invalid version %d (must be 1, 2, or 3)", version)
	}
	if sessionID > 1023 {
		return nil, fmt.Errorf("erspan: session_id %d exceeds 10-bit max (1023)", sessionID)
	}

	dstIP := net.ParseIP(dstIPStr)
	if dstIP == nil {
		return nil, fmt.Errorf("erspan: invalid dst ip %q", dstIPStr)
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		return nil, fmt.Errorf("erspan: dst ip must be IPv4, got %q", dstIPStr)
	}

	var srcIP4 [4]byte
	if srcIPStr != "" {
		srcIP := net.ParseIP(srcIPStr)
		if srcIP == nil {
			return nil, fmt.Errorf("erspan: invalid src ip %q", srcIPStr)
		}
		srcIP = srcIP.To4()
		if srcIP == nil {
			return nil, fmt.Errorf("erspan: src ip must be IPv4, got %q", srcIPStr)
		}
		copy(srcIP4[:], srcIP)
	}

	fd, err := openRawGRESocket()
	if err != nil {
		return nil, fmt.Errorf("erspan: raw socket: %w", err)
	}

	c := &ERSPANClient{
		version:   version,
		sessionID: sessionID & 0x3FF,
		fd:        fd,
	}
	copy(c.dstIP[:], dstIP)
	copy(c.srcIP[:], srcIP4[:])
	return c, nil
}

// Send encapsulates pkt in GRE/ERSPAN and transmits it.
func (c *ERSPANClient) Send(pkt ERSPANPacket) error {
	if len(pkt.Payload) > maxERSPANPayload {
		return fmt.Errorf("erspan: payload %d > max %d", len(pkt.Payload), maxERSPANPayload)
	}

	buf := make([]byte, 0, 20+4+12+14+20+8+len(pkt.Payload))
	buf = c.appendOuterIP(buf, pkt)
	buf = c.appendGRE(buf)
	buf = c.appendERSPANHdr(buf)
	buf = appendInnerEth(buf)
	buf = appendInnerIP(buf, pkt)
	buf = appendInnerUDP(buf, pkt)
	buf = append(buf, pkt.Payload...)

	// Fix outer IP total length and checksum now that we know the full size.
	fixOuterIP(buf)

	return sendRaw(c.fd, c.dstIP, buf)
}

// Close closes the underlying raw socket.
func (c *ERSPANClient) Close() {
	if c.fd >= 0 {
		closeRawSocket(c.fd)
		c.fd = -1
	}
}

// appendOuterIP writes a zero-checksum outer IPv4 header (checksum filled by fixOuterIP).
func (c *ERSPANClient) appendOuterIP(buf []byte, pkt ERSPANPacket) []byte {
	hdr := [20]byte{}
	hdr[0] = (4 << 4) | 5     // ver=4, IHL=5
	hdr[8] = 64               // TTL
	hdr[9] = ipProtoGRE       // protocol
	// tot_len at [2:4] left zero — fixOuterIP fills it
	copy(hdr[12:16], c.srcIP[:])
	copy(hdr[16:20], c.dstIP[:])
	return append(buf, hdr[:]...)
}

func (c *ERSPANClient) appendGRE(buf []byte) []byte {
	var flags uint16
	var proto uint16
	switch c.version {
	case 1:
		proto = greProtoTypeI
	case 3:
		flags = greFlagSeq
		proto = greProtoTypeIII
	default:
		flags = greFlagSeq
		proto = greProtoTypeII
	}
	buf = appendUint16BE(buf, flags)
	buf = appendUint16BE(buf, proto)
	if c.version != 1 {
		seq := c.seq.Add(1) - 1
		buf = appendUint32BE(buf, seq)
	}
	return buf
}

func (c *ERSPANClient) appendERSPANHdr(buf []byte) []byte {
	switch c.version {
	case 2:
		// ERSPAN Type II: 8 bytes
		// Word 0: ver[15:12]=0001, vlan[11:0]=0
		buf = appendUint16BE(buf, 1<<12)
		// Word 1: cos[15:13]=0, en[12:11]=0, T[10]=0, session[9:0]
		buf = appendUint16BE(buf, c.sessionID)
		// Word 2+3: reserved_index
		buf = appendUint32BE(buf, 0)
	case 3:
		// ERSPAN Type III: 12 bytes
		// Word 0: ver[15:12]=0011, vlan[11:0]=0
		buf = appendUint16BE(buf, 3<<12)
		// Word 1: cos[15:13]=0, bso[12:11]=0, T[10]=0, session_id[9:0]
		buf = appendUint16BE(buf, c.sessionID)
		// Word 2: timestamp (seconds — filled at send time is fine for Ativa)
		buf = appendUint32BE(buf, 0)
		// Word 3: sgt[31:16]=0, flags[15:0]=0
		buf = appendUint32BE(buf, 0)
	// Type I: no ERSPAN header
	}
	return buf
}

func appendInnerEth(buf []byte) []byte {
	// 14-byte synthetic Ethernet header: all-zero MACs, ethertype=0x0800 (IPv4)
	eth := [14]byte{}
	eth[12] = 0x08 // ethertype high byte
	// eth[13] = 0x00 already
	return append(buf, eth[:]...)
}

func appendInnerIP(buf []byte, pkt ERSPANPacket) []byte {
	hdr := [20]byte{}
	hdr[0] = (4 << 4) | 5 // ver=4, IHL=5
	hdr[8] = 64            // TTL
	hdr[9] = 17            // protocol=UDP

	innerTotal := uint16(20 + 8 + len(pkt.Payload))
	binary.BigEndian.PutUint16(hdr[2:4], innerTotal)

	if ip := net.ParseIP(pkt.SrcIP); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			copy(hdr[12:16], ip4)
		}
	}
	if ip := net.ParseIP(pkt.DstIP); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			copy(hdr[16:20], ip4)
		}
	}

	binary.BigEndian.PutUint16(hdr[10:12], ipChecksum(hdr[:]))
	return append(buf, hdr[:]...)
}

func appendInnerUDP(buf []byte, pkt ERSPANPacket) []byte {
	udp := [8]byte{}
	binary.BigEndian.PutUint16(udp[0:2], pkt.SrcPort)
	binary.BigEndian.PutUint16(udp[2:4], pkt.DstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(pkt.Payload)))
	// checksum left zero (optional for UDP)
	return append(buf, udp[:]...)
}

// fixOuterIP fills the total-length field and recomputes the IP checksum.
func fixOuterIP(buf []byte) {
	if len(buf) < 20 {
		return
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	binary.BigEndian.PutUint16(buf[10:12], 0)
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum(buf[:20]))
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 != 0 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func appendUint16BE(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

func appendUint32BE(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// logERSPANSend logs a debug-level send event (kept out of the hot path via log level check).
func logERSPANSend(dstIP [4]byte, version uint8, n int) {
	log.Debug().
		Str("dst", net.IP(dstIP[:]).String()).
		Uint8("erspan_version", version).
		Int("bytes", n).
		Msg("ERSPAN packet sent")
}
