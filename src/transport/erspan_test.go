package transport

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestIPChecksum verifies that the checksum of a correct IP header is zero when re-summed.
func TestIPChecksum(t *testing.T) {
	hdr := [20]byte{}
	hdr[0] = (4 << 4) | 5 // ver=4, IHL=5
	hdr[8] = 64            // TTL
	hdr[9] = 17            // UDP
	binary.BigEndian.PutUint16(hdr[2:4], 40)
	copy(hdr[12:16], net.ParseIP("10.0.0.1").To4())
	copy(hdr[16:20], net.ParseIP("10.0.0.2").To4())
	cksum := ipChecksum(hdr[:])
	binary.BigEndian.PutUint16(hdr[10:12], cksum)

	// Re-summing a correct header should give 0xFFFF (ones-complement zero).
	var sum uint32
	for i := 0; i+1 < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if sum != 0xFFFF {
		t.Errorf("expected 0xFFFF after re-sum, got 0x%04X", sum)
	}
}

func newTestClient(version uint8) *ERSPANClient {
	c := &ERSPANClient{
		version:   version,
		sessionID: 7,
		fd:        -1,
	}
	copy(c.srcIP[:], net.ParseIP("192.168.1.1").To4())
	copy(c.dstIP[:], net.ParseIP("10.0.0.1").To4())
	return c
}

func buildTestPacket(t *testing.T, version uint8) []byte {
	t.Helper()
	c := newTestClient(version)
	pkt := ERSPANPacket{
		SrcIP:   "172.16.0.1",
		DstIP:   "172.16.0.2",
		SrcPort: 5060,
		DstPort: 5060,
		Payload: []byte("INVITE sip:bob@example.com SIP/2.0\r\n"),
	}
	buf := make([]byte, 0, 256)
	buf = c.appendOuterIP(buf, pkt)
	buf = c.appendGRE(buf)
	buf = c.appendERSPANHdr(buf)
	buf = appendInnerEth(buf)
	buf = appendInnerIP(buf, pkt)
	buf = appendInnerUDP(buf, pkt)
	buf = append(buf, pkt.Payload...)
	fixOuterIP(buf)
	return buf
}

// TestTypeIPacketLayout validates Type I (raw GRE) wire format.
func TestTypeIPacketLayout(t *testing.T) {
	buf := buildTestPacket(t, 1)

	// Outer IP
	if buf[9] != ipProtoGRE {
		t.Errorf("outer IP protocol: want %d, got %d", ipProtoGRE, buf[9])
	}
	totalLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if totalLen != len(buf) {
		t.Errorf("outer IP total_len: want %d, got %d", len(buf), totalLen)
	}

	// GRE flags (Type I: no sequence number, no ERSPAN header)
	greFlags := binary.BigEndian.Uint16(buf[20:22])
	if greFlags != 0 {
		t.Errorf("Type I GRE flags: want 0, got 0x%04X", greFlags)
	}
	greProto := binary.BigEndian.Uint16(buf[22:24])
	if greProto != greProtoTypeI {
		t.Errorf("Type I GRE proto: want 0x%04X, got 0x%04X", greProtoTypeI, greProto)
	}

	// After GRE (4 bytes), inner Eth starts at offset 24.
	ethOff := 24
	ethertype := binary.BigEndian.Uint16(buf[ethOff+12 : ethOff+14])
	if ethertype != 0x0800 {
		t.Errorf("inner ethertype: want 0x0800, got 0x%04X", ethertype)
	}
}

// TestTypeIIPacketLayout validates ERSPAN Type II wire format.
func TestTypeIIPacketLayout(t *testing.T) {
	buf := buildTestPacket(t, 2)

	// GRE flags must have sequence-number bit set.
	greFlags := binary.BigEndian.Uint16(buf[20:22])
	if greFlags != greFlagSeq {
		t.Errorf("Type II GRE flags: want 0x%04X, got 0x%04X", greFlagSeq, greFlags)
	}
	greProto := binary.BigEndian.Uint16(buf[22:24])
	if greProto != greProtoTypeII {
		t.Errorf("Type II GRE proto: want 0x%04X, got 0x%04X", greProtoTypeII, greProto)
	}

	// GRE(4) + seq(4) = 8 bytes; ERSPAN-II header starts at 20+8=28.
	erspan2Off := 28
	// Word 0: ver[15:12]=1
	ver := binary.BigEndian.Uint16(buf[erspan2Off:erspan2Off+2]) >> 12
	if ver != 1 {
		t.Errorf("ERSPAN-II ver field: want 1, got %d", ver)
	}
	// Word 1: session_id in bits [9:0]
	sid := binary.BigEndian.Uint16(buf[erspan2Off+2:erspan2Off+4]) & 0x3FF
	if sid != 7 {
		t.Errorf("ERSPAN-II session_id: want 7, got %d", sid)
	}

	// After GRE(4)+seq(4)+ERSPAN-II(8) = 16 bytes; inner Eth at 20+16=36.
	ethOff := 36
	ethertype := binary.BigEndian.Uint16(buf[ethOff+12 : ethOff+14])
	if ethertype != 0x0800 {
		t.Errorf("inner ethertype: want 0x0800, got 0x%04X", ethertype)
	}
}

// TestTypeIIIPacketLayout validates ERSPAN Type III wire format.
func TestTypeIIIPacketLayout(t *testing.T) {
	buf := buildTestPacket(t, 3)

	greProto := binary.BigEndian.Uint16(buf[22:24])
	if greProto != greProtoTypeIII {
		t.Errorf("Type III GRE proto: want 0x%04X, got 0x%04X", greProtoTypeIII, greProto)
	}

	// GRE(4)+seq(4)+ERSPAN-III(12)=20; inner Eth at 20+20=40.
	erspan3Off := 28
	ver := binary.BigEndian.Uint16(buf[erspan3Off:erspan3Off+2]) >> 12
	if ver != 3 {
		t.Errorf("ERSPAN-III ver field: want 3, got %d", ver)
	}
	sid := binary.BigEndian.Uint16(buf[erspan3Off+2:erspan3Off+4]) & 0x3FF
	if sid != 7 {
		t.Errorf("ERSPAN-III session_id: want 7, got %d", sid)
	}

	ethOff := 40
	ethertype := binary.BigEndian.Uint16(buf[ethOff+12 : ethOff+14])
	if ethertype != 0x0800 {
		t.Errorf("inner ethertype: want 0x0800, got 0x%04X", ethertype)
	}
}

// TestSeqNumIncrement verifies Type II seq_num increments per packet.
func TestSeqNumIncrement(t *testing.T) {
	c := newTestClient(2)
	pkt := ERSPANPacket{SrcIP: "1.2.3.4", DstIP: "5.6.7.8", SrcPort: 5060, DstPort: 5060, Payload: []byte("x")}

	buf1 := make([]byte, 0, 128)
	buf1 = c.appendOuterIP(buf1, pkt)
	buf1 = c.appendGRE(buf1)
	// outer IP(20) + GRE flags(2) + GRE proto(2) = 24; seq at 24:28
	seq1 := binary.BigEndian.Uint32(buf1[24:28])

	buf2 := make([]byte, 0, 128)
	buf2 = c.appendOuterIP(buf2, pkt)
	buf2 = c.appendGRE(buf2)
	seq2 := binary.BigEndian.Uint32(buf2[24:28])

	if seq2 != seq1+1 {
		t.Errorf("seq_num not incrementing: seq1=%d seq2=%d", seq1, seq2)
	}
}

// TestTypeINoSeqNum validates that Type I never writes a sequence field.
func TestTypeINoSeqNum(t *testing.T) {
	c := newTestClient(1)
	pkt := ERSPANPacket{SrcIP: "1.2.3.4", DstIP: "5.6.7.8", SrcPort: 5060, DstPort: 5060, Payload: []byte("x")}

	buf := make([]byte, 0, 128)
	buf = c.appendOuterIP(buf, pkt)
	buf = c.appendGRE(buf)
	// Type I: GRE base = 4 bytes. Total GRE block = 4 bytes. Next is inner Eth at offset 24.
	// The inner Eth should NOT have sequence number prepended.
	buf = appendInnerEth(buf)

	// Byte at 24 should be start of Eth dst MAC (0x00).
	if buf[24] != 0 {
		t.Errorf("Type I: unexpected byte at offset 24 (expected Eth dst, got 0x%02X)", buf[24])
	}
	if len(buf) != 20+4+14 {
		t.Errorf("Type I: unexpected buffer length %d (want %d)", len(buf), 20+4+14)
	}
}

// TestOuterIPChecksum verifies fixOuterIP produces a valid checksum.
func TestOuterIPChecksum(t *testing.T) {
	buf := buildTestPacket(t, 2)
	// Zeroing the checksum field and recomputing should match.
	cksum := binary.BigEndian.Uint16(buf[10:12])
	binary.BigEndian.PutUint16(buf[10:12], 0)
	recomputed := ipChecksum(buf[:20])
	if recomputed != cksum {
		t.Errorf("outer IP checksum mismatch: stored=0x%04X recomputed=0x%04X", cksum, recomputed)
	}
}
