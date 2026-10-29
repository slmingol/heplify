# Collector

heplify can act as an inbound HEP relay: other agents or HEP-capable devices send packets to heplify, which re-forwards them via `transport[]` to the upstream collector (e.g. Homer).

```
Agent A ──HEP──▶ heplify (collector_settings) ──HEP──▶ transport[] ──▶ Homer
Agent B ──HEP──▶
```

## Configuration

```json
"collector_settings": {
  "active": false,
  "host":   "0.0.0.0",
  "port":   9060,
  "proto":  "udp"
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `active` | `false` | Enable the inbound HEP listener |
| `host` | `0.0.0.0` | Listen address |
| `port` | `9060` | Listen port |
| `proto` | `"udp"` | Transport protocol — see table below |

> **Privileged ports:** a `port` below 1024 (for example `514`) can only be bound with `CAP_NET_BIND_SERVICE`. When heplify runs from the deb/rpm package (systemd service, unprivileged `heplify` user), this capability is not granted by default and heplify fails with `bind: permission denied`. Use a port of 1024 or above, or add a drop-in (`systemctl edit heplify`) with `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`. The same applies to the API and Prometheus listeners.

### Supported protocols

| Value | Description |
|-------|-------------|
| `udp` | UDP listener only (default) |
| `tcp` | TCP listener only |
| `both` | UDP and TCP listeners on the same port |
| `http2` | Cleartext HTTP/2 (h2c), endpoint `POST /hep` with `Content-Type: application/octet-stream` |

## CLI flag

```
-hin  proto:host:port    Enable inbound HEP collector, e.g. -hin udp:0.0.0.0:9060
```

## Behaviour

- Received HEP packets are decoded and validated.
- If `hep_settings.collect_only_sip: true`, non-SIP proto types are silently dropped.
- If `hep_settings.replace_token: true`, the `NodePW` (and optionally `NodeID` / `NodeName`) in each packet is replaced with values from `system_settings` before re-forwarding.
- Re-encoded packets are sent to all active `transport[]` entries.
