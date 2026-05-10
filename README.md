# GoSniffer

A full-stack network packet sniffer and analyzer built in Go with a real-time web dashboard. Point it at any network interface, set your filters, and immediately see live traffic metrics — with one-click recording to PCAP, CSV, or JSON.

---

## Why GoSniffer

Most packet capture tools are either terminal-only (`tcpdump`) or heavyweight desktop apps (Wireshark). GoSniffer sits in the middle: a lightweight Go backend you can deploy anywhere, paired with a clean web UI you can open from any browser on the network.

- No desktop app required
- No Wireshark expertise needed
- REST API for automation
- Docker-ready, runs on Linux and macOS

---

## Features

### Live Metrics Dashboard
The dashboard connects over Server-Sent Events (SSE) and updates in real time without polling. You see packets per second, throughput in Mbps, drop rate, protocol breakdown, system memory, goroutine count, GC pressure, and disk usage — all in one view.

### Flexible BPF Filtering
Filters are built into [Berkeley Packet Filter](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) expressions under the hood. From the UI you select:
- Protocols: TCP, UDP, ICMP, DNS (or any combination)
- Source and destination IP addresses
- Port list (e.g. `80,443,8080`)

Apply a new filter and the sniffer hot-restarts in under a second.

### Multi-Format Packet Recording
Start a timed or manual recording session in any of three formats simultaneously:

| Format | Use Case |
|--------|----------|
| **PCAP** | Binary capture compatible with Wireshark and tcpdump |
| **JSON** | Structured records for scripts, log pipelines, or SIEM ingest |
| **CSV** | Spreadsheet analysis, quick grep, import into Excel/Pandas |

Every record includes: packet number, timestamp, length, src/dst MAC, EtherType, direction (inbound/outbound/broadcast), src/dst IP, protocol, TTL, src/dst port, and TCP flags + sequence/ack numbers.

### Prometheus Metrics
A `/metrics` endpoint exposes the full Prometheus metric set:
- `gosniffer_packets_total` and `gosniffer_bytes_total` by protocol
- `gosniffer_packets_dropped_total` by reason
- TCP connection tracking: active, opened, closed, resets, flags by port
- UDP and ICMP packet counters by port/type
- Bandwidth (bytes/s) by direction, unique IPs per sliding window
- `gosniffer_capture_active` gauge per interface

Plug directly into Grafana with zero extra configuration.

### Direction Detection
The sniffer reads the interface's own MAC address at startup and classifies every Ethernet frame as **inbound**, **outbound**, or **broadcast** — useful for quickly separating egress from ingress traffic in recordings.

---

## Architecture

```
Network Interface (libpcap)
        │
        ▼
  PacketStream
  (capture goroutine)
        │
        ▼
 PacketBroadcaster ──────────────────────────────┐
  (fan-out, drops tracked)                       │
        │                                        │
   ┌────┴────┐                          ┌────────┴────────┐
   │         │                          │                 │
Processor  MetricsService          RecordingService   (future consumers)
(N workers) (SSE + Prometheus)    (PCAP / CSV / JSON)
   │         │                          │
   ▼         ▼                          ▼
 writer    /metrics              capture_*.{pcap,csv,json}
           /sniffer/stream
```

**PacketBroadcaster** — a single goroutine reads from the capture source and fans packets out to all registered consumer channels. If a consumer channel is full the packet is dropped for that consumer (tracked as a metric) but delivery continues to all others.

**PacketProcessor** — spawns N worker goroutines. Writers that support concurrent writes (CSV, JSON) run with the full worker pool. Writers that require sequential ordering (PCAP) are automatically reduced to 1 worker.

**RecordingService** — manages recording sessions per format independently. Each session has an optional duration timer; when it fires the writer flushes, closes the file cleanly, and unregisters from the broadcaster.

**MetricsService** — aggregates per-packet stats and exposes them both as SSE stream (for the live dashboard) and as a Prometheus `/metrics` endpoint.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.25, [gopacket](https://github.com/google/gopacket), [chi](https://github.com/go-chi/chi) |
| Metrics | [prometheus/client_golang](https://github.com/prometheus/client_golang) |
| Config | [cleanenv](https://github.com/ilyakaznacheev/cleanenv) + env file |
| Frontend | Next.js 15, Tailwind CSS |
| Container | Docker (Go backend + Node frontend, separate images) |

---

## Getting Started

### With Docker

```bash
# Backend
docker build -t gosniffer-backend .
docker run --net=host --cap-add NET_ADMIN gosniffer-backend

# Frontend
docker build -f Dockerfile.frontend -t gosniffer-frontend .
docker run -p 3000:3000 gosniffer-frontend
```

> `--net=host` and `NET_ADMIN` are required for raw packet capture.

### Local (Go + Node)

```bash
# Backend
go run ./cmd/GoSniffer

# Frontend
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

### Configuration

Copy `.env` and set your defaults:

```env
SNIFFER_DEVICE=eth0
HTTP_PORT=8080
```

Filters and device can also be changed live from the UI without restarting the process.

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/sniffer/devices` | List available network interfaces |
| `GET/POST` | `/sniffer/config/filters` | Read or update BPF filters |
| `POST` | `/sniffer/config/apply` | Apply new device + filters and restart |
| `POST` | `/sniffer/recording/{format}/start` | Start recording (`format`: pcap, csv, json) |
| `POST` | `/sniffer/recording/{format}/stop` | Stop recording |
| `GET` | `/sniffer/recording/{format}/status` | Recording status |
| `GET` | `/sniffer/stream` | SSE stream of live metrics |
| `GET` | `/metrics` | Prometheus metrics endpoint |
| `GET` | `/ping` | Health check |

---

## Project Structure

```
.
├── cmd/GoSniffer/          # Entry point
├── internal/
│   ├── sniffer/
│   │   ├── capture/        # libpcap interface via gopacket
│   │   ├── processor/
│   │   │   ├── broadcaster/    # Fan-out to consumers
│   │   │   └── processor.go    # Worker pool
│   │   ├── output/
│   │   │   ├── toFife/
│   │   │   │   ├── csvwriter/
│   │   │   │   ├── jsonwriter/
│   │   │   │   └── pcapwriter/
│   │   │   └── filemanager/    # Capture file lifecycle
│   │   ├── BpfFilter/      # BPF expression builder
│   │   ├── metrics_service.go
│   │   └── service.go
│   ├── http-server/
│   │   ├── handlers/       # REST handlers
│   │   └── middleware/
│   ├── metrics/            # Prometheus collector
│   └── config/             # Config structs
└── frontend/               # Next.js dashboard
    └── src/app/dashboard/
        ├── page.tsx         # Live metrics
        ├── recording/       # Recording control
        ├── configuration/   # Device + filter setup
        ├── devices/
        ├── filters/
        └── files/           # Capture file browser
```
