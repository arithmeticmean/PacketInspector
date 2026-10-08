# PacketInspector

A small, multi-threaded **TLS SNI filter** for Linux routers.

PacketInspector sits on the kernel's `FORWARD` path via **NFQUEUE**, reads the
`server_name` (SNI) out of each TLS ClientHello, and **drops the whole
connection** if the hostname is on a blocklist. Everything else is accepted
untouched. No proxy, no MITM, no certificates: it decides from the one
plaintext field TLS leaves visible.

## Architecture

```
                        ┌──────────────────────── Linux router ────────────────────────┐
                        │                                                              │
  client ──── TCP:443 ──┼─▶ iptables FORWARD ─▶ PACKETINSPECTOR chain                  │
                        │                         │  -j NFQUEUE --queue-balance 0:N-1  │
                        │                         │            --queue-bypass          │
                        │        ┌────────────────┼──────────────────┐                 │
                        │        ▼                ▼                  ▼                 │
                        │   NFQUEUE 0        NFQUEUE 1   ...    NFQUEUE N-1            │
                        │        │                │                  │      kernel     │
                        │ ───────┼────────────────┼──────────────────┼──────────────── │
                        │        ▼                ▼                  ▼      userspace  │
                        │   ┌─────────┐      ┌─────────┐        ┌─────────┐            │
                        │   │Worker 0 │      │Worker 1 │  ...   │Worker N │            │
                        │   │ NFQueue │      │ NFQueue │        │ NFQueue │            │
                        │   │ TCP     │      │ TCP     │        │ TCP     │            │
                        │   │ reasm + │      │ reasm + │        │ reasm + │            │
                        │   │ SNI     │      │ SNI     │        │ SNI     │            │
                        │   └────┬────┘      └────┬────┘        └────┬────┘            │
                        │        └────────────────┼──────────────────┘                 │
                        │                         ▼                                    │
                        │              shared read-only BlockList                      │
                        │                         │                                    │
                        │              verdict: NF_ACCEPT / NF_DROP ──────────────▶ server
                        └──────────────────────────────────────────────────────────────┘
```

- **One worker = one queue = one thread.** The kernel hashes each flow to a
  queue, so all packets of a connection land on the same worker: no locks, no
  cross-thread state.
- **Per-packet path:** dissect → flow lookup → verdict. Packets of flows that
  aren't being inspected are verdicted immediately with zero copies.
- **TLS flows:** a SYN opens a tracked flow. ClientHello segments are held and
  reassembled (handles a ClientHello split across segments / out of order) until
  the SNI is known, then the whole flow is `ACCEPT`ed or `DROP`ped. A block is
  remembered for the rest of the connection.
- **Fail-open:** `--queue-bypass` means traffic keeps flowing if the inspector
  isn't running; idle flows are swept so held packets are never stranded.
- **IPv4 + IPv6.**

| File | Role |
|---|---|
| `src/main.cpp` | Startup, signal handling, worker lifecycle, stats |
| `src/NFQueue.cpp` | Thin wrapper over `libnetfilter_queue` (bind, poll, verdict) |
| `src/worker.cpp` | Event loop: one queue + one extractor per thread |
| `src/hostname_extractor.cpp` | Flow tracking, TCP reassembly, SNI parsing |
| `src/blocklist.cpp` | Exact and `*.wildcard` hostname matching |
| `scripts/nfqueue.sh.in` | Installs / removes the iptables rules |

## Build

Requirements: Linux, CMake ≥ 3.9, a C++20 compiler, `libnetfilter_queue`,
`libmnl`, `iptables` (and `ip6tables` for IPv6). PcapPlusPlus is downloaded
automatically at configure time.

```bash
# Arch
sudo pacman -S libnetfilter_queue libmnl iptables
# Debian / Ubuntu
sudo apt install libnetfilter-queue-dev libmnl-dev iptables

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

This produces `build/PacketInspector` and `build/nfqueue.sh`.

## Run

**1. Write a blocklist** — one hostname per line:

```text
# exactly example.com
example.com
# any subdomain of tracker.net (not the apex itself)
*.tracker.net
```

**2. Install the iptables rules** (worker count must match `-j`):

```bash
sudo ./build/nfqueue.sh up 0 4        # queues 0..3, TCP 443/8443
sudo ./build/nfqueue.sh status
```

`MODE=ctdir` inspects the client→server direction of *every* connection
instead of just ports 443/8443; `PORTS=...` changes the port list.

**3. Start the inspector:**

```bash
sudo ./build/PacketInspector -j 4 -nfq 0 -v blocklist.txt
```

| Flag | Meaning | Default |
|---|---|---|
| `-j <n>` | worker threads / queues | 4 |
| `-nfq <n>` | first queue number | 0 |
| `-b <path>` | blocklist (or positional) | `blocklist.txt` |
| `-v` | log `ALLOW`/`BLOCK <host>` per flow | off |
| `--stats <s>` | print counters to stderr every *s* seconds | off |
| `-pin <cpu>` / `-pin-stride <n>` | pin worker *i* to CPU `cpu + i*stride` | off |
| `--passthrough` | accept everything without inspecting (benchmark baseline) | off |

Run `./build/PacketInspector --help` for the rest. Stop with `Ctrl-C`, then
`sudo ./build/nfqueue.sh down` to remove the rules.

## Example: blocking curl

The rules live in `FORWARD`, so the traffic has to be *routed* through the
machine — locally generated traffic is not inspected. The easiest way to try
it on one box is a network namespace that uses the host as its router:

```bash
# client namespace, routed + NATed through the host
sudo ip netns add client
sudo ip link add veth-host type veth peer name veth-cli
sudo ip link set veth-cli netns client
sudo ip addr add 10.200.0.1/24 dev veth-host && sudo ip link set veth-host up
sudo ip netns exec client ip addr add 10.200.0.2/24 dev veth-cli
sudo ip netns exec client ip link set veth-cli up
sudo ip netns exec client ip route add default via 10.200.0.1
sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -j MASQUERADE
sudo mkdir -p /etc/netns/client && echo "nameserver 1.1.1.1" | sudo tee /etc/netns/client/resolv.conf

# rules + inspector
echo "example.com" > blocklist.txt
sudo ./build/nfqueue.sh up 0 1
sudo ./build/PacketInspector -j 1 -v blocklist.txt
```

In another terminal:

```console
$ sudo ip netns exec client curl -sS -o /dev/null -w '%{http_code}\n' https://wikipedia.org
301

$ sudo ip netns exec client curl -sS -m 5 https://example.com
curl: (28) Operation timed out after 5002 milliseconds with 0 bytes received
```

and the inspector logs:

```text
ALLOW wikipedia.org
BLOCK example.com
```

The TCP handshake to `example.com` completes, but the ClientHello and every
packet after it are dropped, so TLS never finishes. Clean up with
`sudo ./build/nfqueue.sh down`, `sudo ip netns del client`, and deleting the
`MASQUERADE` rule (`-D` instead of `-A`).

## Test

### Unit tests (no root)

Packet dissection, blocklist matching and the SNI extractor, with GoogleTest:

```bash
cmake -B build -DPACKET_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build -L unit --output-on-failure
```

### End-to-end tests (root)

Builds a real routed path out of three network namespaces and runs the real
inspector and the real `nfqueue.sh` rules in the middle:

```
   pi-e2e-cli              pi-e2e-rtr               pi-e2e-srv
 ┌────────────┐  veth  ┌────────────────┐  veth  ┌──────────────┐
 │ e2e_sender ├────────┤ FORWARD + rules├────────┤ e2e_receiver │
 └────────────┘        └───────┬────────┘        └──────────────┘
                               │ NFQUEUE
                        PacketInspector
```

The sender injects hand-crafted TCP/TLS frames (blocked/allowed/wildcard SNI,
split and out-of-order ClientHellos, missing SNI, idle flows, IPv6, …), and the
receiver checks per packet whether it was delivered or dropped. The corpus runs
twice: with 1 worker and with 4 workers behind `--queue-balance`, which checks
that a flow's segments always reach the same worker. Nothing touches the host's
own networking.

```bash
cmake -B build -DPACKET_BUILD_E2E=ON
cmake --build build -j
sudo ./build/e2e/run.sh          # -v for verbose
```

## Benchmark

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DPACKET_BUILD_BENCH=ON
cmake --build build -j
sudo ./build/bench/run.sh [seconds-per-run]     # default 4
```

Same three-namespace topology as the e2e suite, but tuned for volume. Packets
are **pre-crafted and injected directly** onto the veth, so there are no real
TCP or TLS handshakes and the load generator isn't what gets measured. Each
packet carries a `CLOCK_MONOTONIC` timestamp (in the payload, or in the
ClientHello's `random` field) so the receiver can compute one-way latency.

It sweeps **1, 2, 4 workers × several offered rates × four profiles**:

| Profile | What runs | What it isolates |
|---|---|---|
| `wire` | no iptables rule | baseline: veth + forwarding |
| `passthrough` | NFQUEUE round trip, always ACCEPT | cost of the queue itself |
| `bulk` | payload packets on untracked flows | the common case: inspection overhead |
| `tls` | every flow opens with SYN + full ClientHello | worst case: track, reassemble, parse SNI |

Numbers come from the kernel wherever possible, not from userspace captures
that can drop under load:

- **offered** — sender's own count (several sharded senders on separate CPUs)
- **delivered** — the router's TX counter on the server-side interface
- **loss** — `1 - delivered/offered`; NFQUEUE drop counters show where it came from
- **p50 / p99** — latency sampled by the receiver from the embedded timestamps
- **per-queue spread** — from `/proc/net/netfilter/nfnetlink_queue`, to show load balancing

Workers and senders are pinned to separate physical cores (derived from
`lscpu`) so the scaling numbers aren't distorted by SMT siblings or CPU
contention. Output looks like:

```text
PROFILE       WORKERS     TARGET  OFFERED_PPS DELIVERED_PPS    LOSS%   P50_us   P99_us
---------------------------------------------------------------------------------------
wire                1     100000          ...          ...      ...      ...      ...
passthrough         1     100000          ...          ...      ...      ...      ...
...
```

Raw rows are saved to `/tmp/pi-bench-last.tsv`. If loss stays at ~0%, the
inspector kept up, so the numbers are a lower bound on capacity, not a ceiling.
