// Central runtime configuration for PacketInspector, populated from argv by
// cli::parse(). Every field defaults to the value that used to be hardcoded, so
// running with no flags behaves as before. Add a knob here + a flag in cli.cpp
// rather than sprinkling constants across the code.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

struct Config {
  // -b <path> (or a bare positional arg): hostnames to block, one per line.
  std::string blocklist_path = "blocklist.txt";

  // -nfq <n>: NFQUEUE number to bind (0..65535). Must match the iptables
  // `--queue-num` used to steer packets here.
  std::uint16_t queue_num = 0;

  // -nfq-size <n>: kernel queue depth in PACKETS (nfq_set_queue_maxlen), not
  // bytes. Deeper = more in-flight packets tolerated before the kernel drops
  // under load. At ~1.5 KB/pkt, 1e6 packets is already ~1.5 GB of headroom.
  std::uint32_t queue_maxlen = 8192;

  // -j <n>: total thread budget. Two are infrastructure -- one runs the NFQUEUE
  // receive loop, one issues verdicts -- and the rest are reassembly /
  // SNI-extraction workers. See worker_count().
  std::size_t jobs = 4;

  // -rcvbuf <bytes>: netlink socket receive buffer (SO_RCVBUF) IN BYTES -- this
  // is the byte-sized queue capacity. Absorbs recv() bursts so packets aren't
  // dropped before we drain them. Set via SO_RCVBUFFORCE, so it bypasses
  // net.core.rmem_max. Capped at ~2 GB (it's an int in the kernel API).
  int recv_buf_bytes = 256 * 1024 * 1024; // 256 MiB

  // -max-blocked <n>: ceiling on how many *already-blocked* flows a worker
  // keeps remembered, so they cannot crowd out flows still awaiting a verdict.
  // 0 derives it from the flow cap (a quarter of it).
  //
  // A blocked flow is black-holed, so the client retransmits and nothing ever
  // arrives to close the entry. Without a separate ceiling they accumulate
  // until the table is full, at which point new flows go untracked and their
  // hostnames unchecked -- meaning enough traffic aimed at a blocked name
  // switches blocking off for everyone else. Overflowing this ring only costs
  // re-parsing a retransmitted ClientHello to reach the same verdict, so it is
  // safe to keep small.
  std::size_t max_blocked_flows = 0;

  // -v: log a line per resolved flow. OFF by default -- at load that is a
  // write() per flow from a worker thread through std::cout's lock, which is
  // enough to dominate a throughput measurement. Also turns on unbuffered
  // stdout, which is what you want when watching it live and not otherwise.
  bool verbose = false;

  // --passthrough: verdict every packet ALLOW straight from the receive
  // thread, with no dissection, no worker and no extractor. Not a production
  // mode -- it exists so a benchmark can separate the cost of the NFQUEUE round
  // trip itself (copy to userspace, netlink hop, verdict syscall) from the cost
  // of inspection. That baseline usually dominates, and without it you cannot
  // tell which one you are optimising.
  bool passthrough = false;

  // --stats <n>: print a counters line to stderr every n seconds; 0 disables.
  // One line per interval regardless of traffic, so it is safe to leave on
  // during a benchmark -- and without it a run that quietly hits the flow cap
  // looks identical to one that didn't.
  unsigned stats_interval_s = 0;

  // Workers = jobs minus the receive thread and the verdict thread; always at
  // least one. Reserving only one of the two oversubscribes a pinned CPU set by
  // a thread, and the one that loses the race is whichever is unlucky --
  // including the receive loop, whose stalling means the kernel queue overflows
  // and packets are dropped before we ever see them.
  std::size_t worker_count() const noexcept {
    return jobs > 2 ? jobs - 2 : 1;
  }
};
