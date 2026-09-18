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

  // -nfq <n>: the FIRST NFQUEUE number to bind. Worker i binds queue_num + i,
  // so the set spans [queue_num, queue_num + jobs - 1] and must match the
  // iptables `--queue-balance` range exactly. Bind fewer queues than the rule
  // spans and that share of traffic goes uninspected.
  std::uint16_t queue_num = 0;

  // -nfq-size <n>: kernel queue depth in PACKETS (nfq_set_queue_maxlen), not
  // bytes. Deeper = more in-flight packets tolerated before the kernel drops
  // under load. PER WORKER, so the machine pays jobs times this.
  std::uint32_t queue_maxlen = 8192;

  // -j <n>: how many workers, and therefore how many queues and how many
  // threads. Each worker is self-contained -- its own queue, its own
  // reassembler -- so there are no infrastructure threads to subtract.
  std::size_t jobs = 4;

  // -rcvbuf <bytes>: netlink socket receive buffer (SO_RCVBUF) IN BYTES.
  // Absorbs recv() bursts so packets aren't dropped before we drain them. Set
  // via SO_RCVBUFFORCE, so it bypasses net.core.rmem_max.
  //
  // This is the TOTAL across all workers; each gets its share (see
  // recv_buf_per_worker()). Splitting rather than multiplying is deliberate:
  // the value that used to be right for one queue would otherwise quietly
  // become 8x that with -j 8.
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

  // -pin <cpu>: pin worker i to CPU (cpu + i). -1 leaves scheduling alone.
  //
  // Worth having for a packet path: an unpinned worker gets migrated between
  // cores, and every migration costs it the flow table and reassembly state it
  // had warm in that core's cache. It also makes a benchmark repeatable, since
  // otherwise the scheduler's choices are part of every measurement.
  int pin_first_cpu = -1;

  // -pin-stride <n>: worker i goes to CPU (pin_first_cpu + i * n).
  //
  // A stride exists because "one worker per CPU number" is usually the wrong
  // thing. With SMT, adjacent CPU numbers are often two threads of ONE physical
  // core, so -pin 0 with 4 workers can land two of them on the same core --
  // which reads as the architecture failing to scale when what actually
  // happened is that two workers were fighting over one core's execution units.
  // `lscpu -e=CPU,CORE` shows the mapping; stride 2 is right when siblings are
  // adjacent pairs, stride 1 when the second half of the CPU list is siblings.
  int pin_stride = 1;

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

  // One worker per job: each owns a queue, a thread and a reassembler, and
  // nothing is reserved for infrastructure.
  std::size_t worker_count() const noexcept { return jobs > 0 ? jobs : 1; }

  // The last queue number in the balance range. Handy for printing the exact
  // `--queue-balance` the iptables rule has to use.
  std::uint16_t last_queue_num() const noexcept {
    return static_cast<std::uint16_t>(queue_num + worker_count() - 1);
  }

  // Each worker's share of the total receive buffer, never below 1 MiB -- a
  // buffer too small to hold one burst drops packets before we can read them,
  // which is worse than overshooting the total.
  int recv_buf_per_worker() const noexcept {
    const auto share =
        static_cast<std::size_t>(recv_buf_bytes) / worker_count();
    constexpr std::size_t kFloor = 1024 * 1024;
    return static_cast<int>(share < kFloor ? kFloor : share);
  }
};
