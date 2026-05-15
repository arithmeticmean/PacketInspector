#include "NFQueue.hpp"
#include "blocklist.hpp"
#include "cli.hpp"
#include "config.hpp"
#include "packet.hpp"
#include "packet_worker.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

// Set once, before the queue starts; only the signal handler reads it. A raw
// pointer because a handler may only touch async-signal-safe things, and
// request_stop() is exactly that (a write() to an eventfd).
NFQueue *g_queue = nullptr;

extern "C" void on_signal(int) {
  if (g_queue != nullptr)
    g_queue->request_stop();
}

// One line of counters. `flows` is what is currently tracked, `dropped_at_cap`
// how many flows went uninspected because a worker's table was full, and
// `undecided` how many packets reached the end of the receive callback without
// a verdict. The last two are bug/pressure indicators: both should stay 0.
std::string stats_line(
    const std::vector<std::unique_ptr<PacketWorker>> &workers,
    const NFQueue &queue) {
  std::size_t flows = 0;
  std::size_t blocked = 0;
  std::uint64_t dropped = 0;
  for (const auto &w : workers) {
    flows += w->tracked_flows();
    blocked += w->blocked_flows();
    dropped += w->flows_dropped_at_cap();
  }
  std::ostringstream os;
  os << "flows=" << flows << " blocked=" << blocked
     << " dropped_at_cap=" << dropped
     << " pending_verdicts=" << queue.pending_verdicts()
     << " undecided=" << queue.packets_undecided();
  return os.str();
}

void install_signal_handlers() {
  struct sigaction sa {};
  sa.sa_handler = &on_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; // no SA_RESTART: let poll() return EINTR
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
  // A dead peer on stdout must not kill the process mid-flow.
  signal(SIGPIPE, SIG_IGN);
}

} // namespace

int main(int argc, char **argv) {
  const cli::ParseResult parsed = cli::parse(argc, argv);
  if (parsed.should_exit)
    return parsed.exit_code;
  const Config cfg = parsed.config;

  // Unbuffered stdout only under -v. Without it, std::cout is block-buffered
  // when stdout is a file or pipe, so the receive loop (which blocks for a long
  // time) never flushes and the log stays empty -- a real debugging blind spot,
  // and exactly what you want while watching it live. It is also a flush per
  // output operation, so it stays off on the quiet path.
  if (cfg.verbose)
    std::cout << std::unitbuf;

  // Loaded once, here at init, then only read -- so every worker thread shares
  // it without locking. A missing/unreadable file is fatal.
  std::unique_ptr<BlockList> blocklist;
  try {
    blocklist = std::make_unique<BlockList>(cfg.blocklist_path);
  } catch (const std::exception &e) {
    std::cerr << "fatal: cannot load blocklist '" << cfg.blocklist_path
              << "': " << e.what() << "\n";
    return 1;
  }

  const std::size_t worker_count = cfg.worker_count();
  std::cout << "PacketInspector: queue " << cfg.queue_num << ", maxlen "
            << cfg.queue_maxlen << ", workers " << worker_count << " (-j "
            << cfg.jobs << "), blocklist '" << cfg.blocklist_path << "'\n";

  // Policy, shared by every worker's extractor. Runs on the worker thread when
  // a flow resolves; the extractor turns the answer into verdicts and, for a
  // BLOCK, remembers it for the rest of the connection.
  const bool verbose = cfg.verbose;
  HostnameExtractor::Decide decide =
      [&blocklist, verbose](const std::optional<std::string> &hostname) -> Verdict {
    const Verdict v = (hostname && blocklist->isHostnameBlocked(*hostname))
                          ? Verdict::BLOCK
                          : Verdict::ALLOW;
    // Runs on a worker thread, once per resolved flow. Logging here is a
    // write() through std::cout's lock, so it is opt-in: left on it would be
    // the bottleneck long before the inspector is.
    if (verbose && hostname)
      std::cout << (v == Verdict::BLOCK ? "BLOCK " : "ALLOW ") << *hostname
                << "\n";
    return v;
  };

  // Filled after the queue is built (the workers need it as their sink), but
  // captured by the receive callback now. Nothing runs until queue.start().
  std::vector<std::unique_ptr<PacketWorker>> workers;

  // Set once the queue exists; only the receive callback uses it, and no packet
  // flows until start().
  NFQueue *nfq = nullptr;

  // Runs on the receive thread and takes ownership of every packet. It makes
  // one decision -- is this a transport some worker can do something with?
  //   * No (undissectable, or not TCP) -> submit ALLOW. The packet is still a
  //     view, so submit() drops the view and queues a 32-byte shell: no copy.
  //   * Yes -> materialize() lifts the bytes out of NFQUEUE's transient buffer
  //     so they survive the hop, then route to the worker owning that flow.
  // No packet *content* is examined here; that is the worker's job.
  const bool passthrough = cfg.passthrough;
  NFQueue::Callback route = [&workers, &nfq, worker_count,
                             passthrough](Packet &&pkt) {
    // Benchmark baseline: straight back out, so what remains is the queue round
    // trip and nothing else.
    if (passthrough) {
      nfq->submit(std::move(pkt), Verdict::ALLOW);
      return;
    }
    FlowView flow;
    if (!pkt.flow_view(flow) || flow.ip_proto != 6 /* TCP */) {
      nfq->submit(std::move(pkt), Verdict::ALLOW);
      return;
    }
    pkt.materialize();
    workers[flow.key % worker_count]->submit(std::move(pkt));
  };

  try {
    NFQueue queue(cfg.queue_num, route, cfg.queue_maxlen, cfg.recv_buf_bytes);
    nfq = &queue;
    g_queue = &queue;

    // Workers shard flows by FlowView::key, so each owns a disjoint set of
    // connections and its extractor needs no locking.
    workers.reserve(worker_count);
    for (std::size_t i = 0; i < worker_count; ++i)
      workers.push_back(
          std::make_unique<PacketWorker>(static_cast<int>(i), decide, queue,
                                         cfg.max_blocked_flows));
    install_signal_handlers();

    // Counters, one line per interval to stderr. Cheap enough to leave on
    // during a benchmark, and without it a run that quietly hit the flow cap
    // is indistinguishable from one that inspected everything.
    std::atomic<bool> reporting{cfg.stats_interval_s > 0};
    std::thread stats;
    if (cfg.stats_interval_s > 0) {
      stats = std::thread([&] {
        const auto interval = std::chrono::seconds(cfg.stats_interval_s);
        while (reporting.load(std::memory_order_relaxed)) {
          // Wake often so shutdown isn't held up by a long interval.
          for (auto slept = std::chrono::milliseconds(0);
               slept < interval && reporting.load(std::memory_order_relaxed);
               slept += std::chrono::milliseconds(100))
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
          if (!reporting.load(std::memory_order_relaxed))
            break;
          std::cerr << "stats: " << stats_line(workers, queue) << "\n";
        }
      });
    }

    queue.start();
    queue.wait(); // until a signal arrives or the receive loop fails

    reporting.store(false, std::memory_order_relaxed);
    if (stats.joinable())
      stats.join();

    // Shutdown order matters: the receive thread is already stopped, so draining
    // the workers now flushes their last verdicts before the queue closes.
    if (cfg.verbose)
      std::cout << "\nshutting down...\n";
    for (auto &w : workers)
      w->stop();
    queue.stop();

    // Always, even when quiet: a one-line account of the run costs nothing and
    // is the difference between a number you can interpret and one you can't.
    std::cerr << "final: " << stats_line(workers, queue) << "\n";

    if (queue.packets_undecided() != 0)
      std::cerr << "warning: " << queue.packets_undecided()
                << " packet(s) reached the end of the callback undecided and "
                   "were allowed\n";
    if (queue.failed()) {
      std::cerr << "fatal: " << queue.error() << "\n";
      return 1;
    }
  } catch (const std::exception &e) {
    std::cerr << "fatal: " << e.what() << "\n";
    return 1;
  }
  return 0;
}
