#include "blocklist.hpp"
#include "cli.hpp"
#include "config.hpp"
#include "worker.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sys/eventfd.h>
#include <unistd.h>

namespace {

// How every worker is told to stop.
//
// One eventfd that all of them poll and NONE of them ever read. Because nothing
// reads it, a single write leaves the counter non-zero and the fd permanently
// readable, so one write wakes every worker at once -- and write() on an
// eventfd is async-signal-safe, which is what lets the signal handler do it.
int g_stop_fd = -1;

extern "C" void on_signal(int) {
  if (g_stop_fd < 0)
    return;
  const std::uint64_t one = 1;
  const ssize_t n = ::write(g_stop_fd, &one, sizeof(one));
  (void)n; // nothing useful to do on failure, and nothing safe to say here
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

// One line of counters, summed across workers.
//
// `dropped_at_cap` counts flows that went uninspected because a worker's table
// was full, and `undecided` packets a callback dropped on the floor. Both are
// bug or pressure indicators and both should stay 0. `outstanding` is what the
// workers are currently holding; it should stay small and keep returning to 0.
std::string stats_line(const std::vector<std::unique_ptr<Worker>> &workers) {
  std::size_t flows = 0, blocked = 0;
  std::uint64_t dropped = 0, received = 0, verdicted = 0, outstanding = 0,
                undecided = 0;
  for (const auto &w : workers) {
    flows += w->tracked_flows();
    blocked += w->blocked_flows();
    dropped += w->flows_dropped_at_cap();
    received += w->queue().packets_received();
    verdicted += w->queue().verdicts_issued();
    outstanding += w->queue().outstanding();
    undecided += w->queue().packets_undecided();
  }
  std::ostringstream os;
  os << "rx=" << received << " verdicts=" << verdicted
     << " outstanding=" << outstanding << " flows=" << flows
     << " blocked=" << blocked << " dropped_at_cap=" << dropped
     << " undecided=" << undecided;
  return os.str();
}

} // namespace

int main(int argc, char **argv) {
  const cli::ParseResult parsed = cli::parse(argc, argv);
  if (parsed.should_exit)
    return parsed.exit_code;
  const Config cfg = parsed.config;

  // Unbuffered stdout only under -v. Otherwise std::cout is block-buffered when
  // stdout is a pipe or file, and a worker that blocks in poll() for a long time
  // never flushes -- so the log looks empty exactly when you are watching it.
  // It costs a flush per output operation, so it stays off on the quiet path.
  if (cfg.verbose)
    std::cout << std::unitbuf;

  // Loaded once, here, then only ever read -- which is what lets every worker
  // share it with no lock. A missing or unreadable file is fatal.
  std::unique_ptr<BlockList> blocklist;
  try {
    blocklist = std::make_unique<BlockList>(cfg.blocklist_path);
  } catch (const std::exception &e) {
    std::cerr << "fatal: cannot load blocklist '" << cfg.blocklist_path
              << "': " << e.what() << "\n";
    return 1;
  }

  const int stop_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (stop_fd < 0) {
    std::cerr << "fatal: eventfd: " << std::strerror(errno) << "\n";
    return 1;
  }
  g_stop_fd = stop_fd;

  const std::size_t worker_count = cfg.worker_count();

  std::cout << "PacketInspector: " << worker_count << " worker(s) on queues "
            << cfg.queue_num << ".." << cfg.last_queue_num() << ", maxlen "
            << cfg.queue_maxlen << "/queue, rcvbuf "
            << (cfg.recv_buf_per_worker() / (1024 * 1024)) << " MiB/queue, "
            << "blocklist '" << cfg.blocklist_path << "'\n"
            << "iptables must route to this exact range, e.g.\n"
            << "  -j NFQUEUE --queue-balance " << cfg.queue_num << ":"
            << cfg.last_queue_num() << " --queue-bypass\n"
            // Always flushed, even without -v. Without this the banner sits in
            // a block buffer whenever stdout is a file or pipe, so anything
            // scripting this -- waiting for the queues to be bound before it
            // starts sending -- would wait forever on output that exists but
            // has not been written.
            << std::flush;

  std::vector<std::unique_ptr<Worker>> workers;
  int rc = 0;

  try {
    // Built and bound up front, before any thread starts. A queue that fails to
    // bind throws here, and we exit without having inspected anything -- far
    // better than running with a gap in the range, where the kernel keeps
    // hashing traffic to a queue nobody is listening on.
    workers.reserve(worker_count);
    for (std::size_t i = 0; i < worker_count; ++i)
      workers.push_back(std::make_unique<Worker>(
          static_cast<int>(i),
          static_cast<std::uint16_t>(cfg.queue_num + i), *blocklist, stop_fd,
          cfg.verbose, cfg.passthrough, cfg.queue_maxlen,
          cfg.recv_buf_per_worker(), TcpTlsHostnameExtractor::kDefaultMaxFlows,
          cfg.max_blocked_flows,
          cfg.pin_first_cpu >= 0
              ? cfg.pin_first_cpu + static_cast<int>(i) * cfg.pin_stride
              : -1));

    install_signal_handlers();
    for (auto &w : workers)
      w->start();

    // Optional counters thread. One line per interval regardless of traffic,
    // so a run that quietly hit the flow cap does not look like a clean one.
    std::atomic<bool> reporting{cfg.stats_interval_s > 0};
    std::thread stats;
    if (cfg.stats_interval_s > 0) {
      stats = std::thread([&] {
        const auto interval = std::chrono::seconds(cfg.stats_interval_s);
        while (reporting.load(std::memory_order_relaxed)) {
          // Wake often, so shutdown is not held up by a long interval.
          for (auto slept = std::chrono::milliseconds(0);
               slept < interval && reporting.load(std::memory_order_relaxed);
               slept += std::chrono::milliseconds(100))
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
          if (!reporting.load(std::memory_order_relaxed))
            break;
          std::cerr << "stats: " << stats_line(workers) << "\n";
        }
      });
    }

    // Each worker returns from its loop on the stop fd or on its own queue
    // failing, and flushes whatever it was holding before it does.
    for (auto &w : workers)
      w->join();

    reporting.store(false, std::memory_order_relaxed);
    if (stats.joinable())
      stats.join();

    if (cfg.verbose)
      std::cout << "\nshutting down...\n";

    // Always, even on a quiet run: a one-line account costs nothing and is the
    // difference between a number you can interpret and one you cannot.
    std::cerr << "final: " << stats_line(workers) << "\n";

    for (const auto &w : workers) {
      if (w->queue().packets_undecided() != 0)
        std::cerr << "warning: worker " << w->id() << " had "
                  << w->queue().packets_undecided()
                  << " packet(s) reach the end of the callback undecided; they "
                     "were allowed\n";
      if (w->queue().failed()) {
        std::cerr << "fatal: worker " << w->id() << " (queue "
                  << w->queue_num() << "): " << w->queue().error() << "\n";
        rc = 1;
      }
    }
  } catch (const std::exception &e) {
    std::cerr << "fatal: " << e.what() << "\n";
    rc = 1;
  }

  // If we got here by exception, workers may be running and nothing has asked
  // them to stop -- and ~Worker() joins, so destroying them would hang. Writing
  // the stop fd is harmless when they are already finished.
  on_signal(0);
  workers.clear();
  g_stop_fd = -1;
  ::close(stop_fd);
  return rc;
}
