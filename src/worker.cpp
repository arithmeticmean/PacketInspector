#include "worker.hpp"

#include <chrono>
#include <cstring>
#include <iostream>

#include <pthread.h>
#include <sched.h>
#include <optional>
#include <string>

namespace {

// How long a worker waits in poll() before giving up and looking around. It
// bounds two things: how quickly a stop request is noticed, and how stale the
// idle-flow sweep can get.
//
// It must be finite. This thread is the only one a worker has, so if it blocks
// forever on a quiet queue, nothing runs the sweep and any packets being held
// for a flow that went silent are never released.
constexpr auto kIdlePoll = std::chrono::milliseconds(100);

} // namespace

Worker::Worker(int id, std::uint16_t queue_num, const BlockList &blocklist,
               int stop_fd, bool verbose, bool passthrough,
               std::uint32_t queue_maxlen, int recv_buf_bytes,
               std::size_t max_flows, std::size_t max_blocked, int pin_cpu)
    : _id(id), _blocklist(blocklist), _verbose(verbose),
      _passthrough(passthrough), _pin_cpu(pin_cpu),

      // Binds the queue here and now. Throws if the queue number is taken or we
      // lack CAP_NET_ADMIN, which is what stops a half-bound set of workers
      // from silently passing traffic through uninspected.
      _queue(
          queue_num,
          // Runs on this worker's thread, once per packet. It does nothing but
          // pass the packet to the extractor: the extractor either decides it
          // immediately or holds it until the flow's hostname is known, and
          // either way the answer comes back through decided().
          [this](Packet &&pkt) {
            if (_passthrough) {
              _queue.submit(std::move(pkt), Verdict::ALLOW);
              return;
            }
            _tls.feed(std::move(pkt));
          },
          stop_fd,
          queue_maxlen, recv_buf_bytes),

      // The policy the extractor applies once a flow resolves. Keeping it here
      // rather than inside the extractor is what lets the extractor stay pure
      // mechanism -- it knows how to find a hostname, not what to think of one.
      _tls(
          [this](const std::optional<std::string> &hostname) -> Verdict {
            const Verdict v =
                (hostname && _blocklist.isHostnameBlocked(*hostname))
                    ? Verdict::BLOCK
                    : Verdict::ALLOW;
            // Once per resolved flow, not per packet -- but still a write()
            // through std::cout's lock, so it stays opt-in.
            if (_verbose && hostname)
              std::cout << (v == Verdict::BLOCK ? "BLOCK " : "ALLOW ")
                        << *hostname << "\n";
            return v;
          },
          max_flows, max_blocked) {}

Worker::~Worker() { join(); }

void Worker::start() {
  if (_thread.joinable())
    return;
  _thread = std::thread(&Worker::loop, this);

  // Pin after the thread exists. Best-effort: a CPU that is not present, or a
  // restricted affinity mask, is a reason to run unpinned rather than to fail
  // -- the worker is perfectly correct either way.
  if (_pin_cpu >= 0) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(static_cast<unsigned>(_pin_cpu), &set);
    const int rc =
        pthread_setaffinity_np(_thread.native_handle(), sizeof(set), &set);
    if (rc != 0)
      std::cerr << "warning: worker " << _id << " could not pin to CPU "
                << _pin_cpu << ": " << std::strerror(rc) << "\n";
  }
}

void Worker::join() {
  if (_thread.joinable())
    _thread.join();
}

void Worker::drain_decided() {
  auto &out = _tls.decided();
  for (Decided &d : out)
    _queue.submit(std::move(d.pkt), d.verdict);
  out.clear();
}

void Worker::loop() {
  for (;;) {
    const NFQueue::Event ev = _queue.run_once(kIdlePoll);

    // Stop: someone wrote the shared stop fd. Error: the queue gave up; main
    // reports it after the join. Either way we fall out and clean up below.
    if (ev == NFQueue::Event::Stop || ev == NFQueue::Event::Error)
      break;

    // Runs on every turn, whether packets arrived or the poll timed out.
    //
    // Both cases are needed. On a busy queue poll never times out, so a
    // timeout-only sweep would never run; on a quiet one no packets arrive, so
    // a packet-only sweep would never run. It is cheap to call either way --
    // the extractor rate-limits the actual sweep to once a second internally.
    _tls.tick(std::chrono::steady_clock::now());

    // Everything decided during the drain above, plus anything the sweep just
    // released, goes to the kernel here -- one place, once per turn.
    drain_decided();
  }

  // Shutting down: resolve every flow still being tracked so the packets they
  // are holding get verdicted. Anything left undecided would hold a kernel
  // queue slot for the life of the process and hang that connection.
  _tls.flush();
  drain_decided();
}
