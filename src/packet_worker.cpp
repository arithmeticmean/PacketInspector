#include "packet_worker.hpp"

#include <chrono>
#include <utility>

namespace {

// How long the loop parks when its queue is empty. Bounds both how quickly a
// stop() is noticed and how coarse the idle-flow sweep is.
constexpr auto kIdlePoll = std::chrono::milliseconds(100);

} // namespace

PacketWorker::PacketWorker(int id, HostnameExtractor::Decide decide,
                           VerdictSink &sink, std::size_t max_blocked)
    : _id(id), _tls(std::move(decide), sink,
                    TcpTlsHostnameExtractor::kDefaultMaxFlows, max_blocked) {
  // Start the thread last: every member it touches is already constructed.
  _thread = std::thread(&PacketWorker::loop, this);
}

PacketWorker::~PacketWorker() { stop(); }

void PacketWorker::submit(Packet pkt) { _queue.enqueue(std::move(pkt)); }

void PacketWorker::stop() {
  if (!_thread.joinable())
    return; // already stopped/joined
  _running.store(false, std::memory_order_release);
  _thread.join(); // the loop drains the queue before it exits
}

void PacketWorker::loop() {
  Packet pkt;
  for (;;) {
    if (_queue.wait_dequeue_timed(pkt, kIdlePoll)) {
      _tls.feed(std::move(pkt));
      continue;
    }
    // Timed out, so the queue is empty right now. Exiting only from here is
    // what makes stop() drain rather than discard: anything still queued keeps
    // the loop in the branch above.
    if (!_running.load(std::memory_order_acquire))
      break;
    // No traffic -- still expire idle flows, or their held packets would wait
    // for a packet that may never come.
    _tls.tick(std::chrono::steady_clock::now());
  }
  _tls.flush(); // release everything still held, or it is never verdicted
}
