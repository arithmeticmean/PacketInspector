#pragma once

#include "hostname_extractor.hpp"
#include "packet.hpp"
#include "verdict_sink.hpp"

#include <atomic>
#include <thread>

#include <blockingconcurrentqueue.h>

// An async worker: its own thread draining its own queue, owning one hostname
// extractor. The producer shards packets across workers by FlowView::key, so
// each worker sees a disjoint set of flows and its extractor's state needs no
// locking.
//
// Packets flow by move the whole way: submit() moves an owning Packet into the
// queue, the loop moves it out and into extractor.feed(). Pass an owning Packet
// (Packet::materialize()) so the bytes survive the hop off the NFQUEUE thread.
//
// The loop wakes periodically even with no traffic, so a worker that goes quiet
// still expires idle flows instead of sitting on their held packets.
class PacketWorker {
public:
  // `sink` must outlive the worker. `max_blocked` bounds how many decided-
  // against flows the extractor remembers; 0 derives it from the flow cap.
  PacketWorker(int id, HostnameExtractor::Decide decide, VerdictSink &sink,
               std::size_t max_blocked = 0);
  ~PacketWorker();

  PacketWorker(const PacketWorker &) = delete;
  PacketWorker &operator=(const PacketWorker &) = delete;

  // Enqueue a packet for this worker (thread-safe; producer side).
  void submit(Packet pkt);

  // Drain what is queued, release anything still held, and join. Idempotent.
  void stop();

  int id() const noexcept { return _id; }

  // Counters, safe to read from another thread while the worker runs.
  std::size_t tracked_flows() const noexcept { return _tls.tracked_flows(); }
  std::uint64_t flows_dropped_at_cap() const noexcept {
    return _tls.flows_dropped_at_cap();
  }
  std::size_t blocked_flows() const noexcept { return _tls.blocked_flows(); }

private:
  void loop();

  int _id;
  std::atomic<bool> _running{true};
  moodycamel::BlockingConcurrentQueue<Packet> _queue;
  TcpTlsHostnameExtractor _tls; // for now the only extractor; dispatch grows here
  std::thread _thread;
};
