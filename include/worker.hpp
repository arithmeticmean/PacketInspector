#pragma once

#include "NFQueue.hpp"
#include "blocklist.hpp"
#include "hostname_extractor.hpp"

#include <cstddef>
#include <cstdint>
#include <thread>

// One self-contained inspector: its own NFQUEUE, its own TCP reassembler, and a
// shared read-only blocklist, all driven by one thread.
//
// Everything a packet needs happens on that thread, in order:
//
//   queue.run_once()  ->  extractor.feed()  ->  extractor.decided()
//                                                     |
//                                                     v
//                                              queue.submit()
//
// There is no queue between the stages and no lock anywhere, because a worker
// shares no mutable state with any other worker. The kernel guarantees that by
// hashing each packet to a queue on (saddr, daddr, protocol), so every flow
// between a pair of hosts lands on exactly one worker -- which is what makes a
// per-worker reassembler correct.
//
// The blocklist is the one thing shared, and it is immutable after construction,
// so every worker reads it concurrently without synchronization.
class Worker {
public:
  // Builds and binds the queue immediately, on the caller's thread, so a bind
  // failure throws before anything starts. That matters: with --queue-balance,
  // a queue nobody is listening on silently loses its share of the traffic, so
  // a half-started set of workers is worse than none.
  //
  // `blocklist` and `stop_fd` must outlive the worker.
  // `passthrough` allows every packet without inspecting it: no dissection, no
  // reassembler, no extractor. Not a production mode -- it exists so a
  // benchmark can price the NFQUEUE round trip on its own, separately from the
  // cost of inspection.
  Worker(int id, std::uint16_t queue_num, const BlockList &blocklist,
         int stop_fd, bool verbose, bool passthrough,
         std::uint32_t queue_maxlen, int recv_buf_bytes, std::size_t max_flows,
         std::size_t max_blocked, int pin_cpu = -1);
  ~Worker();

  Worker(const Worker &) = delete;
  Worker &operator=(const Worker &) = delete;

  // Spawn the thread. Idempotent.
  void start();

  // Wait for the thread to finish. It stops on its own once the shared stop fd
  // is written, or if its queue fails. Idempotent.
  void join();

  int id() const noexcept { return _id; }
  std::uint16_t queue_num() const noexcept { return _queue.queue_num(); }
  const NFQueue &queue() const noexcept { return _queue; }

  std::size_t tracked_flows() const noexcept { return _tls.tracked_flows(); }
  std::size_t blocked_flows() const noexcept { return _tls.blocked_flows(); }
  std::uint64_t flows_dropped_at_cap() const noexcept {
    return _tls.flows_dropped_at_cap();
  }

private:
  void loop();

  // Hand everything the extractor finished with to the kernel, then reset the
  // buffer for the next round. The buffer is reused, so this stops allocating
  // once a worker reaches steady state.
  void drain_decided();

  int _id;
  const BlockList &_blocklist;
  bool _verbose;
  bool _passthrough;
  int _pin_cpu; // -1 = do not pin

  // Declared before _tls: the extractor's policy callback reads them.
  NFQueue _queue;
  TcpTlsHostnameExtractor _tls;
  std::thread _thread;
};
