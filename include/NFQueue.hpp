// C++ wrapper around libnetfilter_queue for ONE queue number, driven by its
// caller's thread. It owns no thread and starts nothing; the worker that owns
// this object calls run_once() in a loop:
//
//   poll()  ->  recv()  ->  nfq_handle_packet()  ->  your Callback, once per
//                                                    packet in the buffer
//
// Because receive, inspection and verdict all happen on that one thread, a
// packet never crosses a thread boundary and never has to be copied out of the
// receive buffer.
//
// Scale by running N of these, one per thread, each on its own queue number,
// with iptables spreading traffic across the range:
//
//   -j NFQUEUE --queue-balance 0:N-1 --queue-bypass
//
// The kernel picks the queue by hashing (saddr, daddr, protocol). Ports are NOT
// in that hash and it is deliberately symmetric, so every flow between a pair
// of hosts, both directions, lands on the same queue -- which is what lets each
// worker keep its own reassembler with no locking. The flip side is that load
// spreads per host-pair, not per flow, so one busy pair sits on one queue.
//
// EVERY queue in the range must have a listener. There is no failover: packets
// hashed to an unbound queue are dropped (or ACCEPTed uninspected, with
// --queue-bypass). Binding fewer queues than the rule spans silently lets that
// fraction of traffic through, so a failed bind has to be fatal.
//
// Non-copyable and non-movable: the constructor hands `this` to the C library
// as its opaque user pointer, so the address has to stay put.

#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "packet.hpp"

struct nfq_handle;
struct nfq_q_handle;
struct nfgenmsg;
struct nfq_data;

class NFQueue {
public:
  // Called once per packet, on the caller's thread, and takes ownership of it.
  //
  // It does NOT have to verdict the packet before returning -- moving it into
  // per-flow state to await a hostname is the normal path. It just must not
  // silently drop it; see packets_undecided().
  using Callback = std::function<void(Packet &&)>;

  // Why run_once() came back.
  enum class Event : std::uint8_t {
    Packets, // a buffer was drained; the callback ran once per packet in it
    Idle,    // poll timed out -- nothing arrived, so run your idle sweep now
    Stop,    // the stop fd is readable
    Error,   // the receive path failed; see error()
  };

  // Open and bind queue `queueNum`.
  //
  // `stopFd` is polled alongside the netlink socket but never read or closed
  // here -- it belongs to the caller and is shared by every worker. Nothing
  // reads it, so one write leaves it readable for good and wakes all of them.
  //
  // `queueMaxLen` (in packets) and `recvBufBytes` (in bytes) are PER QUEUE, so
  // N workers cost N times these. Worth re-checking a value that was tuned back
  // when there was only one queue.
  //
  // Throws std::system_error (carrying errno) if anything fails to open or bind.
  NFQueue(std::uint16_t queueNum, Callback cb, int stopFd,
          std::uint32_t queueMaxLen = 8192, int recvBufBytes = 32 * 1024 * 1024);
  ~NFQueue();

  NFQueue(const NFQueue &) = delete;
  NFQueue &operator=(const NFQueue &) = delete;
  NFQueue(NFQueue &&) = delete;
  NFQueue &operator=(NFQueue &&) = delete;

  // One turn of the loop: wait up to `timeout`, and if the socket has data,
  // drain the whole buffer -- one recv() usually carries many packets, and the
  // callback runs for each.
  //
  // `timeout` must be finite. Blocking forever would mean a quiet worker never
  // runs its idle sweep, and never releases the packets it is holding for a
  // flow that has gone silent.
  Event run_once(std::chrono::milliseconds timeout);

  // Stamp the verdict on `pkt`, release its bytes, and tell the kernel. One
  // syscall per packet for now; batching several into one nfq_set_verdict_batch
  // is possible later without changing this signature.
  void submit(Packet &&pkt, Verdict v);

  // --- counters ------------------------------------------------------------
  // Atomic because a stats thread may read them while this one runs. Only this
  // thread writes.

  std::uint64_t packets_received() const noexcept {
    return _received.load(std::memory_order_relaxed);
  }
  std::uint64_t verdicts_issued() const noexcept {
    return _verdicted.load(std::memory_order_relaxed);
  }

  // Received but not yet verdicted -- what some flow is holding right now.
  // Should stay small and keep coming back to zero. Growing without bound means
  // packets are held and never released, which pins kernel queue slots and
  // hangs those connections.
  std::uint64_t outstanding() const noexcept {
    return packets_received() - verdicts_issued();
  }

  // Packets the callback neither verdicted nor took ownership of; we allow them
  // rather than strand a queue slot. Moving a packet into per-flow state clears
  // its pending flag, so held packets are NOT counted here -- any nonzero value
  // is a real bug in the callback.
  std::uint64_t packets_undecided() const noexcept {
    return _undecided.load(std::memory_order_relaxed);
  }

  // True once the receive path has given up; error() then says why.
  bool failed() const noexcept {
    return _err_errno.load(std::memory_order_acquire) != 0;
  }
  std::string error() const;

  std::uint16_t queue_num() const noexcept { return _queue_num; }

private:
  // libnetfilter_queue can only call a plain C-style function, so it calls this
  // one, and we get the instance back out of the user pointer we registered in
  // the constructor. It does nothing else -- all the work is in handle().
  static int on_packet(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa,
                       void *user);

  // The real per-packet work: pull out the id and bytes, wrap them in a Packet
  // and hand it to the callback.
  int handle(nfq_data *nfa);

  void record_error(const char *what, int err) noexcept;

  nfq_handle *_h = nullptr;
  nfq_q_handle *_qh = nullptr;
  Callback _cb;
  std::vector<char> _buf;
  std::uint16_t _queue_num;
  int _stop_fd = -1; // borrowed, shared by all workers; never read or closed

  std::atomic<std::uint64_t> _received{0};
  std::atomic<std::uint64_t> _verdicted{0};
  std::atomic<std::uint64_t> _undecided{0};

  // errno of the failure, 0 while healthy. `_err_what` is always a string
  // literal, so there is no lifetime to manage. Publish it before _err_errno.
  std::atomic<int> _err_errno{0};
  std::atomic<const char *> _err_what{nullptr};
};
