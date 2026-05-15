// C++ wrapper around libnetfilter_queue, running the queue on two threads:
//
//   receive thread  recv() -> nfq_handle_packet() -> your Callback
//   verdict thread  drains a lock-free queue -> nfq_set_verdict()
//
// Splitting them takes the verdict syscall off the receive path entirely. The
// callback hands each packet on and returns immediately; nothing on the hot
// path blocks on a syscall or a mutex, so the kernel queue keeps draining even
// while verdicts are going out. It also means exactly one thread ever writes
// verdicts, which is why there is no lock here at all: producers only push onto
// a lock-free queue.
//
// Packets are moved, never copied. The callback takes ownership of each packet
// and must eventually route it to submit() -- directly, or via a worker that
// does. A packet that is never submitted holds a slot in the kernel queue
// forever and hangs its connection, so an unsubmitted packet coming back from
// the callback is allowed as a fail-safe (see packets_undecided()).
//
// Non-copyable and non-movable: the constructor hands `this` to the C library as
// the callback's opaque pointer, so the address must stay fixed.

#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include <blockingconcurrentqueue.h>

#include "packet.hpp"
#include "verdict_sink.hpp"

struct nfq_handle;
struct nfq_q_handle;
struct nfgenmsg;
struct nfq_data;

class NFQueue : public VerdictSink {
public:
  // Runs on the receive thread, once per packet, and takes ownership of it.
  // Keep it quick: the receive loop resumes only when it returns.
  using Callback = std::function<void(Packet &&)>;

  // Open + bind queue `queueNum` and register `cb`. `queueMaxLen` sets the
  // kernel queue depth (nfq_set_queue_maxlen) and `recvBufBytes` the netlink
  // socket receive buffer -- both best-effort headroom for bursts. Throws
  // std::system_error (carrying errno) on any initialization failure. No thread
  // runs until start().
  NFQueue(std::uint16_t queueNum, Callback cb, std::uint32_t queueMaxLen = 8192,
          int recvBufBytes = 8 * 1024 * 1024);
  ~NFQueue() override;

  NFQueue(const NFQueue &) = delete;
  NFQueue &operator=(const NFQueue &) = delete;
  NFQueue(NFQueue &&) = delete;
  NFQueue &operator=(NFQueue &&) = delete;

  // --- lifecycle -----------------------------------------------------------
  //
  // Shutdown is two-step because the queue cannot know when *your* producers
  // are done. Stop them in the middle:
  //
  //   q.start();
  //   q.wait();                              // until stop_receiving() or error
  //   for (auto &w : workers) w->stop();     // workers submit their last verdicts
  //   q.stop();                              // flush the verdict queue, join
  //
  // Skipping the middle step is safe but loses whatever verdicts the workers
  // had not submitted yet; those packets are left to the kernel queue.

  // Spawn the receive and verdict threads. Idempotent.
  void start();

  // Block until the receive loop stops -- either because stop_receiving() was
  // called or because it hit an unrecoverable error (see failed()).
  void wait();

  // Wake the receive loop and join it. No further packets reach the callback.
  // Verdicts still flow. Idempotent.
  void stop_receiving();

  // stop_receiving(), then drain every queued verdict to the kernel and join the
  // verdict thread. Call once producers are quiesced. Idempotent; also run by
  // the destructor.
  void stop();

  // Async-signal-safe: nudges the receive loop to exit, nothing more. Safe to
  // call from a signal handler; pair it with wait() + stop() on the main thread.
  void request_stop() noexcept;

  // --- verdicts ------------------------------------------------------------

  // Stamp `v` on the packet and hand it to the verdict thread. Releases the
  // packet's bytes first, so only a 32-byte shell crosses the queue and the
  // buffer is freed here, on the calling thread. Thread-safe, lock-free, and
  // never blocks.
  void submit(Packet &&pkt, Verdict v) override;

  // Same for a whole flow's packets, in one bulk enqueue. Leaves `pkts` empty.
  void submit(std::vector<Packet> &&pkts, Verdict v) override;

  // --- diagnostics ---------------------------------------------------------

  // Verdicts accepted but not yet written to the kernel. Approximate.
  std::size_t pending_verdicts() const noexcept;

  // Packets the callback returned without submitting, which we allowed as a
  // fail-safe. Any nonzero value is a bug in the callback.
  std::uint64_t packets_undecided() const noexcept {
    return _undecided.load(std::memory_order_relaxed);
  }

  // Set once the receive loop has aborted. error() then describes why; it is
  // empty while things are healthy.
  bool failed() const noexcept {
    return _err_errno.load(std::memory_order_acquire) != 0;
  }
  std::string error() const;

private:
  static int trampoline(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfa,
                        void *self);
  int handle(nfq_data *nfa);

  void recv_loop();
  void verdict_loop();

  // Issue one verdict to the kernel. Verdict-thread only: libnetfilter_queue
  // bumps a non-atomic sequence counter on the handle, so this must stay
  // single-writer.
  void issue(std::uint32_t id, Verdict v);

  void record_error(const char *what, int err) noexcept;

  nfq_handle *h_ = nullptr;
  nfq_q_handle *qh_ = nullptr;
  Callback cb_;
  std::vector<char> buf_;
  std::uint16_t queueNum_;

  // Shells awaiting a verdict syscall. Many producers, one consumer.
  moodycamel::BlockingConcurrentQueue<Packet> _verdicts;

  std::thread _recv_thread;
  std::thread _verdict_thread;
  int _stop_evt = -1; // eventfd: wakes the receive loop out of poll()
  std::atomic<bool> _draining{false};
  bool _started = false;

  std::atomic<std::uint64_t> _undecided{0};
  // errno of the failure, 0 while healthy; `_err_what` is always a literal, so
  // there is no lifetime to manage. Publish _err_what before _err_errno.
  std::atomic<int> _err_errno{0};
  std::atomic<const char *> _err_what{nullptr};
};
