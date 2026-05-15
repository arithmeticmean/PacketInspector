#include "NFQueue.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <iterator>
#include <system_error>
#include <utility>

// glibc headers before the kernel uapi header to avoid the linux/in.h vs
// netinet/in.h struct redefinition clash.
#include <arpa/inet.h>
#include <sys/socket.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/netlink.h> // SOL_NETLINK, NETLINK_NO_ENOBUFS
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace {

// Throw a std::system_error carrying the current errno and a context string.
[[noreturn]] void fail(const char *what) {
  throw std::system_error(errno, std::generic_category(), what);
}

// Big enough for a full 0xffff-byte packet plus netlink header overhead.
constexpr std::size_t kRecvBuf = 0xffff + 4096;

// Verdicts pulled from the queue per syscall batch. Bigger batches amortize the
// dequeue, not the syscalls (one per packet either way).
constexpr std::size_t kVerdictBatch = 256;

// How long the verdict thread parks when the queue is empty. Only bounds how
// quickly it notices a drain request; a real verdict wakes it immediately.
constexpr auto kVerdictIdleWait = std::chrono::milliseconds(50);

} // namespace

NFQueue::NFQueue(std::uint16_t queueNum, Callback cb, std::uint32_t queueMaxLen,
                 int recvBufBytes)
    : cb_(std::move(cb)), queueNum_(queueNum) {
  buf_.resize(kRecvBuf);

  _stop_evt = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (_stop_evt < 0)
    fail("eventfd");

  h_ = nfq_open();
  if (h_ == nullptr) {
    const int e = errno;
    ::close(_stop_evt);
    throw std::system_error(e, std::generic_category(), "nfq_open");
  }

  // Everything past this point must clean up what came before it.
  auto bail = [&](const char *what) {
    const int e = errno;
    if (qh_ != nullptr)
      nfq_destroy_queue(qh_);
    nfq_close(h_);
    ::close(_stop_evt);
    throw std::system_error(e, std::generic_category(), what);
  };

  // Legacy per-family bind; a no-op on modern kernels, but surfaces an EPERM
  // (missing CAP_NET_ADMIN) here rather than silently.
  nfq_unbind_pf(h_, AF_INET);
  if (nfq_bind_pf(h_, AF_INET) < 0)
    bail("nfq_bind_pf");

  qh_ = nfq_create_queue(h_, queueNum_, &NFQueue::trampoline, this);
  if (qh_ == nullptr)
    bail("nfq_create_queue");

  if (nfq_set_mode(qh_, NFQNL_COPY_PACKET, 0xffff) < 0)
    bail("nfq_set_mode");

  // Under load, kernel->userspace bursts can outrun the callback. These raise
  // the headroom so packets aren't dropped before we drain them; all
  // best-effort (no hard failure if the kernel declines).
  //   - a deeper queue holds more in-flight packets awaiting a verdict,
  //   - a bigger netlink socket buffer absorbs recv() bursts,
  //   - NO_ENOBUFS trades an error-on-overflow for a silent drop so the socket
  //     never desyncs (the drop still shows in the NFQUEUE counters).
  nfq_set_queue_maxlen(qh_, queueMaxLen);
  const int fd = nfq_fd(h_);
  int rcvbuf = recvBufBytes;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  int on = 1;
  setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &on, sizeof(on));
}

NFQueue::~NFQueue() {
  stop();
  if (qh_ != nullptr)
    nfq_destroy_queue(qh_);
  if (h_ != nullptr)
    nfq_close(h_);
  if (_stop_evt >= 0)
    ::close(_stop_evt);
}

// --- lifecycle -------------------------------------------------------------

void NFQueue::start() {
  if (_started)
    return;
  _started = true;
  _verdict_thread = std::thread(&NFQueue::verdict_loop, this);
  _recv_thread = std::thread(&NFQueue::recv_loop, this);
}

void NFQueue::wait() {
  if (_recv_thread.joinable())
    _recv_thread.join();
}

void NFQueue::request_stop() noexcept {
  if (_stop_evt < 0)
    return;
  const std::uint64_t one = 1;
  // write() on an eventfd is async-signal-safe. Nothing to do if it fails: a
  // pending count is already enough to wake the poll().
  const ssize_t n = ::write(_stop_evt, &one, sizeof(one));
  (void)n;
}

void NFQueue::stop_receiving() {
  request_stop();
  wait();
}

void NFQueue::stop() {
  stop_receiving();
  if (_verdict_thread.joinable()) {
    // Publish the drain request only now: the verdict loop exits on an empty
    // poll once it sees this, which is only correct after every producer has
    // stopped.
    _draining.store(true, std::memory_order_release);
    _verdict_thread.join();
  }
}

// --- receive side ----------------------------------------------------------

// C callback -> owning instance.
int NFQueue::trampoline(nfq_q_handle *, nfgenmsg *, nfq_data *nfa, void *self) {
  return static_cast<NFQueue *>(self)->handle(nfa);
}

int NFQueue::handle(nfq_data *nfa) {
  std::uint32_t id = 0;
  if (auto *ph = nfq_get_msg_packet_hdr(nfa))
    id = ntohl(ph->packet_id);

  unsigned char *payload = nullptr;
  const int len = nfq_get_payload(nfa, &payload);

  // A view over the receive buffer: no copy yet. The callback materializes it
  // only if the packet is going somewhere.
  Packet pkt = (len > 0 && payload != nullptr)
                   ? Packet(payload, static_cast<std::uint32_t>(len), id)
                   : Packet(nullptr, 0, id);

  // Never let an exception unwind through libnetfilter_queue's C frames -- it
  // would hit a frame with no unwind info and terminate the process. Swallowing
  // it leaves `pkt` pending, so the fail-safe below allows the packet.
  try {
    cb_(std::move(pkt));
  } catch (...) {
  }

  // The callback should have moved the packet onward. If it did not, `pkt` is
  // still pending -- allow it rather than strand a kernel queue slot forever.
  if (pkt.pending_verdict()) {
    _undecided.fetch_add(1, std::memory_order_relaxed);
    submit(std::move(pkt), Verdict::ALLOW);
  }
  return 0;
}

void NFQueue::recv_loop() {
  const int fd = nfq_fd(h_);
  struct pollfd fds[2];
  fds[0] = {fd, POLLIN, 0};
  fds[1] = {_stop_evt, POLLIN, 0};

  for (;;) {
    fds[0].revents = 0;
    fds[1].revents = 0;
    if (::poll(fds, 2, -1) < 0) {
      if (errno == EINTR)
        continue;
      record_error("poll", errno);
      return;
    }
    if (fds[1].revents != 0)
      return; // stop requested

    if ((fds[0].revents & POLLIN) == 0) {
      if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        record_error("poll: netlink socket error", EIO);
        return;
      }
      continue;
    }

    const ssize_t rv = ::recv(fd, buf_.data(), buf_.size(), 0);
    if (rv < 0) {
      // ENOBUFS: the kernel dropped packets because we fell behind. EINTR/EAGAIN
      // are transient. None are fatal.
      if (errno == ENOBUFS || errno == EINTR || errno == EAGAIN ||
          errno == EWOULDBLOCK)
        continue;
      record_error("recv", errno);
      return;
    }
    if (rv == 0)
      continue;

    // Parses the buffer and calls trampoline() once per packet it contains.
    nfq_handle_packet(h_, buf_.data(), static_cast<int>(rv));
  }
}

// --- verdict side ----------------------------------------------------------

// NF_ACCEPT lets the packet continue through the kernel's chains; NF_DROP
// discards it.
void NFQueue::issue(std::uint32_t id, Verdict v) {
  nfq_set_verdict(qh_, id, v == Verdict::BLOCK ? NF_DROP : NF_ACCEPT, 0,
                  nullptr);
}

void NFQueue::submit(Packet &&pkt, Verdict v) {
  if (!pkt.pending_verdict())
    return; // already submitted, or a moved-from husk: never verdict twice
  pkt.set_verdict(v);
  pkt.release_bytes(); // freed here, on the caller's thread
  pkt.clear_pending();
  _verdicts.enqueue(std::move(pkt));
}

void NFQueue::submit(std::vector<Packet> &&pkts, Verdict v) {
  std::size_t n = 0;
  for (std::size_t i = 0; i < pkts.size(); ++i) {
    Packet &p = pkts[i];
    if (!p.pending_verdict())
      continue;
    p.set_verdict(v);
    p.release_bytes();
    p.clear_pending();
    if (n != i)
      pkts[n] = std::move(p); // compact, so the bulk enqueue is contiguous
    ++n;
  }
  if (n > 0)
    _verdicts.enqueue_bulk(std::make_move_iterator(pkts.begin()), n);
  pkts.clear();
}

void NFQueue::verdict_loop() {
  moodycamel::ConsumerToken tok(_verdicts);
  Packet batch[kVerdictBatch];

  for (;;) {
    const std::size_t n = _verdicts.wait_dequeue_bulk_timed(
        tok, batch, kVerdictBatch, kVerdictIdleWait);
    for (std::size_t i = 0; i < n; ++i)
      issue(batch[i].id(), batch[i].verdict());

    // Only quit on an empty poll, so a drain request never leaves a verdict
    // behind. Safe because stop() sets _draining after the producers are gone.
    if (n == 0 && _draining.load(std::memory_order_acquire))
      return;
  }
}

// --- diagnostics -----------------------------------------------------------

std::size_t NFQueue::pending_verdicts() const noexcept {
  return _verdicts.size_approx();
}

void NFQueue::record_error(const char *what, int err) noexcept {
  _err_what.store(what, std::memory_order_relaxed);
  _err_errno.store(err != 0 ? err : EIO, std::memory_order_release);
}

std::string NFQueue::error() const {
  const int e = _err_errno.load(std::memory_order_acquire);
  if (e == 0)
    return {};
  const char *what = _err_what.load(std::memory_order_relaxed);
  return std::string(what != nullptr ? what : "nfqueue") + ": " +
         std::strerror(e);
}
