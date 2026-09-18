#include "NFQueue.hpp"

#include <cerrno>
#include <cstring>
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
#include <unistd.h>

namespace {

// Big enough for a full 0xffff-byte packet plus netlink header overhead.
constexpr std::size_t kRecvBuf = 0xffff + 4096;

} // namespace

// ---------------------------------------------------------------------------
// Setup. Everything the kernel needs to know before it will hand us packets.
// ---------------------------------------------------------------------------

NFQueue::NFQueue(std::uint16_t queueNum, Callback cb, int stopFd,
                 std::uint32_t queueMaxLen, int recvBufBytes)
    : _cb(std::move(cb)), _queue_num(queueNum), _stop_fd(stopFd) {
  _buf.resize(kRecvBuf);

  // Open the netlink socket to nfnetlink_queue.
  _h = nfq_open();
  if (_h == nullptr)
    throw std::system_error(errno, std::generic_category(), "nfq_open");

  // From here on anything that fails has to undo what already succeeded,
  // otherwise we leak a socket on every failed worker start.
  auto bail = [&](const char *what) {
    const int e = errno;
    if (_qh != nullptr)
      nfq_destroy_queue(_qh);
    nfq_close(_h);
    throw std::system_error(e, std::generic_category(), what);
  };

  // A no-op on modern kernels, kept because it is the first call that touches
  // netfilter and so the first place a missing CAP_NET_ADMIN shows up as EPERM.
  // Better to fail here, by name, than to bind a queue that never sees traffic.
  if (nfq_bind_pf(_h, AF_INET) < 0)
    bail("nfq_bind_pf");

  // Claim our queue number and say which C function the library should call
  // for each packet. `this` is the opaque pointer handed back to on_packet().
  _qh = nfq_create_queue(_h, _queue_num, &NFQueue::on_packet, this);
  if (_qh == nullptr)
    bail("nfq_create_queue");

  // Ask for the whole packet, not just headers -- we need the TLS payload.
  if (nfq_set_mode(_qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    bail("nfq_set_mode");

  // Headroom for bursts, all best-effort: the kernel declining any of these is
  // a performance problem, not a correctness one, so none of them is fatal.
  //   - a deeper queue holds more packets awaiting a verdict,
  //   - a bigger socket buffer absorbs recv() bursts,
  //   - NO_ENOBUFS trades an error-on-overflow for a silent drop, so the socket
  //     never desyncs (the drop still shows up in the NFQUEUE counters).
  nfq_set_queue_maxlen(_qh, queueMaxLen);

  const int fd = nfq_fd(_h);
  int rcvbuf = recvBufBytes;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  int on = 1;
  setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &on, sizeof(on));
}

NFQueue::~NFQueue() {
  if (_qh != nullptr)
    nfq_destroy_queue(_qh);
  if (_h != nullptr)
    nfq_close(_h);
  // _stop_fd is borrowed from the caller -- not ours to close.
}

// ---------------------------------------------------------------------------
// The loop. One turn per call; the worker decides how often to come back.
// ---------------------------------------------------------------------------

NFQueue::Event NFQueue::run_once(std::chrono::milliseconds timeout) {
  const int fd = nfq_fd(_h);

  struct pollfd fds[2];
  fds[0] = {fd, POLLIN, 0};
  fds[1] = {_stop_fd, POLLIN, 0};
  const nfds_t nfds = _stop_fd >= 0 ? 2 : 1;

  const int n = ::poll(fds, nfds, static_cast<int>(timeout.count()));

  if (n < 0) {
    // A signal interrupted the wait. Nothing happened; let the worker come
    // back round, which also gives it a chance to notice the stop fd.
    if (errno == EINTR)
      return Event::Idle;
    record_error("poll", errno);
    return Event::Error;
  }

  // Nothing arrived within the timeout. This is the worker's cue to run its
  // idle sweep -- it is the only wakeup a quiet queue ever gets.
  if (n == 0)
    return Event::Idle;

  // Somebody asked everyone to stop.
  if (nfds == 2 && fds[1].revents != 0)
    return Event::Stop;

  if ((fds[0].revents & POLLIN) == 0) {
    // Not readable, so either a socket error or a spurious wakeup.
    if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      record_error("poll: netlink socket error", EIO);
      return Event::Error;
    }
    return Event::Idle;
  }

  const ssize_t rv = ::recv(fd, _buf.data(), _buf.size(), 0);
  if (rv < 0) {
    // ENOBUFS means the kernel dropped packets because we fell behind;
    // EINTR/EAGAIN are transient. None of them are worth giving up over.
    if (errno == ENOBUFS || errno == EINTR || errno == EAGAIN ||
        errno == EWOULDBLOCK)
      return Event::Idle;
    record_error("recv", errno);
    return Event::Error;
  }
  if (rv == 0)
    return Event::Idle;

  // One recv() usually carries several packets. This walks the buffer and calls
  // on_packet() -- and through it, the worker's callback -- once for each.
  nfq_handle_packet(_h, _buf.data(), static_cast<int>(rv));
  return Event::Packets;
}

// ---------------------------------------------------------------------------
// Per-packet path.
// ---------------------------------------------------------------------------

// libnetfilter_queue can only call a plain C function, so it calls this one and
// hands back the `this` we registered. Unwrap and get out of the way.
int NFQueue::on_packet(nfq_q_handle *, nfgenmsg *, nfq_data *nfa, void *user) {
  return static_cast<NFQueue *>(user)->handle(nfa);
}

int NFQueue::handle(nfq_data *nfa) {
  // The id is how the kernel knows which packet a verdict refers to. Without it
  // we cannot answer at all, so it is read first and unconditionally.
  std::uint32_t id = 0;
  if (auto *ph = nfq_get_msg_packet_hdr(nfa))
    id = ntohl(ph->packet_id);

  unsigned char *payload = nullptr;
  const int len = nfq_get_payload(nfa, &payload);

  _received.fetch_add(1, std::memory_order_relaxed);

  // A view over the receive buffer -- no copy. Since everything downstream runs
  // on this thread, most packets are decided and verdicted before this returns
  // and never need one. Only a packet somebody decides to HOLD has to be
  // materialized, and that is the holder's job.
  Packet pkt = (len > 0 && payload != nullptr)
                   ? Packet(payload, static_cast<std::uint32_t>(len), id)
                   : Packet(nullptr, 0, id);

  // An exception must never unwind through libnetfilter_queue's C frames -- it
  // would hit a frame with no unwind information and abort the process.
  // Swallowing it leaves `pkt` pending, which the fail-safe below then catches.
  try {
    _cb(std::move(pkt));
  } catch (...) {
  }

  // The callback should have either verdicted the packet or taken ownership of
  // it. Moving from a Packet clears its pending flag, so a packet that was held
  // does NOT land here -- if this is still pending, the callback genuinely
  // dropped it, and we allow it rather than strand a kernel queue slot forever.
  if (pkt.pending_verdict()) {
    _undecided.fetch_add(1, std::memory_order_relaxed);
    submit(std::move(pkt), Verdict::ALLOW);
  }
  return 0;
}

void NFQueue::submit(Packet &&pkt, Verdict v) {
  // Already answered for, or a moved-from husk. Verdicting an id twice is a
  // protocol error against the kernel, so this guard is load-bearing.
  if (!pkt.pending_verdict())
    return;

  pkt.set_verdict(v);
  pkt.release_bytes(); // done with the bytes; free them here, on this thread
  pkt.clear_pending();

  // NF_ACCEPT lets the packet carry on through the kernel's chains; NF_DROP
  // discards it, which is how a blocked flow is black-holed.
  const int rc = nfq_set_verdict(
      _qh, pkt.id(), v == Verdict::BLOCK ? NF_DROP : NF_ACCEPT, 0, nullptr);

  // Only count a verdict the kernel actually took. If this fails the packet is
  // still sitting in the kernel queue, and outstanding() will show it.
  if (rc >= 0)
    _verdicted.fetch_add(1, std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

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
