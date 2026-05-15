#pragma once

#include <array>
#include <cstdint>
#include <memory>

// The verdict applied to a packet at the netlink queue.
enum class Verdict : uint8_t {
  ALLOW,
  BLOCK,
};

// The dissected packet: the 5-tuple that routes it to a worker, plus where its
// L4 payload starts. Populated by Packet::flow_view().
struct FlowView {
  uint8_t ip_version = 0; // 4 or 6
  uint8_t ip_proto = 0;   // IPPROTO_TCP / IPPROTO_UDP

  // Network-order addresses; IPv4 occupies the first 4 bytes, IPv6 all 16.
  std::array<uint8_t, 16> src_ip{};
  std::array<uint8_t, 16> dst_ip{};

  // Host byte order.
  uint16_t src_port = 0;
  uint16_t dst_port = 0;

  // The L4 payload: points into the packet's own bytes, so it is valid only
  // while that packet is alive and unreleased. Empty for a pure ACK/SYN/FIN.
  const uint8_t *payload = nullptr;
  uint32_t payload_len = 0;

  // Raw TCP flags byte (FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10).
  // Zero for UDP.
  uint8_t tcp_flags = 0;

  // Flow key: a hash of the 5-tuple, used two ways -- `key % worker_count`
  // picks the owning worker on the receive thread, and the worker's extractor
  // keys its per-flow cache by it. Direction-insensitive, so both directions of
  // a connection land on the same worker and the same cache entry.
  //
  // Purely internal: it is never compared against, or derived from, any key
  // produced by PcapPlusPlus.
  uint32_t key = 0;
};

// A layer-3 packet as delivered by NFQUEUE, carried end to end: the same object
// travels recv thread -> worker -> extractor -> verdict thread, moved at every
// hop and never copied.
//
// It has three states, and the two transitions between them are the only places
// bytes are allocated or freed:
//
//   view    _view -> the NFQUEUE receive buffer, no ownership.
//           Only ever valid on the receive thread: the next recv() overwrites
//           those bytes, so a view must never cross a thread.
//              | materialize()  -- the one copy in the pipeline
//              v
//   owned   _owned holds the bytes. Safe to hand to another thread; lives until
//           the reassembler is done with it.
//              | release_bytes()
//              v
//   shell   No bytes, just `id` + `verdict`. All the verdict thread needs, so
//           this is what crosses to it -- 32 bytes, no heap.
//
// Move-only by design: exactly one Packet owns a buffer, which makes the
// pipeline a single-owner chain and stops a stray copy from double-verdicting an
// id. A moved-from Packet is left empty and no longer pending.
class Packet {
public:
  Packet() = default;

  // A view over bytes owned by someone else. The packet is born owing a
  // verdict (see pending_verdict()).
  Packet(const uint8_t *data, uint32_t len, uint32_t id) noexcept
      : _view(data), _len(len), _id(id), _pending(true) {}

  Packet(Packet &&o) noexcept
      : _view(o._view), _owned(std::move(o._owned)), _len(o._len), _id(o._id),
        _verdict(o._verdict), _pending(o._pending) {
    o.clear();
  }
  Packet &operator=(Packet &&o) noexcept {
    if (this != &o) {
      _view = o._view;
      _owned = std::move(o._owned);
      _len = o._len;
      _id = o._id;
      _verdict = o._verdict;
      _pending = o._pending;
      o.clear();
    }
    return *this;
  }
  Packet(const Packet &) = delete;
  Packet &operator=(const Packet &) = delete;

  // Raw layer-3 bytes (null in the shell state) and the NFQUEUE packet id.
  // `len()` keeps reporting the original length after release_bytes(), so a
  // shell still says how big the packet was.
  const uint8_t *data() const noexcept { return _view ? _view : _owned.get(); }
  uint32_t len() const noexcept { return _len; }
  uint32_t id() const noexcept { return _id; }

  bool has_bytes() const noexcept { return data() != nullptr; }
  bool is_view() const noexcept { return _view != nullptr; }

  // view -> owned. Copies the bytes out of the NFQUEUE buffer so they survive
  // the hop to a worker thread. Idempotent: a no-op on an already-owning packet
  // and on a shell. This is the only allocation on the packet path.
  void materialize();

  // owned/view -> shell. Frees the bytes on the calling thread -- always the
  // thread that last used them, which keeps allocation and release on the same
  // side of the queue.
  void release_bytes() noexcept {
    _owned.reset();
    _view = nullptr;
  }

  // The verdict that will be applied to this packet at the queue. Defaults to
  // ALLOW so that a path which forgets to decide fails open rather than
  // silently dropping traffic.
  Verdict verdict() const noexcept { return _verdict; }
  void set_verdict(Verdict v) noexcept { _verdict = v; }

  // True while this packet still owes the kernel a verdict. Set on arrival,
  // cleared by NFQueue::submit() and by being moved from. NFQueue uses it to
  // catch a callback that drops a packet on the floor -- an unverdicted packet
  // holds a kernel queue slot forever and hangs its connection.
  bool pending_verdict() const noexcept { return _pending; }
  void clear_pending() noexcept { _pending = false; }

  // Parse the 5-tuple into `flow` (network-order addresses, host-order ports,
  // proto, ip_version) and fill its routing key. Returns false if the packet is
  // not a dissectable IPv4/IPv6 TCP/UDP packet (flow is left default). All
  // reads are bounds-checked; never allocates or throws.
  bool flow_view(FlowView &flow) const noexcept;

  // The routing key: a hash of the 5-tuple. Use `flow_key() % worker_count` to
  // pick the owning worker. Returns 0 if the packet is not dissectable.
  uint32_t flow_key() const noexcept;

private:
  // Leave a moved-from packet inert: no bytes, no id, owing nothing. Without
  // this the scalars would survive the move and the husk would still look like
  // a submittable shell.
  void clear() noexcept {
    _view = nullptr;
    _len = 0;
    _id = 0;
    _verdict = Verdict::ALLOW;
    _pending = false;
  }

  // At most one of these is live: `_view` points at external bytes (view mode),
  // `_owned` holds them (concrete mode), or neither (shell). data() returns
  // whichever is active.
  const uint8_t *_view = nullptr;
  std::unique_ptr<uint8_t[]> _owned;
  uint32_t _len = 0;
  uint32_t _id = 0;
  Verdict _verdict = Verdict::ALLOW;
  bool _pending = false;
};
