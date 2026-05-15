#include "packet.hpp"

#include <cstring>

// Everything below is internal to this translation unit: byte-wise big-endian
// reads, IPv4/IPv6 dissection, and the flow hash. Allocation- and
// exception-free and strictly bounds-checked, so a malformed or truncated
// packet can never read out of bounds.
namespace {

// --- byte-wise big-endian (network order) readers --------------------------
// No unaligned-load UB, no host-endianness dependency. Callers guarantee the
// bytes exist (each call site bounds-checks first).
inline uint16_t be16(const uint8_t *p) noexcept {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
// IP protocol numbers we act on: TCP (HTTP/1,2 over TLS) and UDP (HTTP/3/QUIC).
constexpr uint8_t kProtoTcp = 6;
constexpr uint8_t kProtoUdp = 17;

// Transport (TCP/UDP): fill the 5-tuple ports + proto and locate the payload.
// Returns false for anything that isn't TCP/UDP or is too short to dissect.
bool parseL4(uint8_t proto, const uint8_t *l4, uint32_t l4_len, FlowView &flow,
             const uint8_t *&payload, uint32_t &payload_len) noexcept {
  flow.ip_proto = proto;
  if (proto == kProtoTcp) {
    if (l4_len < 20) // minimum TCP header
      return false;
    flow.src_port = be16(l4);
    flow.dst_port = be16(l4 + 2);
    flow.tcp_flags = l4[13];
    const uint32_t data_off = static_cast<uint32_t>(l4[12] >> 4) * 4u;
    if (data_off < 20 || data_off > l4_len)
      return false; // bogus data offset
    payload = l4 + data_off;
    payload_len = l4_len - data_off;
    return true;
  }
  if (proto == kProtoUdp) {
    if (l4_len < 8) // UDP header is fixed 8 bytes
      return false;
    flow.src_port = be16(l4);
    flow.dst_port = be16(l4 + 2);
    const uint16_t udp_len = be16(l4 + 4);
    uint32_t plen = l4_len - 8;
    if (udp_len >= 8 && static_cast<uint32_t>(udp_len - 8) <= plen)
      plen = static_cast<uint32_t>(udp_len - 8);
    payload = l4 + 8;
    payload_len = plen;
    return true;
  }
  return false; // not a transport we care about
}

bool parseIPv4(const uint8_t *data, uint32_t len, FlowView &flow,
               const uint8_t *&payload, uint32_t &payload_len) noexcept {
  if (len < 20) // minimum IPv4 header
    return false;
  flow.ip_version = 4;

  const uint32_t ihl = static_cast<uint32_t>(data[0] & 0x0f) * 4u;
  if (ihl < 20 || ihl > len)
    return false; // bogus header length

  // A non-first fragment (offset != 0) carries no L4 header -> can't dissect.
  if ((be16(data + 6) & 0x1fff) != 0)
    return false;

  std::memcpy(flow.src_ip.data(), data + 12, 4); // first 4 bytes of the field
  std::memcpy(flow.dst_ip.data(), data + 16, 4);

  // Trust total_length only when sane (strips any L2 padding); else use capture.
  const uint16_t total_len = be16(data + 2);
  uint32_t l3_len = len;
  if (total_len >= ihl && total_len <= len)
    l3_len = total_len;

  return parseL4(data[9], data + ihl, l3_len - ihl, flow, payload, payload_len);
}

// IPv6 extension headers we follow past.
constexpr uint8_t kV6HopByHop = 0;
constexpr uint8_t kV6Routing = 43;
constexpr uint8_t kV6Fragment = 44;
constexpr uint8_t kV6DestOpts = 60;
constexpr uint8_t kV6Mobility = 135;
constexpr int kMaxV6ExtHeaders = 8; // bound the walk so crafted chains can't spin

bool parseIPv6(const uint8_t *data, uint32_t len, FlowView &flow,
               const uint8_t *&payload, uint32_t &payload_len) noexcept {
  constexpr uint32_t kFixed = 40;
  if (len < kFixed)
    return false;
  flow.ip_version = 6;

  const uint16_t plen = be16(data + 4); // length after the fixed header
  std::memcpy(flow.src_ip.data(), data + 8, 16);
  std::memcpy(flow.dst_ip.data(), data + 24, 16);

  uint32_t l3_len = len;
  if (kFixed + static_cast<uint32_t>(plen) <= len)
    l3_len = kFixed + plen;

  uint8_t next = data[6];
  uint32_t off = kFixed;

  for (int i = 0; i < kMaxV6ExtHeaders; ++i) {
    if (next == kProtoTcp || next == kProtoUdp)
      return parseL4(next, data + off, l3_len - off, flow, payload, payload_len);

    switch (next) {
    case kV6HopByHop:
    case kV6Routing:
    case kV6DestOpts:
    case kV6Mobility: {
      // [next(1)][hdr_ext_len(1)][...]; length in 8-octet units, first excluded.
      if (off + 2 > l3_len)
        return false;
      next = data[off];
      off += (static_cast<uint32_t>(data[off + 1]) + 1u) * 8u;
      if (off > l3_len)
        return false;
      break;
    }
    case kV6Fragment: {
      // Fixed 8-byte header; nonzero fragment offset => not the first fragment.
      if (off + 8 > l3_len)
        return false;
      if ((be16(data + off + 2) & 0xfff8) != 0)
        return false;
      next = data[off];
      off += 8;
      break;
    }
    default:
      return false; // No-Next-Header / ESP / AH / ICMPv6 / unknown: not for us
    }
  }
  return false; // too many extension headers -> bail (bounded)
}

// Flow key: a light base-131 polynomial hash of the 5-tuple.
//
// Direction-insensitive: the two endpoints are hashed separately and then
// combined in a symmetric order, so a packet and its reply produce the same key.
// That keeps both directions of a connection on one worker and in one cache
// entry, without depending on which side we happen to see first.
uint32_t endpointHash(const std::array<uint8_t, 16> &ip, uint16_t port) noexcept {
  std::size_t h = 0;
  for (uint8_t b : ip)
    h = h * 131 + b;
  h = h * 131 + port;
  return static_cast<uint32_t>(h);
}

uint32_t routeKey(const FlowView &f) noexcept {
  const uint32_t a = endpointHash(f.src_ip, f.src_port);
  const uint32_t b = endpointHash(f.dst_ip, f.dst_port);
  const uint32_t lo = a < b ? a : b; // symmetric: order the endpoints
  const uint32_t hi = a < b ? b : a;
  std::size_t h = f.ip_proto;
  h = h * 1000003 + lo;
  h = h * 1000003 + hi;
  return static_cast<uint32_t>(h);
}

// L3 dissection: fills the 5-tuple in `flow` and points `payload`/`payload_len`
// at the L4 payload. False if the packet is not a dissectable IPv4/IPv6 TCP/UDP
// packet.
bool parseFlow(const uint8_t *data, uint32_t len, FlowView &flow,
               const uint8_t *&payload, uint32_t &payload_len) noexcept {
  flow = FlowView{};
  if (data == nullptr || len < 1)
    return false;

  // Dispatch on the version nibble, then locate the transport payload.
  const uint8_t version = static_cast<uint8_t>(data[0] >> 4);
  if (version == 4)
    return parseIPv4(data, len, flow, payload, payload_len);
  if (version == 6)
    return parseIPv6(data, len, flow, payload, payload_len);
  return false;
}

} // namespace

void Packet::materialize() {
  if (_view == nullptr)
    return; // already owning, or a shell: nothing to copy

  if (_len > 0) {
    // for_overwrite, not make_unique: the latter value-initializes, so we would
    // memset the whole buffer only to memcpy over it immediately.
    auto buf = std::make_unique_for_overwrite<uint8_t[]>(_len);
    std::memcpy(buf.get(), _view, _len);
    _owned = std::move(buf);
  }
  _view = nullptr; // view -> owned (or -> shell for a zero-length packet)
}

bool Packet::flow_view(FlowView &flow) const noexcept {
  const uint8_t *payload = nullptr;
  uint32_t payload_len = 0;
  if (!parseFlow(data(), len(), flow, payload, payload_len))
    return false;
  flow.payload = payload;
  flow.payload_len = payload_len;
  flow.key = routeKey(flow);
  return true;
}

uint32_t Packet::flow_key() const noexcept {
  FlowView flow;
  return flow_view(flow) ? flow.key : 0;
}
