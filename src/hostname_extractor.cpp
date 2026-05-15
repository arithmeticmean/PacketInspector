#include "hostname_extractor.hpp"

#include <utility>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PacketUtils.h>
#include <pcapplusplus/ProtocolType.h>
#include <pcapplusplus/RawPacket.h>

namespace {

// A ClientHello arrives in a handful of segments and fits a single TLS record
// (<= 16 KiB). These bounds cap how long/large we buffer a still-undecided flow
// before giving up and letting its packets through (no hostname).
constexpr std::size_t kMaxPacketsPerConn = 32;
constexpr std::size_t kMaxStreamBytes = 32u * 1024u;

// A handshake completes in well under a second on any live path; 10 s is a
// generous ceiling before we release a stalled/partial flow.
constexpr auto kWaitIdleTimeout = std::chrono::seconds(10);

// A blocked flow has every packet dropped, so no FIN or RST ever reaches us and
// nothing else would ever remove the entry. This is the only thing that does.
constexpr auto kBlockIdleTimeout = std::chrono::seconds(60);

constexpr auto kSweepInterval = std::chrono::seconds(1);

// The cheap gate that starts tracking a flow: a TLS handshake record opens with
// content_type 0x16 and major version 0x03. Deliberately permissive -- a false
// positive costs one tracked flow that resolves to "no hostname", while a false
// negative loses the flow permanently. The real parse happens later, on the
// reassembled stream, where a truncated ClientHello can be waited out instead of
// rejected.
bool opensTlsHandshake(const uint8_t *payload, uint32_t len) noexcept {
  return len >= 2 && payload[0] == 0x16 && payload[1] == 0x03;
}

constexpr uint8_t kProtoTcp = 6;
constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpRst = 0x04;
constexpr uint8_t kTcpAck = 0x10;

// How much closed-connection state PcapPlusPlus is allowed to reclaim per
// purge, and how long it must sit closed first.
//
// The defaults are 30 per call and a 5 second delay, which are wildly out of
// scale here: we close a connection for every flow we resolve, so at a few
// thousand connections/sec a worker retires hundreds per second and reclaims
// thirty. The reassembler's internal state then grows without bound, every
// packet it handles gets slower, packets sit in the kernel queue longer waiting
// for a verdict, and the queue eventually overflows -- which shows up as
// dropped SYNs and multi-second TCP handshakes long before anything looks like
// a CPU limit.
constexpr uint32_t kPcppClosedDelaySec = 1;
constexpr uint32_t kPcppPurgeBatch = 8192;

// A client->server connection opening: SYN set, ACK clear. The server's SYN-ACK
// has both, and must not start a flow -- though with a direction-insensitive
// flow key it lands on the entry the client's SYN already created.
//
// Tracking from here, rather than waiting for a packet that opens a TLS record,
// is what catches a ClientHello whose opening segment arrives after its
// continuations: the flow is already tracked, so nothing is allowed through and
// discarded before we know what it is.
bool isClientSyn(const FlowView &f) noexcept {
  return (f.tcp_flags & kTcpSyn) != 0 && (f.tcp_flags & kTcpAck) == 0;
}

// Which side of the connection reassembled data came from. pcpp numbers sides
// by order of appearance, and the first packet we ever feed for a connection is
// the client's -- its SYN when we saw one, otherwise the segment that opened the
// TLS record. So side 0 is the client, and we want nothing else: a ClientHello
// is parsed out of the client->server stream, and appending the server's reply
// to that buffer would corrupt it.
constexpr int8_t kClientSide = 0;

// Verdict from extractHostname(). Built for incremental use here: append the
// newly reassembled client->server bytes to a per-flow buffer, call
// extractHostname() on the whole buffer, then:
//   Found    -> use host/host_len, done with this flow
//   NotFound -> stop; there is no hostname to get here
//   NeedMore -> keep buffering; call again after the next reassembled chunk
enum class HostnameResult : uint8_t { Found, NotFound, NeedMore };

// Extract the hostname (TLS SNI host_name) from the reassembled client->server
// TCP stream. `tls_data`/`len` start at the TLS record layer and may hold only
// part of the ClientHello (hence NeedMore). Zero-copy on Found:
// `host`/`host_len` point inside `tls_data` (not NUL-terminated; valid only
// while that buffer lives). Assumes the ClientHello fits one TLS record (the
// normal case). Never allocates; every read is bounds-checked.
HostnameResult extractHostname(const uint8_t *tls_data, uint32_t len,
                               const uint8_t *&host,
                               uint32_t &host_len) noexcept {
  const uint8_t *p = tls_data;
  auto rd16 = [](const uint8_t *q) noexcept -> uint16_t {
    return static_cast<uint16_t>((static_cast<uint16_t>(q[0]) << 8) | q[1]);
  };

  // --- TLS record header: content_type(1) version(2) length(2) ---
  if (len < 1)
    return HostnameResult::NeedMore;
  if (p[0] != 0x16) // not a handshake record -> never a ClientHello
    return HostnameResult::NotFound;
  if (len >= 2 && p[1] != 0x03) // TLS/SSL3 share major 3
    return HostnameResult::NotFound;
  if (len < 5)
    return HostnameResult::NeedMore; // valid handshake-record prefix, need more

  const uint16_t rec_len = rd16(p + 3);
  if (rec_len == 0 || rec_len > 16384) // TLSPlaintext.length cap = 2^14
    return HostnameResult::NotFound;

  // --- Handshake header: msg_type(1) length(3) ---
  if (len < 9)
    return HostnameResult::NeedMore; // have the record header, need the hs
                                     // header
  if (p[5] != 0x01) // not a ClientHello (e.g. ServerHello 0x02)
    return HostnameResult::NotFound;
  const uint32_t hs_len = (static_cast<uint32_t>(p[6]) << 16) |
                          (static_cast<uint32_t>(p[7]) << 8) | p[8];
  if (hs_len < 34 ||
      hs_len > 65535) // legacy_version+random floor; sane ceiling
    return HostnameResult::NotFound;

  const uint32_t body_end = 9u + hs_len; // record hdr(5) + hs hdr(4) + body
  if (len < body_end)
    return HostnameResult::NeedMore; // full ClientHello not reassembled yet

  // --- Complete ClientHello body [9, body_end): walk to server_name ---
  uint32_t o = 9;
  auto have = [&](uint32_t k) noexcept { return o + k <= body_end; };

  // legacy_version(2) + random(32) + session_id_len(1).
  if (!have(2 + 32 + 1))
    return HostnameResult::NotFound;
  o += 2 + 32;
  o += 1u + p[o]; // session_id_len + session_id

  // cipher_suites: length(2) + suites.
  if (!have(2))
    return HostnameResult::NotFound;
  o += 2u + rd16(p + o);

  // compression_methods: length(1) + methods.
  if (!have(1))
    return HostnameResult::NotFound;
  o += 1u + p[o];

  // extensions: total_length(2) + extension list.
  if (!have(2))
    return HostnameResult::NotFound; // no extensions block -> no hostname
  uint32_t ext_end = o + 2u + rd16(p + o);
  o += 2;
  if (ext_end > body_end)
    ext_end = body_end;

  // Each extension: type(2) length(2) data(length). Look for server_name (0).
  while (o + 4 <= ext_end) {
    const uint16_t etype = rd16(p + o);
    const uint16_t elen = rd16(p + o + 2);
    o += 4;
    if (o + elen > ext_end)
      break;
    if (etype == 0x0000) {
      // ServerNameList: list_length(2) { name_type(1) name_length(2) name }...
      uint32_t q = o;
      uint32_t list_end = o + elen;
      if (q + 2 > list_end)
        return HostnameResult::NotFound;
      const uint32_t named = q + 2u + rd16(p + q);
      q += 2;
      if (named < list_end)
        list_end = named;
      while (q + 3 <= list_end) {
        const uint8_t name_type = p[q];
        const uint16_t name_len = rd16(p + q + 1);
        q += 3;
        if (q + name_len > list_end)
          break;
        if (name_type == 0x00) { // host_name
          host = p + q;
          host_len = name_len;
          return HostnameResult::Found;
        }
        q += name_len;
      }
      return HostnameResult::NotFound; // server_name present but no host_name
    }
    o += elen;
  }
  return HostnameResult::NotFound; // no server_name extension
}

} // namespace

// Out-of-line to anchor the vtable in this translation unit.
HostnameExtractor::~HostnameExtractor() = default;

TcpTlsHostnameExtractor::TcpTlsHostnameExtractor(Decide decide,
                                                 VerdictSink &sink,
                                                 std::size_t max_flows,
                                                 std::size_t max_blocked)
    : _decide(std::move(decide)), _sink(sink),
      _reassembly(&TcpTlsHostnameExtractor::onMessageReady, this, nullptr,
                  &TcpTlsHostnameExtractor::onConnectionEnd,
                  pcpp::TcpReassemblyConfiguration(
                      /*removeConnInfo=*/true, kPcppClosedDelaySec,
                      kPcppPurgeBatch)),
      _max_flows(max_flows == 0 ? 1 : max_flows) {
  // Derive from the flow cap when unset, so configuring one keeps the other in
  // proportion. Never zero: the ring is indexed modulo its size, and the tests
  // build extractors with caps small enough for the division to reach zero.
  _max_blocked = max_blocked != 0
                     ? max_blocked
                     : std::max<std::size_t>(1, _max_flows / kDefaultBlockedShare);
  _max_blocked = std::min(_max_blocked, _max_flows);
  // Allocated once and never resized. Zero-filled slots need no sentinel:
  // every eviction re-checks the victim is still a blocked flow before
  // touching it, so a stale or never-written slot simply finds nothing.
  _block_ring.assign(_max_blocked, 0);
}

void TcpTlsHostnameExtractor::remember_blocked(uint32_t key) {
  // Evict first, then take the slot. Constant work per registration, whether
  // the ring is empty or full -- the property that keeps this off the cliff
  // that a reclaim-when-full scheme would have.
  const uint32_t victim = _block_ring[_block_next];
  if (victim != 0 && victim != key) {
    auto it = _conns.find(victim);
    // The key may have been reused by a *different* flow since, and that flow
    // may still be undecided. Erasing it would be the very bug this bound
    // exists to prevent, so the state is checked, not assumed.
    if (it != _conns.end() && it->second.state == State::Block) {
      _conns.erase(it);
      publish();
    }
  }
  _block_ring[_block_next] = key;
  _block_next = (_block_next + 1) % _max_blocked;
}

bool TcpTlsHostnameExtractor::evict_oldest_blocked() {
  // One full turn at most: slots may hold keys already reclaimed elsewhere.
  for (std::size_t tried = 0; tried < _max_blocked; ++tried) {
    const uint32_t victim = _block_ring[_block_next];
    _block_ring[_block_next] = 0;
    _block_next = (_block_next + 1) % _max_blocked;
    if (victim == 0)
      continue;
    auto it = _conns.find(victim);
    if (it != _conns.end() && it->second.state == State::Block) {
      _conns.erase(it);
      publish();
      return true;
    }
  }
  return false;
}

void TcpTlsHostnameExtractor::sink_one(Packet &&pkt, Verdict v) {
  _sink.submit(std::move(pkt), v);
}

void TcpTlsHostnameExtractor::feed(Packet pkt) {
  // Republish the table size however we leave -- feed() has a lot of early
  // returns, and a counter that is only right on some of them is worse than no
  // counter at all. One relaxed store per packet.
  struct PublishOnExit {
    TcpTlsHostnameExtractor *self;
    ~PublishOnExit() { self->publish(); }
  } published{this};

  const auto now = std::chrono::steady_clock::now();
  tick(now);

  FlowView f;
  // Anything we cannot dissect, or that is not TCP, we have nothing to say
  // about. (The receive thread already filters these out; this is the backstop
  // for a packet that slipped through.)
  if (!pkt.has_bytes() || !pkt.flow_view(f) || f.ip_proto != kProtoTcp) {
    sink_one(std::move(pkt), Verdict::ALLOW);
    return;
  }

  const uint32_t key = f.key;
  auto it = _conns.find(key);

  // Already decided against: drop it without going near the reassembler. No
  // pcpp::Packet is built on this path.
  if (it != _conns.end() && it->second.state == State::Block) {
    it->second.last = now;
    sink_one(std::move(pkt), Verdict::BLOCK);
    return;
  }

  if (it == _conns.end()) {
    // Start tracking at the connection's SYN, so the whole client->server
    // stream is captured from byte zero however its segments are ordered. The
    // handshake-opening test is the fallback for a flow whose SYN we never saw
    // -- one already in progress when we attached.
    //
    // Anything else on an untracked flow tells us nothing. This is the common
    // case for the bulk of traffic: one failed hash lookup and a flags test.
    if (!isClientSyn(f) && !opensTlsHandshake(f.payload, f.payload_len)) {
      sink_one(std::move(pkt), Verdict::ALLOW);
      return;
    }
    if (_conns.size() >= _max_flows) {
      // Rate-limited, unlike the version this replaces. sweep() walks the whole
      // table; calling it unguarded here meant that once the table was full and
      // stayed full, every new flow paid an O(n) scan that reclaimed nothing --
      // an O(n) step on the busiest path there is, precisely when the machine
      // could least afford it.
      if (now - _lastSweep >= kSweepInterval) {
        _lastSweep = now;
        sweep(now);
      }
      // A decided flow must never keep an undecided one out: the first carries
      // no correctness, the second is a hostname waiting to be checked. Losing
      // a blocked entry only means re-parsing that connection's next
      // retransmitted ClientHello and reaching the same verdict.
      if (_conns.size() >= _max_flows)
        evict_oldest_blocked();
      if (_conns.size() >= _max_flows) {
        _dropped_at_cap.fetch_add(1, std::memory_order_relaxed);
        sink_one(std::move(pkt), Verdict::ALLOW);
        return;
      }
    }
    it = _conns.try_emplace(key).first;
  }

  Conn &c = it->second;
  c.last = now;

  if (c.held.size() >= kMaxPacketsPerConn) {
    resolve(key, std::nullopt); // flooded without a decision -> give up
    sink_one(std::move(pkt), Verdict::ALLOW);
    return;
  }

  // A pure ACK carries no payload to order and no state transition to observe,
  // so handing it to the reassembler buys nothing and costs a pcpp::Packet
  // construction -- several heap allocations -- on the busiest path there is.
  // Everything it actually needs still goes in: payload, the SYN that
  // establishes its sequence baseline (without which a ClientHello whose
  // opening segment arrives late cannot be reassembled), and FIN/RST so a
  // connection end is seen promptly rather than waiting for the idle sweep.
  const bool hold = f.payload_len > 0;
  if (!hold && (f.tcp_flags & (kTcpSyn | kTcpFin | kTcpRst)) == 0) {
    sink_one(std::move(pkt), Verdict::ALLOW);
    return;
  }

  // Wrap the bare L3 packet; LINKTYPE_RAW lets pcpp pick IPv4/IPv6 by itself.
  timeval ts{};
  pcpp::RawPacket raw(pkt.data(), static_cast<int>(pkt.len()), ts, false,
                      pcpp::LINKTYPE_RAW);
  pcpp::Packet parsed(&raw);

  // Only packets carrying payload are worth holding: a bare SYN/ACK/FIN teaches
  // us nothing, and holding it would just stall the handshake.
  if (hold)
    // Into the flow BEFORE reassembly, so a decision reached on this very
    // packet includes it. The move preserves the buffer's address, so
    // `raw`/`parsed` stay valid for reassemblePacket().
    c.held.push_back(std::move(pkt));

  _current_key = key;
  _feeding = true;
  _reassembly.reassemblePacket(parsed); // may resolve(key, ...) synchronously
  _feeding = false;
  // `c` may have been erased by resolve(); do not touch it past this point.
  drain_closes();

  if (hold) {
    // Reassembled, so the bytes have done their job -- drop them and keep the
    // shell. If the flow resolved during the call the packet is already at the
    // sink, which released it there.
    auto still = _conns.find(key);
    if (still != _conns.end() && !still->second.held.empty())
      still->second.held.back().release_bytes();
  } else {
    sink_one(std::move(pkt), Verdict::ALLOW);
  }
}

void TcpTlsHostnameExtractor::tick(
    std::chrono::steady_clock::time_point now) {
  if (now - _lastSweep < kSweepInterval)
    return;
  _lastSweep = now;
  sweep(now);
}

void TcpTlsHostnameExtractor::flush() {
  std::vector<uint32_t> waiting;
  waiting.reserve(_conns.size());
  for (const auto &[key, c] : _conns)
    if (c.state == State::Wait)
      waiting.push_back(key);
  for (uint32_t key : waiting)
    resolve(key, std::nullopt); // release whatever is still held
  _conns.clear();
  drain_closes();
  publish();
}

void TcpTlsHostnameExtractor::drain_closes() {
  for (uint32_t token : _to_close)
    _reassembly.closeConnection(token);
  _to_close.clear();
}

// Both callbacks fire synchronously from inside reassemblePacket(), for the
// connection whose packet we just fed -- so `_current_key` identifies the flow
// and pcpp's own connection identity is never used to look up our state.
void TcpTlsHostnameExtractor::onMessageReady(int8_t side,
                                             const pcpp::TcpStreamData &data,
                                             void *cookie) {
  auto *self = static_cast<TcpTlsHostnameExtractor *>(cookie);
  if (!self->_feeding)
    return;
  if (side != kClientSide)
    return; // server->client data: not where a ClientHello lives

  auto it = self->_conns.find(self->_current_key);
  if (it == self->_conns.end() || it->second.state != State::Wait)
    return; // already decided this flow -- ignore trailing/late data
  Conn &c = it->second;

  // Their key for this connection, kept only so we can hand it back to
  // closeConnection(). We never interpret or compare it.
  c.pcpp_key = data.getConnectionData().flowKey;

  c.stream.insert(c.stream.end(), data.getData(),
                  data.getData() + data.getDataLength());

  const uint8_t *host = nullptr;
  uint32_t host_len = 0;
  switch (extractHostname(c.stream.data(),
                          static_cast<uint32_t>(c.stream.size()), host,
                          host_len)) {
  case HostnameResult::Found:
    self->resolve(self->_current_key,
                  std::string(reinterpret_cast<const char *>(host), host_len));
    break;
  case HostnameResult::NotFound:
    self->resolve(self->_current_key, std::nullopt);
    break;
  case HostnameResult::NeedMore:
    if (c.stream.size() > kMaxStreamBytes)
      self->resolve(self->_current_key, std::nullopt); // oversized, no hello
    break;
  }
}

void TcpTlsHostnameExtractor::onConnectionEnd(
    const pcpp::ConnectionData & /*conn*/,
    pcpp::TcpReassembly::ConnectionEndReason /*reason*/, void *cookie) {
  auto *self = static_cast<TcpTlsHostnameExtractor *>(cookie);
  if (!self->_feeding)
    return; // from purge/close, not from a fed packet: the sweep handles those

  auto it = self->_conns.find(self->_current_key);
  if (it == self->_conns.end())
    return;
  // pcpp is finished with this connection; closing it again would be an error.
  it->second.pcpp_closed = true;
  // FIN/RST: release whatever is still held for this flow (no hostname).
  self->resolve(self->_current_key, std::nullopt);
}

void TcpTlsHostnameExtractor::resolve(uint32_t key,
                                      std::optional<std::string> hostname) {
  auto it = _conns.find(key);
  if (it == _conns.end())
    return; // guard against double-delivery (e.g. decision then FIN)
  Conn &c = it->second;
  if (c.state == State::Block)
    return; // decided already; its packets are verdicted as they arrive

  const Verdict v = _decide(hostname);
  std::vector<Packet> held = std::move(c.held);
  const uint32_t token = c.pcpp_key;
  const bool closed = c.pcpp_closed;

  if (v == Verdict::BLOCK) {
    // Keep the entry so the rest of the connection is dropped on arrival. It is
    // reaped by kBlockIdleTimeout -- nothing else will, since a blocked flow
    // never gets a FIN or RST through to us.
    c.state = State::Block;
    c.held.clear();
    c.stream.clear();
    c.stream.shrink_to_fit();
    // Registering may evict a different, older blocked flow. `c` is a
    // reference into _conns and must not be used afterwards.
    remember_blocked(key);
  } else {
    // Erased, so later packets of this flow take the untracked path and are
    // allowed on a single failed lookup. This is why two states are enough.
    _conns.erase(it);
  }

  // Our state is gone (or marked Block) before this, so the end callback that
  // closeConnection() triggers finds nothing to do. The close itself is
  // deferred: we may be inside reassemblePacket() right now.
  if (token != 0 && !closed)
    _to_close.push_back(token);

  _sink.submit(std::move(held), v);
}

void TcpTlsHostnameExtractor::sweep(std::chrono::steady_clock::time_point now) {
  // Collect first, then act: resolve() erases from _conns.
  std::vector<uint32_t> expired;
  std::size_t blocked = 0;
  for (const auto &[key, c] : _conns) {
    if (c.state == State::Block)
      ++blocked;
    const auto idle =
        c.state == State::Block ? kBlockIdleTimeout : kWaitIdleTimeout;
    if (now - c.last >= idle)
      expired.push_back(key);
  }
  // Recomputed here rather than tracked at every insert and erase. This walk
  // already exists, so the count is free -- and a derived gauge cannot drift
  // out of step with reality the way a hand-maintained one silently would.
  _blocked.store(blocked, std::memory_order_relaxed);
  for (uint32_t key : expired) {
    auto it = _conns.find(key);
    if (it == _conns.end())
      continue;
    if (it->second.state == State::Block)
      _conns.erase(it); // just forget it; nothing is held
    else
      resolve(key, std::nullopt); // stalled/partial -> let it through
  }

  _reassembly.purgeClosedConnections(); // free pcpp state for ended flows
  drain_closes();
  publish();
}
