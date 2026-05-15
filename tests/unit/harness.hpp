#pragma once

// Shared test scaffolding: a VerdictSink that records what it was handed, plus
// helpers for building owning packets and whole flows.

#include "packet.hpp"
#include "packet_builders.hpp"
#include "verdict_sink.hpp"

#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace testpkt {

// Records the verdict issued for every packet id. Mirrors what NFQueue::submit
// does to a packet (stamp, release, mark decided) so the tests exercise the same
// ownership contract, and counts any packet verdicted twice -- which in
// production would mean issuing two kernel verdicts for one id.
//
// Thread-safe: the worker tests drive it from the worker's thread.
class FakeSink : public VerdictSink {
public:
  void submit(Packet &&pkt, Verdict v) override {
    const std::lock_guard<std::mutex> lk(_m);
    record(pkt, v);
  }

  void submit(std::vector<Packet> &&pkts, Verdict v) override {
    const std::lock_guard<std::mutex> lk(_m);
    for (Packet &p : pkts)
      record(p, v);
    pkts.clear();
  }

  std::optional<Verdict> verdict_for(uint32_t id) const {
    const std::lock_guard<std::mutex> lk(_m);
    const auto it = _seen.find(id);
    if (it == _seen.end())
      return std::nullopt;
    return it->second;
  }

  std::size_t count() const {
    const std::lock_guard<std::mutex> lk(_m);
    return _seen.size();
  }

  std::size_t count_with(Verdict v) const {
    const std::lock_guard<std::mutex> lk(_m);
    std::size_t n = 0;
    for (const auto &[id, got] : _seen)
      if (got == v)
        ++n;
    return n;
  }

  // Nonzero means some packet was verdicted more than once.
  std::size_t double_submits() const {
    const std::lock_guard<std::mutex> lk(_m);
    return _double;
  }

private:
  void record(Packet &p, Verdict v) {
    if (!p.pending_verdict()) {
      ++_double; // an already-decided packet reached a sink again
      return;
    }
    p.set_verdict(v);
    p.release_bytes();
    p.clear_pending();
    if (!_seen.emplace(p.id(), v).second)
      ++_double;
  }

  mutable std::mutex _m;
  std::unordered_map<uint32_t, Verdict> _seen;
  std::size_t _double = 0;
};

// An owning packet over `b`, as the receive thread hands to a worker.
inline Packet owned(const std::vector<uint8_t> &b, uint32_t id) {
  Packet p(b.data(), static_cast<uint32_t>(b.size()), id);
  p.materialize();
  return p;
}

using Segment = std::pair<std::vector<uint8_t>, uint32_t>; // (l3 bytes, id)

// A client->server flow: SYN followed by `nseg` data segments carrying
// `payload`, with consecutive sequence numbers. Segments are in wire order and
// ids run from `first_id`.
inline std::vector<Segment> flow(const std::vector<uint8_t> &payload,
                                 uint16_t sport, std::size_t nseg,
                                 uint32_t first_id = 1) {
  std::vector<Segment> segs;
  const uint32_t isn = 1000;
  uint32_t id = first_id;
  segs.push_back(
      {build_l3("10.0.0.1", "1.2.3.4", sport, 443, isn, SYN, nullptr, 0), id++});

  uint32_t seq = isn + 1;
  std::size_t off = 0;
  const std::size_t chunk =
      nseg == 0 ? payload.size() : (payload.size() + nseg - 1) / nseg;
  while (off < payload.size()) {
    const std::size_t n = std::min(chunk, payload.size() - off);
    segs.push_back({build_l3("10.0.0.1", "1.2.3.4", sport, 443, seq, PSH | ACK,
                             payload.data() + off, n),
                    id++});
    off += n;
    seq += n;
  }
  return segs;
}

} // namespace testpkt
