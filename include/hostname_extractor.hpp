#pragma once

#include "packet.hpp"
#include "verdict_sink.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <pcapplusplus/TcpReassembly.h>

// Abstract interface: consumes a stream of L3 packets (all belonging to one
// worker's flows) and verdicts every one of them, holding back only those it
// needs to inspect until the flow's hostname is known.
//
// Concrete extractors pick their own protocol but share this shape:
//   * TcpTlsHostnameExtractor -- TLS SNI over TCP (implemented here)
//   * QuicTlsHostnameExtractor / UdpDnsHostnameExtractor -- later
class HostnameExtractor {
public:
  // Policy: given the hostname a flow resolved to (or none), what happens to
  // it? Runs on the worker thread. Kept out of the extractor so the blocklist
  // lookup stays the caller's business and the extractor only does mechanism --
  // but the extractor needs the answer, because a BLOCK must be remembered for
  // the rest of the connection.
  using Decide =
      std::function<Verdict(const std::optional<std::string> &hostname)>;

  virtual ~HostnameExtractor();

  // Feed one L3 packet. Taken by value: the extractor moves it into its
  // per-flow state until the flow is decided, so pass an owning Packet (see
  // Packet::materialize()). Every packet is either verdicted before this
  // returns or held and verdicted when its flow resolves.
  virtual void feed(Packet pkt) = 0;

  // Expire idle flows. Must be called periodically even when no packets arrive,
  // or a worker that goes quiet will sit on held packets forever.
  virtual void tick(std::chrono::steady_clock::time_point now) = 0;

  // Resolve every tracked flow now, allowing whatever is still held. For
  // shutdown: anything left unverdicted hangs its connection.
  virtual void flush() = 0;
};

// TLS-over-TCP hostname extractor.
//
// Per flow it keeps one of two states, and the absence of an entry is itself
// meaningful:
//
//   (no entry)  Nothing known. A client->server SYN starts tracking, as does a
//               payload that opens a TLS handshake record (the fallback for a
//               connection already running when we attached); anything else is
//               allowed immediately. Flows that resolve to ALLOW are erased and
//               fall back here, so the bulk of traffic -- everything on an
//               established connection -- costs one failed hash lookup.
//   Wait        Undecided. Packets go to the reassembler; those carrying
//               payload are held until the hostname is known.
//   Block       Decided against. Packets are dropped without reassembly.
//
// NOT thread-safe: one thread drives one instance, and the Decide/VerdictSink
// callbacks run inline on that thread and must not re-enter feed().
class TcpTlsHostnameExtractor : public HostnameExtractor {
public:
  // Ceiling on concurrently tracked flows. Without it, connections that each
  // send a partial ClientHello are an unbounded memory sink.
  static constexpr std::size_t kDefaultMaxFlows = 65536;

  // Ceiling on the *decided-against* share of that budget, as a divisor of
  // max_flows: a quarter by default.
  //
  // Block entries and Wait entries compete for one table, and only Wait
  // entries carry correctness -- failing to create one means a hostname goes
  // unchecked. Blocked flows are also the ones that never end: they are
  // black-holed, so the client retransmits forever and nothing ever arrives to
  // close them. Left to compete freely they win on volume and starve out the
  // flows that matter, which is a hostname blocker being switched off by
  // sending it traffic to block. Bounding them separately is what stops that.
  static constexpr std::size_t kDefaultBlockedShare = 4;

  // `sink` must outlive the extractor. `max_blocked` of 0 derives the blocked
  // ceiling from max_flows, which is what keeps the two in step when only one
  // is configured.
  TcpTlsHostnameExtractor(Decide decide, VerdictSink &sink,
                          std::size_t max_flows = kDefaultMaxFlows,
                          std::size_t max_blocked = 0);

  void feed(Packet pkt) override;
  void tick(std::chrono::steady_clock::time_point now) override;
  void flush() override;

  // --- counters -------------------------------------------------------------
  // Published as atomics so a monitoring thread can read them while the worker
  // runs; the extractor itself is otherwise single-threaded. Updated once per
  // feed()/sweep(), never per lookup.

  // Flows currently tracked (Wait + Block).
  std::size_t tracked_flows() const noexcept {
    return _flows.load(std::memory_order_relaxed);
  }
  // Flows we declined to track because the table was full. Nonzero means the
  // cap is being hit and hostnames are going unchecked.
  std::uint64_t flows_dropped_at_cap() const noexcept {
    return _dropped_at_cap.load(std::memory_order_relaxed);
  }
  // Flows currently in Block state. Expected to sit at the blocked ceiling
  // under sustained blocking; that is the bound working, not a problem.
  std::size_t blocked_flows() const noexcept {
    return _blocked.load(std::memory_order_relaxed);
  }

private:
  enum class State : uint8_t { Wait, Block };

  struct Conn {
    State state = State::Wait;
    std::vector<Packet> held;    // payload packets awaiting the decision
    std::vector<uint8_t> stream; // reassembled client->server bytes
    // PcapPlusPlus's own key for this connection, kept as an opaque token so we
    // can hand it back to closeConnection(). Never computed or compared by us.
    uint32_t pcpp_key = 0;
    bool pcpp_closed = false; // pcpp already ended it; don't close it again
    std::chrono::steady_clock::time_point last;
  };

  // pcpp callbacks -- C function pointers, cookie == this.
  static void onMessageReady(int8_t side, const pcpp::TcpStreamData &data,
                             void *cookie);
  static void onConnectionEnd(const pcpp::ConnectionData &conn,
                              pcpp::TcpReassembly::ConnectionEndReason reason,
                              void *cookie);

  // Decide `key`'s flow, verdict everything held for it, and either drop the
  // entry (ALLOW) or turn it into a Block entry.
  void resolve(uint32_t key, std::optional<std::string> hostname);
  void sweep(std::chrono::steady_clock::time_point now);
  void sink_one(Packet &&pkt, Verdict v);

  // Record `key` as blocked, evicting the oldest blocked flow if the ring is
  // full. One eviction per registration, always: there is no threshold to
  // cross and no batch to pay for, so the cost is the same saturated or idle.
  void remember_blocked(uint32_t key);
  // Drop the oldest blocked flow. Returns false when there is none to drop.
  bool evict_oldest_blocked();

  // Deferred closeConnection() tokens. Calling into pcpp while we are inside
  // reassemblePacket() would mutate its connection map from under it, so
  // closes are collected and drained at a safe point.
  void drain_closes();

  // Republish the table size for readers on other threads.
  void publish() noexcept {
    _flows.store(_conns.size(), std::memory_order_relaxed);
  }

  Decide _decide;
  VerdictSink &_sink;
  pcpp::TcpReassembly _reassembly;
  std::vector<uint32_t> _to_close;
  std::unordered_map<uint32_t, Conn> _conns;

  // Which flow's packet is currently inside reassemblePacket(). Every pcpp
  // callback we can receive fires synchronously from a call we make, so this is
  // all the correlation we need -- pcpp's own connection identity is never used
  // to find our state.
  uint32_t _current_key = 0;
  bool _feeding = false;

  std::size_t _max_flows;

  // Blocked flows, oldest-first, as a fixed ring of keys. Sized once at
  // construction and never resized, so it costs one allocation and a constant
  // footprint -- 4 bytes per slot, 64 KiB at the default.
  //
  // std::vector rather than std::array because max_flows is a constructor
  // argument, not a compile-time constant: the unit tests build extractors
  // with tiny caps to exercise the full-table path, and a fixed-size ring
  // would be larger than the whole table there.
  //
  // Holds keys only. Nothing is ever looked up through it -- it decides who
  // leaves, never who is present.
  std::size_t _max_blocked;
  std::vector<uint32_t> _block_ring;
  std::size_t _block_next = 0; // slot to overwrite, i.e. the oldest

  std::chrono::steady_clock::time_point _lastSweep{};
  std::atomic<std::size_t> _flows{0};
  std::atomic<std::size_t> _blocked{0};
  std::atomic<std::uint64_t> _dropped_at_cap{0};
};
