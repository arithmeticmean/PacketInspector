// Tests for TcpTlsHostnameExtractor.
//
// Every test drives the real extractor over real crafted IPv4/TCP packets and
// reads its decided() buffer -- there is nothing stubbed out, because the
// extractor's only output is a vector.
//
// The two invariants underneath all of these:
//
//   1. EVERY packet fed in is eventually decided. A packet that is never
//      decided holds a kernel queue slot for the life of the process and hangs
//      its connection, so "how many came out" is checked as carefully as "what
//      verdict did they get".
//   2. When in doubt, ALLOW. Every bail-out path below fails open. A hostname
//      blocker that starts dropping traffic it could not parse is worse than
//      one that misses a flow.

#include "hostname_extractor.hpp"
#include "packet_builders.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <string>
#include <vector>

using namespace testpkt;
using namespace std::chrono_literals;

namespace {

// Collects what the extractor decided, and checks the ownership contract while
// doing it: a packet must arrive still owing a verdict, and must arrive once.
struct Sink {
  std::vector<std::pair<uint32_t, Verdict>> seen;
  std::size_t not_pending = 0; // already decided when it reached us: a bug
  std::size_t duplicates = 0;  // decided twice: would double-verdict an id

  // Drain whatever the extractor has produced since the last call. This is
  // exactly what Worker::drain_decided() does in production.
  void drain(TcpTlsHostnameExtractor &x) {
    for (Decided &d : x.decided()) {
      if (!d.pkt.pending_verdict()) {
        ++not_pending;
        continue;
      }
      for (const auto &[id, v] : seen)
        if (id == d.pkt.id())
          ++duplicates;
      seen.emplace_back(d.pkt.id(), d.verdict);
      d.pkt.clear_pending();
    }
    x.decided().clear();
  }

  std::size_t count() const { return seen.size(); }

  std::optional<Verdict> verdict_for(uint32_t id) const {
    for (const auto &[got_id, v] : seen)
      if (got_id == id)
        return v;
    return std::nullopt;
  }

  std::size_t count_with(Verdict want) const {
    std::size_t n = 0;
    for (const auto &[id, v] : seen)
      if (v == want)
        ++n;
    return n;
  }
};

// An owning packet, as a worker would hand over after materializing it.
Packet owned(const std::vector<uint8_t> &bytes, uint32_t id) {
  Packet p(bytes.data(), static_cast<uint32_t>(bytes.size()), id);
  p.materialize();
  return p;
}

// Policy: block exactly one hostname, and record every hostname we were asked
// about so a test can assert what the extractor actually parsed out.
struct Policy {
  std::string blocked;
  std::vector<std::optional<std::string>> asked;

  HostnameExtractor::Decide fn() {
    return [this](const std::optional<std::string> &h) -> Verdict {
      asked.push_back(h);
      return (h && *h == blocked) ? Verdict::BLOCK : Verdict::ALLOW;
    };
  }
};

constexpr const char *kClient = "10.0.0.1";
constexpr const char *kServer = "1.2.3.4";

// A client SYN: what normally starts a flow being tracked.
std::vector<uint8_t> syn(uint16_t sport, uint32_t seq = 1000) {
  return build_l3(kClient, kServer, sport, 443, seq, SYN, nullptr, 0);
}

// One client->server data segment.
std::vector<uint8_t> seg(uint16_t sport, uint32_t seq, const uint8_t *data,
                         std::size_t len) {
  return build_l3(kClient, kServer, sport, 443, seq, PSH | ACK, data, len);
}

std::vector<uint8_t> seg(uint16_t sport, uint32_t seq,
                         const std::vector<uint8_t> &data) {
  return seg(sport, seq, data.data(), data.size());
}

} // namespace

// ===========================================================================
// The happy paths: does it find the hostname at all?
// ===========================================================================

TEST(Extractor, BlocksAHostnameOnTheList) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello("blocked.example.com");
  const auto s = syn(40000);
  const auto d = seg(40000, 1001, hello);

  x.feed(owned(s, 1));
  x.feed(owned(d, 2));
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u);
  ASSERT_TRUE(pol.asked[0].has_value());
  EXPECT_EQ(*pol.asked[0], "blocked.example.com");

  // Both packets come back, and both are dropped: the SYN too, because the
  // whole connection is black-holed once the flow is decided against.
  EXPECT_EQ(sink.count(), 2u);
  EXPECT_EQ(sink.verdict_for(2), Verdict::BLOCK);
  EXPECT_EQ(sink.duplicates, 0u);
  EXPECT_EQ(sink.not_pending, 0u);
}

TEST(Extractor, AllowsAHostnameNotOnTheList) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello("allowed.example.com");
  x.feed(owned(syn(40001), 1));
  x.feed(owned(seg(40001, 1001, hello), 2));
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u);
  EXPECT_EQ(*pol.asked[0], "allowed.example.com");
  EXPECT_EQ(sink.count(), 2u);
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 2u);
}

TEST(Extractor, FindsAHostnameSplitAcrossSegments) {
  // The case the whole reassembler exists for: a ClientHello that does not fit
  // in one segment. Post-quantum key shares have made this the common case.
  Policy pol{"split.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello("split.example.com");
  ASSERT_GT(hello.size(), 20u);

  x.feed(owned(syn(40002), 1));
  uint32_t id = 2, seq = 1001;
  for (std::size_t off = 0; off < hello.size(); off += 7) {
    const std::size_t n = std::min<std::size_t>(7, hello.size() - off);
    x.feed(owned(seg(40002, seq, hello.data() + off, n), id++));
    seq += n;
  }
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u);
  EXPECT_EQ(*pol.asked[0], "split.example.com");
  EXPECT_EQ(sink.count(), id - 1) << "every packet fed must come back";
  // The SYN carried no payload, so it was allowed the moment it arrived --
  // before the hostname was known. Only the data segments are dropped. See
  // AllowsTheSynOfAFlowItLaterBlocks for why that is harmless.
  EXPECT_EQ(sink.verdict_for(1), Verdict::ALLOW);
  EXPECT_EQ(sink.count_with(Verdict::BLOCK), id - 2);
}

TEST(Extractor, FindsAHostnameWhenSegmentsArriveOutOfOrder) {
  // Same ClientHello, second half delivered first. pcpp buffers the
  // out-of-order fragment and releases it once the gap is filled.
  Policy pol{"reorder.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello("reorder.example.com");
  const std::size_t half = hello.size() / 2;

  x.feed(owned(syn(40003), 1));
  x.feed(owned(seg(40003, 1001 + half, hello.data() + half,
                   hello.size() - half),
               2));                                       // later half first
  x.feed(owned(seg(40003, 1001, hello.data(), half), 3)); // then the gap
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u);
  EXPECT_EQ(*pol.asked[0], "reorder.example.com");
  EXPECT_EQ(sink.count(), 3u);
  EXPECT_EQ(sink.count_with(Verdict::BLOCK), 2u) << "both data segments";
  EXPECT_EQ(sink.verdict_for(1), Verdict::ALLOW) << "the SYN went through";
}

TEST(Extractor, PicksUpAFlowWithNoSynFromTheRecordItself) {
  // A connection already in progress when we attached: no SYN was ever seen, so
  // tracking has to start from a payload that opens a TLS handshake record.
  Policy pol{"midstream.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello("midstream.example.com");
  x.feed(owned(seg(40004, 5000, hello), 1)); // no SYN at all
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u);
  EXPECT_EQ(*pol.asked[0], "midstream.example.com");
  EXPECT_EQ(sink.verdict_for(1), Verdict::BLOCK);
}

TEST(Extractor, RemembersTheDecisionForTheRestOfTheConnection) {
  // Once a flow is blocked, later packets are dropped on arrival without going
  // near the reassembler -- and the policy is not consulted again.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello("blocked.example.com");
  x.feed(owned(syn(40005), 1));
  x.feed(owned(seg(40005, 1001, hello), 2));
  sink.drain(x);
  ASSERT_EQ(pol.asked.size(), 1u);

  const std::vector<uint8_t> more{'x', 'y', 'z'};
  for (uint32_t i = 0; i < 5; ++i)
    x.feed(owned(seg(40005, 1001 + hello.size() + i * 3, more), 10 + i));
  sink.drain(x);

  EXPECT_EQ(pol.asked.size(), 1u) << "policy re-consulted on a decided flow";
  for (uint32_t i = 0; i < 5; ++i)
    EXPECT_EQ(sink.verdict_for(10 + i), Verdict::BLOCK);
}

// ===========================================================================
// Traffic that is none of our business. All of it must pass straight through.
// ===========================================================================

TEST(Extractor, AllowsNonTlsPayload) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const std::vector<uint8_t> http{'G', 'E', 'T', ' ', '/', '\r', '\n'};
  x.feed(owned(syn(40010), 1));
  x.feed(owned(seg(40010, 1001, http), 2));
  sink.drain(x);

  EXPECT_EQ(sink.count(), 2u);
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 2u);
}

TEST(Extractor, AllowsAPureAckWithoutTrackingIt) {
  // The bulk of real traffic. A bare ACK on an untracked flow teaches us
  // nothing, and must not cost a reassembler entry.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  x.feed(owned(build_l3(kClient, kServer, 40011, 443, 9000, ACK, nullptr, 0),
               1));
  sink.drain(x);

  EXPECT_EQ(sink.verdict_for(1), Verdict::ALLOW);
  EXPECT_EQ(x.tracked_flows(), 0u);
}

TEST(Extractor, AllowsGarbageThatIsNotEvenAPacket) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const std::vector<uint8_t> junk{0xff, 0x00, 0x13, 0x37};
  x.feed(owned(junk, 1));
  x.feed(Packet(nullptr, 0, 2)); // no bytes at all
  sink.drain(x);

  EXPECT_EQ(sink.count(), 2u);
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 2u);
}

TEST(Extractor, AllowsATruncatedClientHelloThatCanNeverComplete) {
  // Record header says one thing, the handshake body says it is not a
  // ClientHello. Definitively not ours -- decided at once, not waited on.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  // A ServerHello (0x02) inside a handshake record.
  std::vector<uint8_t> not_hello{0x16, 0x03, 0x01, 0x00, 0x30,
                                 0x02, 0x00, 0x00, 0x2c};
  not_hello.resize(53, 0xAA);

  x.feed(owned(syn(40012), 1));
  x.feed(owned(seg(40012, 1001, not_hello), 2));
  sink.drain(x);

  EXPECT_EQ(sink.count(), 2u);
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 2u);
}

TEST(Extractor, AllowsAClientHelloWithNoServerNameExtension) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello(""); // builder omits SNI when host is empty
  x.feed(owned(syn(40013), 1));
  x.feed(owned(seg(40013, 1001, hello), 2));
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u);
  EXPECT_FALSE(pol.asked[0].has_value()) << "no SNI must resolve to no hostname";
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 2u);
}

// ===========================================================================
// THE FOUR BAIL-OUTS
//
// Each is a different way a flow can fail to produce a hostname, and each has
// to release the packets it was holding rather than sit on them. All four fail
// open.
// ===========================================================================

// --- Bail 1: the TLS record declares a length past the 2^14 legal maximum ---
//
// Checked inside extractHostname() against the record header, so it resolves
// IMMEDIATELY rather than buffering. A record claiming more than a legal
// TLSPlaintext can hold is not a ClientHello, and no amount of waiting fixes it.
TEST(Extractor, BailsAtOnceOnAnOversizedRecordLength) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  // 0x16 0x03 0x01, then a declared record length of 0xFFFF (> 16384).
  std::vector<uint8_t> bad{0x16, 0x03, 0x01, 0xff, 0xff,
                           0x01, 0x00, 0x00, 0x40};
  bad.resize(80, 0xAA);

  x.feed(owned(syn(40020), 1));
  x.feed(owned(seg(40020, 1001, bad), 2));
  sink.drain(x);

  // Resolved on the spot: nothing is still being held.
  ASSERT_EQ(pol.asked.size(), 1u);
  EXPECT_FALSE(pol.asked[0].has_value());
  EXPECT_EQ(sink.count(), 2u) << "both packets released immediately";
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 2u);
  EXPECT_EQ(x.tracked_flows(), 0u) << "flow erased, not left waiting";
}

TEST(Extractor, BailsAtOnceOnAZeroRecordLength) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  std::vector<uint8_t> bad{0x16, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40};
  bad.resize(80, 0xAA);

  x.feed(owned(syn(40021), 1));
  x.feed(owned(seg(40021, 1001, bad), 2));
  sink.drain(x);

  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 2u);
  EXPECT_EQ(x.tracked_flows(), 0u);
}

// --- Bail 2: the reassembled stream passes kMaxStreamBytes (32 KiB) ---
//
// This is the one that catches a stream which keeps LOOKING like a valid but
// incomplete ClientHello. The parse keeps saying NeedMore, so only a byte
// ceiling ever stops it.
TEST(Extractor, BailsWhenTheStreamGrowsPastTheByteCeiling) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  // A valid ClientHello prefix that promises a body far larger than will ever
  // arrive: record length 16384 (legal), handshake length 0xFFF0 (legal by the
  // parser's own bound). Every parse returns NeedMore.
  std::vector<uint8_t> prefix{0x16, 0x03, 0x01, 0x40, 0x00,
                              0x01, 0x00, 0xff, 0xf0};

  x.feed(owned(syn(40030), 1));
  x.feed(owned(seg(40030, 1001, prefix), 2));
  sink.drain(x);

  // The SYN went straight through; the payload segment is what is being held,
  // because the prefix is a valid-but-incomplete ClientHello.
  EXPECT_EQ(sink.count(), 1u) << "a valid incomplete prefix must be waited on";
  EXPECT_EQ(x.tracked_flows(), 1u);

  // Now pour in filler until the 32 KiB ceiling trips. Use few, large segments
  // so the packet-count bail (32) cannot fire first.
  const std::vector<uint8_t> chunk(4096, 0xAA);
  uint32_t seq = 1001 + static_cast<uint32_t>(prefix.size());
  uint32_t id = 3;
  for (int i = 0; i < 10 && pol.asked.empty(); ++i) {
    x.feed(owned(seg(40030, seq, chunk), id++));
    seq += static_cast<uint32_t>(chunk.size());
    sink.drain(x);
  }

  ASSERT_EQ(pol.asked.size(), 1u) << "byte ceiling never tripped";
  EXPECT_FALSE(pol.asked[0].has_value());
  EXPECT_EQ(sink.count(), id - 1) << "every packet fed must come back";
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), id - 1);
  EXPECT_EQ(sink.duplicates, 0u);
}

// --- Bail 3: the flow holds kMaxPacketsPerConn (32) packets ---
//
// A flow that floods us with many small segments without ever completing a
// ClientHello. Bounds how much memory ONE flow can pin.
TEST(Extractor, BailsWhenAFlowHoldsTooManyPackets) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  // Same never-completing prefix, but delivered one byte at a time so the
  // packet count runs out long before the byte ceiling does.
  std::vector<uint8_t> prefix{0x16, 0x03, 0x01, 0x40, 0x00,
                              0x01, 0x00, 0xff, 0xf0};

  x.feed(owned(syn(40040), 1));
  uint32_t seq = 1001, id = 2;
  for (std::size_t i = 0; i < prefix.size(); ++i) {
    x.feed(owned(seg(40040, seq, &prefix[i], 1), id++));
    ++seq;
  }
  sink.drain(x);
  EXPECT_TRUE(pol.asked.empty()) << "still a valid prefix; keep waiting";

  // Keep dribbling single bytes until the held-packet cap trips.
  const uint8_t filler = 0xAA;
  for (int i = 0; i < 64 && pol.asked.empty(); ++i) {
    x.feed(owned(seg(40040, seq, &filler, 1), id++));
    ++seq;
    sink.drain(x);
  }

  ASSERT_EQ(pol.asked.size(), 1u) << "held-packet cap never tripped";
  EXPECT_FALSE(pol.asked[0].has_value());
  EXPECT_EQ(sink.count(), id - 1) << "every packet fed must come back";
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), id - 1);
  EXPECT_EQ(sink.duplicates, 0u) << "a released packet must not be re-released";
}

// --- Bail 4: the flow goes idle for kWaitIdleTimeout (10 s) ---
//
// A flow that simply stops talking. Nothing else will ever release its held
// packets, because nothing else ever arrives for it.
TEST(Extractor, BailsWhenAWaitingFlowGoesIdle) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  // Half a ClientHello, then silence.
  const auto hello = client_hello("idle.example.com");
  const std::size_t half = hello.size() / 2;

  x.feed(owned(syn(40050), 1));
  x.feed(owned(seg(40050, 1001, hello.data(), half), 2));
  sink.drain(x);

  // Only the SYN is out; the half ClientHello is held.
  EXPECT_EQ(sink.count(), 1u) << "incomplete hello must be held, not released";
  EXPECT_EQ(x.tracked_flows(), 1u);
  EXPECT_TRUE(pol.asked.empty());

  // A sweep before the timeout changes nothing.
  x.tick(std::chrono::steady_clock::now() + 2s);
  sink.drain(x);
  EXPECT_EQ(sink.count(), 1u) << "released early, before the idle timeout";
  EXPECT_EQ(x.tracked_flows(), 1u);

  // Past the 10 s ceiling, the sweep gives up and lets the flow through.
  x.tick(std::chrono::steady_clock::now() + 11s);
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u) << "idle timeout never fired";
  EXPECT_FALSE(pol.asked[0].has_value());
  EXPECT_EQ(sink.count(), 2u) << "both held packets released";
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 2u);
  EXPECT_EQ(x.tracked_flows(), 0u);
}

// ===========================================================================
// Bounds on the flow table itself.
// ===========================================================================

TEST(Extractor, StopsTrackingNewFlowsAtTheCapAndAllowsThem) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn(), /*max_flows=*/4);
  Sink sink;

  // Four flows, each parked mid-ClientHello so none of them ever resolves.
  const auto hello = client_hello("blocked.example.com");
  uint32_t id = 1;
  for (uint16_t i = 0; i < 4; ++i) {
    x.feed(owned(syn(41000 + i), id++));
    x.feed(owned(seg(41000 + i, 1001, hello.data(), 4), id++));
  }
  sink.drain(x);
  EXPECT_EQ(x.tracked_flows(), 4u);
  EXPECT_EQ(x.flows_dropped_at_cap(), 0u);

  // A fifth cannot be tracked, so it goes through unchecked -- which is the
  // honest failure and exactly what the counter is there to surface.
  x.feed(owned(syn(41099), id++));
  x.feed(owned(seg(41099, 1001, hello), id++));
  sink.drain(x);

  EXPECT_GT(x.flows_dropped_at_cap(), 0u) << "cap breach not counted";
  EXPECT_EQ(sink.verdict_for(id - 1), Verdict::ALLOW);
}

TEST(Extractor, BlockedFlowsCannotCrowdOutUndecidedOnes) {
  // The attack this bound exists for: send enough traffic that SHOULD be
  // blocked, and the blocked entries fill the table, so genuinely new flows go
  // untracked and unchecked. Blocked entries get their own small ceiling.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn(), /*max_flows=*/8, /*max_blocked=*/2);
  Sink sink;

  const auto hello = client_hello("blocked.example.com");
  uint32_t id = 1;
  for (uint16_t i = 0; i < 6; ++i) {
    x.feed(owned(syn(42000 + i), id++));
    x.feed(owned(seg(42000 + i, 1001, hello), id++));
    sink.drain(x);
  }

  // Six flows were blocked, but only two are remembered at a time.
  EXPECT_LE(x.tracked_flows(), 2u)
      << "blocked flows are not bounded by max_blocked";
  EXPECT_EQ(sink.count(), id - 1) << "every packet fed must come back";
  EXPECT_EQ(sink.count_with(Verdict::BLOCK), 6u)
      << "the ClientHello of every blocked flow must be dropped";
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 6u) << "the six SYNs";
}

// ===========================================================================
// Shutdown.
// ===========================================================================

TEST(Extractor, FlushReleasesEverythingStillHeld) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello("never.example.com");
  x.feed(owned(syn(43000), 1));
  x.feed(owned(seg(43000, 1001, hello.data(), hello.size() / 2), 2));
  x.feed(owned(syn(43001), 3));
  x.feed(owned(seg(43001, 1001, hello.data(), hello.size() / 2), 4));
  sink.drain(x);
  EXPECT_EQ(sink.count(), 2u) << "only the two SYNs; both hellos still waiting";

  x.flush();
  sink.drain(x);

  EXPECT_EQ(sink.count(), 4u) << "flush must release every held packet";
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 4u);
  EXPECT_EQ(x.tracked_flows(), 0u);
  EXPECT_EQ(sink.duplicates, 0u);
}

TEST(Extractor, KeepsConcurrentFlowsSeparate) {
  // Two flows interleaved packet by packet. Each must get its own verdict,
  // which is only true if their reassembly state never mixes.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto bad = client_hello("blocked.example.com");
  const auto good = client_hello("fine.example.com");

  x.feed(owned(syn(44000), 1));
  x.feed(owned(syn(44001), 2));

  const std::size_t n = std::max(bad.size(), good.size());
  uint32_t id = 3;
  uint32_t seq_bad = 1001, seq_good = 1001;
  for (std::size_t off = 0; off < n; off += 8) {
    if (off < bad.size()) {
      const std::size_t k = std::min<std::size_t>(8, bad.size() - off);
      x.feed(owned(seg(44000, seq_bad, bad.data() + off, k), id++));
      seq_bad += k;
    }
    if (off < good.size()) {
      const std::size_t k = std::min<std::size_t>(8, good.size() - off);
      x.feed(owned(seg(44001, seq_good, good.data() + off, k), id++));
      seq_good += k;
    }
  }
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 2u);
  EXPECT_EQ(sink.count(), id - 1);
  EXPECT_GT(sink.count_with(Verdict::BLOCK), 0u);
  EXPECT_GT(sink.count_with(Verdict::ALLOW), 0u);
  EXPECT_EQ(sink.duplicates, 0u);
  EXPECT_EQ(sink.not_pending, 0u);
}

TEST(Extractor, AOneSidedFinDoesNotReleaseAHeldFlow) {
  // Worth knowing, because it is easy to assume otherwise: PcapPlusPlus only
  // ends a connection on FIN once BOTH sides have sent one. We normally see
  // only the client->server direction (the iptables rule matches --dports
  // 443,8443), so the server's FIN never reaches us and this condition is never
  // met in production.
  //
  // That is not a leak -- the idle sweep is what actually reaps these -- but it
  // does mean the FIN path carries much less weight than it looks like it does.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello("aborted.example.com");
  const std::size_t half = hello.size() / 2;

  x.feed(owned(syn(45000), 1));
  x.feed(owned(seg(45000, 1001, hello.data(), half), 2));
  sink.drain(x);
  EXPECT_EQ(sink.count(), 1u) << "only the SYN; the partial hello is held";

  x.feed(owned(build_l3(kClient, kServer, 45000, 443,
                        1001 + static_cast<uint32_t>(half), FIN | ACK, nullptr,
                        0),
               3));
  sink.drain(x);

  // The FIN itself goes through, but the held packet stays held.
  EXPECT_EQ(sink.count(), 2u) << "one-sided FIN must not end the connection";
  EXPECT_TRUE(pol.asked.empty());
  EXPECT_EQ(x.tracked_flows(), 1u);

  // The idle sweep is the backstop that actually releases it.
  x.tick(std::chrono::steady_clock::now() + 11s);
  sink.drain(x);
  EXPECT_EQ(sink.count(), 3u) << "the idle sweep must release it";
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 3u);
  EXPECT_EQ(x.tracked_flows(), 0u);
}

TEST(Extractor, ARstReleasesAHeldFlowImmediately) {
  // A RST closes the connection unilaterally, so unlike FIN this one does fire
  // on traffic we actually see.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello("reset.example.com");
  const std::size_t half = hello.size() / 2;

  x.feed(owned(syn(45001), 1));
  x.feed(owned(seg(45001, 1001, hello.data(), half), 2));
  sink.drain(x);
  EXPECT_EQ(sink.count(), 1u);

  x.feed(owned(build_l3(kClient, kServer, 45001, 443,
                        1001 + static_cast<uint32_t>(half), RST | ACK, nullptr,
                        0),
               3));
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u) << "RST must end the connection";
  EXPECT_FALSE(pol.asked[0].has_value()) << "no hostname was ever completed";
  EXPECT_EQ(sink.count(), 3u) << "RST must release the held packets";
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 3u);
  EXPECT_EQ(x.tracked_flows(), 0u);
}

TEST(Extractor, AllowsTheSynOfAFlowItLaterBlocks) {
  // Documents a deliberate asymmetry that is otherwise surprising.
  //
  // A SYN carries no payload, so nothing can be known about the flow when it
  // arrives -- and holding it would stall the handshake that has to complete
  // before the ClientHello can even be sent. So it is allowed through, and the
  // connection is killed one packet later at the ClientHello. The client gets a
  // completed handshake and then a black hole, which is what blocking by SNI
  // looks like from the outside no matter how it is implemented.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto hello = client_hello("blocked.example.com");
  x.feed(owned(syn(46000), 1));
  sink.drain(x);
  EXPECT_EQ(sink.verdict_for(1), Verdict::ALLOW)
      << "a SYN cannot be held: nothing is known yet and holding stalls the "
         "handshake";

  x.feed(owned(seg(46000, 1001, hello), 2));
  sink.drain(x);
  EXPECT_EQ(sink.verdict_for(2), Verdict::BLOCK);
}

// ===========================================================================
// Record-layer fragmentation.
//
// TLS has two independent framing layers: records, and the handshake messages
// carried inside them. RFC 8446 s5.1 allows a single handshake message to be
// "fragmented across several records" -- so a ClientHello may legally arrive as
//
//   [rec hdr][first half of ClientHello][rec hdr][second half]
//
// This is NOT the same as TCP segmentation, which the reassembler already
// handles: the extra record header lands in the middle of the byte stream, so
// reassembling the stream perfectly still leaves it there.
// ===========================================================================

namespace {

// Re-frame a one-record ClientHello as two records, splitting the handshake
// message `at` bytes in. Both records are well-formed TLS.
std::vector<uint8_t> split_across_two_records(const std::vector<uint8_t> &one,
                                              std::size_t at) {
  const std::vector<uint8_t> hs(one.begin() + 5, one.end()); // strip record hdr
  const std::size_t n = hs.size();
  std::vector<uint8_t> out;
  auto rec = [&](const uint8_t *p, std::size_t len) {
    out.push_back(0x16);
    out.push_back(0x03);
    out.push_back(0x01);
    out.push_back(static_cast<uint8_t>(len >> 8));
    out.push_back(static_cast<uint8_t>(len));
    out.insert(out.end(), p, p + len);
  };
  rec(hs.data(), at);
  rec(hs.data() + at, n - at);
  return out;
}

} // namespace

TEST(Extractor, BlocksAClientHelloFragmentedAcrossTwoRecords) {
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto one = client_hello("blocked.example.com");
  const auto two = split_across_two_records(one, 20);

  x.feed(owned(syn(47000), 1));
  x.feed(owned(seg(47000, 1001, two), 2));
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u) << "the flow never resolved at all";
  ASSERT_TRUE(pol.asked[0].has_value())
      << "SNI not extracted: the second record's 5-byte header was parsed as "
         "ClientHello body, desynchronising the walk. The flow fails OPEN, so "
         "a client that fragments its ClientHello bypasses the blocklist.";
  EXPECT_EQ(*pol.asked[0], "blocked.example.com");
  EXPECT_EQ(sink.verdict_for(2), Verdict::BLOCK);
}

TEST(Extractor, BlocksAClientHelloSplitAtAPathologicalOffset) {
  // One byte in the first record, everything else in the second. Legal, and the
  // shape an evasion tool would actually pick.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto two = split_across_two_records(client_hello("blocked.example.com"), 1);
  x.feed(owned(syn(47001), 1));
  x.feed(owned(seg(47001, 1001, two), 2));
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u);
  ASSERT_TRUE(pol.asked[0].has_value());
  EXPECT_EQ(*pol.asked[0], "blocked.example.com");
  EXPECT_EQ(sink.verdict_for(2), Verdict::BLOCK);
}

TEST(Extractor, BlocksAFragmentedClientHelloAlsoSplitAcrossTcpSegments) {
  // Both framing layers fragmented at once: record-layer fragmentation AND TCP
  // segmentation, with the segment boundaries deliberately not aligned to the
  // record boundaries.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto two = split_across_two_records(client_hello("blocked.example.com"), 13);
  x.feed(owned(syn(47002), 1));
  uint32_t id = 2, seq = 1001;
  for (std::size_t off = 0; off < two.size(); off += 9) {
    const std::size_t n = std::min<std::size_t>(9, two.size() - off);
    x.feed(owned(seg(47002, seq, two.data() + off, n), id++));
    seq += n;
  }
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u);
  ASSERT_TRUE(pol.asked[0].has_value());
  EXPECT_EQ(*pol.asked[0], "blocked.example.com");
  EXPECT_EQ(sink.count_with(Verdict::BLOCK), id - 2) << "all data segments";
}

TEST(Extractor, WaitsForTheSecondRecordRatherThanGuessing) {
  // Only the first record has arrived. The handshake message is incomplete, so
  // the flow must be held -- not resolved as "no hostname", which would let a
  // blocked flow through on a technicality.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  const auto two = split_across_two_records(client_hello("blocked.example.com"), 20);
  const std::size_t first_record = 5 + 20;

  x.feed(owned(syn(47003), 1));
  x.feed(owned(seg(47003, 1001, two.data(), first_record), 2));
  sink.drain(x);

  EXPECT_TRUE(pol.asked.empty()) << "resolved before the hello was complete";
  EXPECT_EQ(x.tracked_flows(), 1u);
  EXPECT_EQ(sink.count(), 1u) << "only the SYN; the record is still held";

  // The rest arrives and the flow resolves.
  x.feed(owned(seg(47003, 1001 + first_record, two.data() + first_record,
                   two.size() - first_record),
               3));
  sink.drain(x);
  ASSERT_EQ(pol.asked.size(), 1u);
  ASSERT_TRUE(pol.asked[0].has_value());
  EXPECT_EQ(sink.count_with(Verdict::BLOCK), 2u);
}

TEST(Extractor, AllowsANonHandshakeRecordAppearingMidHandshake) {
  // An alert record (0x15) where a handshake continuation was promised. Not a
  // ClientHello we can complete -- decided at once, and fails open.
  Policy pol{"blocked.example.com", {}};
  TcpTlsHostnameExtractor x(pol.fn());
  Sink sink;

  auto two = split_across_two_records(client_hello("blocked.example.com"), 20);
  two[5 + 20] = 0x15; // rewrite the second record's content_type

  x.feed(owned(syn(47004), 1));
  x.feed(owned(seg(47004, 1001, two), 2));
  sink.drain(x);

  ASSERT_EQ(pol.asked.size(), 1u);
  EXPECT_FALSE(pol.asked[0].has_value());
  EXPECT_EQ(sink.count_with(Verdict::ALLOW), 2u);
  EXPECT_EQ(x.tracked_flows(), 0u);
}
