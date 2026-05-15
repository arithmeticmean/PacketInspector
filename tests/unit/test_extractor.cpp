#include "harness.hpp"
#include "hostname_extractor.hpp"

#include <algorithm>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using namespace testpkt;

namespace {

using clock_t_ = std::chrono::steady_clock;

// An extractor wired to a recording sink, with a Decide that blocks whatever is
// in `blocked`. Everything the extractor was asked about lands in `asked`.
struct Ext {
  FakeSink sink;
  std::set<std::string> blocked;
  std::vector<std::optional<std::string>> asked;
  TcpTlsHostnameExtractor ext;

  explicit Ext(std::size_t max_flows = TcpTlsHostnameExtractor::kDefaultMaxFlows)
      : ext(
            [this](const std::optional<std::string> &h) {
              asked.push_back(h);
              return (h && blocked.count(*h) != 0) ? Verdict::BLOCK
                                                   : Verdict::ALLOW;
            },
            sink, max_flows) {}

  void feed(const std::vector<uint8_t> &bytes, uint32_t id) {
    ext.feed(owned(bytes, id));
  }
  void feed_all(const std::vector<Segment> &segs) {
    for (const auto &[bytes, id] : segs)
      feed(bytes, id);
  }

  // The hostname of the first flow that resolved, if any.
  std::optional<std::string> first_host() const {
    return asked.empty() ? std::nullopt : asked.front();
  }
};

} // namespace

// --- hostname extraction ---------------------------------------------------

TEST(Extractor, SingleSegmentClientHello) {
  Ext e;
  e.feed_all(flow(client_hello("single.example.com"), 40000, 1));
  ASSERT_EQ(e.asked.size(), 1u);
  ASSERT_TRUE(e.first_host().has_value());
  EXPECT_EQ(*e.first_host(), "single.example.com");
}

TEST(Extractor, ClientHelloWithoutSyn) {
  // The receive thread routes everything, but a flow can still start mid-stream
  // if we attached after it opened. The verdict must fire on the ClientHello
  // itself, not wait for the idle sweep.
  Ext e;
  const auto ch = client_hello("nosyn.example.com");
  e.feed(build_l3("10.0.0.1", "1.2.3.4", 40010, 443, 1001, PSH | ACK, ch.data(),
                  ch.size()),
         1);
  ASSERT_EQ(e.asked.size(), 1u);
  ASSERT_TRUE(e.first_host().has_value());
  EXPECT_EQ(*e.first_host(), "nosyn.example.com");
}

TEST(Extractor, MultiSegmentReassembly) {
  Ext e;
  e.feed_all(flow(client_hello("split.example.com"), 40001, 4));
  ASSERT_TRUE(e.first_host().has_value());
  EXPECT_EQ(*e.first_host(), "split.example.com");
}

// Once a flow is tracked, later segments are fed regardless of order and the
// reassembler closes the gaps.
TEST(Extractor, OutOfOrderOnceTrackingHasStarted) {
  auto segs = flow(client_hello("reorder.example.com"), 40002, 3);
  ASSERT_EQ(segs.size(), 4u); // SYN + 3 data segments
  // The opening segment still arrives first; swap the two behind it.
  std::swap(segs[2], segs[3]);

  Ext e;
  e.feed_all(segs);
  ASSERT_TRUE(e.first_host().has_value());
  EXPECT_EQ(*e.first_host(), "reorder.example.com");
}

// The case SYN-seeding exists for. The segment that opens the TLS record
// arrives LAST, so nothing before it looks like TLS. Tracking from the SYN means
// the flow is already known by then, and the continuations are held instead of
// being allowed through and lost.
TEST(Gate, OpeningSegmentArrivingLateIsStillCaught) {
  auto segs = flow(client_hello("reorder.example.com"), 40003, 3);
  std::reverse(segs.begin() + 1, segs.end()); // opening segment arrives last

  Ext e;
  e.feed_all(segs);
  ASSERT_TRUE(e.first_host().has_value())
      << "the flow must be tracked from its SYN, not from the opening segment";
  EXPECT_EQ(*e.first_host(), "reorder.example.com");
}

TEST(Gate, ClientSynStartsTracking) {
  Ext e;
  e.feed(build_l3("10.0.0.1", "1.2.3.4", 40103, 443, 1000, SYN, nullptr, 0), 1);
  EXPECT_EQ(e.ext.tracked_flows(), 1u);
  // Tracked, but not held: a SYN carries nothing to inspect, and holding it
  // would stop the connection ever being established.
  EXPECT_EQ(e.sink.verdict_for(1), Verdict::ALLOW);
}

TEST(Gate, ServerSynAckDoesNotStartTracking) {
  Ext e;
  // Server -> client, so SYN and ACK are both set.
  e.feed(build_l3("1.2.3.4", "10.0.0.1", 443, 40104, 7000, SYN | ACK, nullptr, 0),
         1);
  EXPECT_EQ(e.ext.tracked_flows(), 0u);
  EXPECT_EQ(e.sink.verdict_for(1), Verdict::ALLOW);
}

// The FORWARD rule queues both directions, so server->client packets reach the
// extractor too. Their bytes must never reach the buffer we parse as a
// ClientHello -- a ServerHello also opens 0x16 0x03, and mixing it in would make
// the parse fail and let the flow through.
TEST(Gate, ServerToClientDataDoesNotCorruptTheClientStream) {
  Ext e;
  const uint16_t sport = 40105;
  e.feed(build_l3("10.0.0.1", "1.2.3.4", sport, 443, 1000, SYN, nullptr, 0), 1);

  // A ServerHello-shaped record arriving from the server before the client's
  // ClientHello is reassembled.
  const uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x04,
                                  0x02, 0x00, 0x00, 0x00};
  e.feed(build_l3("1.2.3.4", "10.0.0.1", 443, sport, 7000, PSH | ACK,
                  server_hello, sizeof(server_hello)),
         2);

  const auto ch = client_hello("clientside.example.com");
  e.feed(build_l3("10.0.0.1", "1.2.3.4", sport, 443, 1001, PSH | ACK, ch.data(),
                  ch.size()),
         3);

  ASSERT_TRUE(e.first_host().has_value())
      << "server data was mixed into the client stream";
  EXPECT_EQ(*e.first_host(), "clientside.example.com");
}

TEST(Extractor, ClientHelloWithoutSni) {
  Ext e;
  e.feed_all(flow(client_hello(""), 40004, 1)); // no server_name extension
  ASSERT_EQ(e.asked.size(), 1u);
  EXPECT_FALSE(e.first_host().has_value());
}

// --- the gate: what starts tracking a flow ---------------------------------

// The regression test for the original bug. A ClientHello split across segments
// means only the FIRST segment looks like TLS; the continuation is arbitrary
// handshake bytes. Tracking has to be a property of the flow, not of each
// packet, or the continuation is allowed through and the stream never completes.
TEST(Gate, ContinuationOfASplitClientHelloIsNotLost) {
  const auto ch = client_hello("continuation.example.com");
  auto segs = flow(ch, 40100, 3);

  // Precondition: the continuation segments really don't look like TLS on their
  // own, so nothing but flow state could have kept them.
  ASSERT_GE(segs.size(), 3u);
  for (std::size_t i = 2; i < segs.size(); ++i) {
    FlowView f;
    const Packet p = owned(segs[i].first, 0);
    ASSERT_TRUE(p.flow_view(f));
    ASSERT_GE(f.payload_len, 2u);
    EXPECT_FALSE(f.payload[0] == 0x16 && f.payload[1] == 0x03)
        << "segment " << i << " still looks like a handshake opening";
  }

  Ext e;
  e.feed_all(segs);
  ASSERT_TRUE(e.first_host().has_value());
  EXPECT_EQ(*e.first_host(), "continuation.example.com");
}

// Tracking every connection from its SYN is only affordable because a non-TLS
// one is dropped again as soon as its first payload byte rules TLS out. It costs
// one insert and one erase, not a table entry for the connection's lifetime.
TEST(Gate, NonTlsFlowIsForgottenOnItsFirstPayload) {
  const char *http = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  std::vector<uint8_t> payload(http, http + std::strlen(http));
  Ext e;
  e.feed_all(flow(payload, 40004, 1));

  EXPECT_EQ(e.ext.tracked_flows(), 0u) << "must not linger until the timeout";
  ASSERT_EQ(e.asked.size(), 1u);
  EXPECT_FALSE(e.first_host().has_value());
  EXPECT_EQ(e.sink.count(), 2u); // SYN + the data segment, both allowed
  EXPECT_EQ(e.sink.count_with(Verdict::ALLOW), 2u);
}

// A packet with no payload arriving on a flow we ARE tracking must still be
// released immediately -- holding a pure ACK stalls the peer's window for no
// information gain.
TEST(Gate, PayloadlessPacketOnATrackedFlowIsNotHeld) {
  // A ClientHello split so the flow stays undecided after the first segment.
  const auto ch = client_hello("held.example.com");
  const std::vector<uint8_t> firstHalf(ch.begin(), ch.begin() + ch.size() / 2);

  Ext e;
  e.feed(build_l3("10.0.0.1", "1.2.3.4", 40102, 443, 1001, PSH | ACK,
                  firstHalf.data(), firstHalf.size()),
         1);
  ASSERT_EQ(e.ext.tracked_flows(), 1u); // undecided, holding packet 1
  EXPECT_EQ(e.sink.verdict_for(1), std::nullopt);

  // A pure ACK on the same flow.
  e.feed(build_l3("10.0.0.1", "1.2.3.4", 40102, 443, 1500, ACK, nullptr, 0), 2);
  EXPECT_EQ(e.sink.verdict_for(2), Verdict::ALLOW) << "pure ACK must not be held";
  EXPECT_EQ(e.sink.verdict_for(1), std::nullopt) << "payload packet still held";
}

// --- the two states --------------------------------------------------------

TEST(FlowState, BlockedFlowStaysBlockedForLaterPackets) {
  Ext e;
  e.blocked.insert("bad.example.com");
  e.feed_all(flow(client_hello("bad.example.com"), 40200, 2));

  ASSERT_EQ(e.asked.size(), 1u);
  ASSERT_EQ(e.ext.tracked_flows(), 1u) << "a blocked flow must be remembered";

  // More data on the same flow, long after the decision. It must be dropped
  // without asking the policy again.
  e.feed(build_l3("10.0.0.1", "1.2.3.4", 40200, 443, 9000, PSH | ACK,
                  reinterpret_cast<const uint8_t *>("xxxx"), 4),
         99);
  EXPECT_EQ(e.sink.verdict_for(99), Verdict::BLOCK);
  EXPECT_EQ(e.asked.size(), 1u) << "policy must be consulted once per flow";
  EXPECT_EQ(e.sink.double_submits(), 0u);
}

TEST(FlowState, AllowedFlowIsForgottenSoLaterPacketsAreCheap) {
  Ext e;
  e.feed_all(flow(client_hello("good.example.com"), 40201, 2));

  ASSERT_EQ(e.asked.size(), 1u);
  EXPECT_EQ(e.ext.tracked_flows(), 0u) << "an allowed flow leaves no entry";

  e.feed(build_l3("10.0.0.1", "1.2.3.4", 40201, 443, 9000, PSH | ACK,
                  reinterpret_cast<const uint8_t *>("xxxx"), 4),
         99);
  EXPECT_EQ(e.sink.verdict_for(99), Verdict::ALLOW);
  EXPECT_EQ(e.ext.tracked_flows(), 0u);
  EXPECT_EQ(e.asked.size(), 1u);
}

TEST(FlowState, EveryPacketOfABlockedFlowIsVerdicted) {
  Ext e;
  e.blocked.insert("bad.example.com");
  const auto segs = flow(client_hello("bad.example.com"), 40202, 3);
  e.feed_all(segs);

  for (const auto &[bytes, id] : segs) {
    (void)bytes;
    EXPECT_TRUE(e.sink.verdict_for(id).has_value())
        << "packet " << id << " never got a verdict";
  }
  // The SYN carries no payload, so it is released on arrival; the data segments
  // are held and dropped together.
  EXPECT_EQ(e.sink.verdict_for(segs.front().second), Verdict::ALLOW);
  EXPECT_EQ(e.sink.count_with(Verdict::BLOCK), segs.size() - 1);
  EXPECT_EQ(e.sink.double_submits(), 0u);
}

// --- reaping ---------------------------------------------------------------

TEST(Reaping, StalledFlowIsReleasedAfterTheIdleTimeout) {
  const auto ch = client_hello("stalled.example.com");
  const std::vector<uint8_t> firstHalf(ch.begin(), ch.begin() + ch.size() / 2);

  Ext e;
  e.feed(build_l3("10.0.0.1", "1.2.3.4", 40300, 443, 1001, PSH | ACK,
                  firstHalf.data(), firstHalf.size()),
         1);
  ASSERT_EQ(e.ext.tracked_flows(), 1u);
  ASSERT_EQ(e.sink.verdict_for(1), std::nullopt); // held, undecided

  e.ext.tick(clock_t_::now() + std::chrono::seconds(11));

  EXPECT_EQ(e.ext.tracked_flows(), 0u);
  EXPECT_EQ(e.sink.verdict_for(1), Verdict::ALLOW)
      << "a stalled flow must fail open, not hold its packets forever";
}

// Nothing else can remove a Block entry: every packet of the flow is dropped, so
// no FIN or RST ever reaches us.
TEST(Reaping, BlockEntryExpires) {
  Ext e;
  e.blocked.insert("bad.example.com");
  e.feed_all(flow(client_hello("bad.example.com"), 40301, 1));
  ASSERT_EQ(e.ext.tracked_flows(), 1u);

  e.ext.tick(clock_t_::now() + std::chrono::seconds(30));
  EXPECT_EQ(e.ext.tracked_flows(), 1u) << "block must outlive the Wait timeout";

  e.ext.tick(clock_t_::now() + std::chrono::seconds(61));
  EXPECT_EQ(e.ext.tracked_flows(), 0u);
}

TEST(Reaping, FlushReleasesEverythingStillHeld) {
  const auto ch = client_hello("shutdown.example.com");
  const std::vector<uint8_t> firstHalf(ch.begin(), ch.begin() + ch.size() / 2);

  Ext e;
  e.feed(build_l3("10.0.0.1", "1.2.3.4", 40302, 443, 1001, PSH | ACK,
                  firstHalf.data(), firstHalf.size()),
         1);
  ASSERT_EQ(e.sink.verdict_for(1), std::nullopt);

  e.ext.flush();
  EXPECT_EQ(e.sink.verdict_for(1), Verdict::ALLOW);
  EXPECT_EQ(e.ext.tracked_flows(), 0u);
}

TEST(Reaping, FlowsAreNotTrackedPastTheCap) {
  Ext e(2); // room for two flows
  const auto ch = client_hello("capped.example.com");
  const std::vector<uint8_t> firstHalf(ch.begin(), ch.begin() + ch.size() / 2);

  uint32_t id = 1;
  for (uint16_t sport = 41000; sport < 41010; ++sport)
    e.feed(build_l3("10.0.0.1", "1.2.3.4", sport, 443, 1001, PSH | ACK,
                    firstHalf.data(), firstHalf.size()),
           id++);

  EXPECT_LE(e.ext.tracked_flows(), 2u);
  EXPECT_GT(e.ext.flows_dropped_at_cap(), 0u);
  // Whatever we refused to track must still have been allowed through.
  EXPECT_GT(e.sink.count_with(Verdict::ALLOW), 0u);
  EXPECT_EQ(e.sink.double_submits(), 0u);
}
