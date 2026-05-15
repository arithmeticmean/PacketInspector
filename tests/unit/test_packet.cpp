#include "packet.hpp"
#include "packet_builders.hpp"

#include <algorithm>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

using namespace testpkt;

namespace {
Packet view(const std::vector<uint8_t> &b, uint32_t id = 0) {
  return Packet(b.data(), static_cast<uint32_t>(b.size()), id);
}
} // namespace

TEST(FlowView, DissectsTcpAndLocatesThePayload) {
  const auto ch = client_hello("example.org");
  const auto seg = build_l3("10.0.0.1", "93.184.216.34", 50000, 443, 1000,
                            PSH | ACK, ch.data(), ch.size());
  FlowView f;
  ASSERT_TRUE(view(seg).flow_view(f));
  EXPECT_EQ(f.ip_version, 4);
  EXPECT_EQ(f.ip_proto, 6);
  EXPECT_EQ(f.src_port, 50000);
  EXPECT_EQ(f.dst_port, 443);
  EXPECT_NE(f.key, 0u);

  // The payload must point at the TLS record, not at the TCP header -- the
  // extractor's gate reads exactly these two bytes.
  ASSERT_EQ(f.payload_len, ch.size());
  ASSERT_NE(f.payload, nullptr);
  EXPECT_EQ(f.payload[0], 0x16);
  EXPECT_EQ(f.payload[1], 0x03);
}

TEST(FlowView, ReportsTcpFlags) {
  FlowView f;
  const auto syn = build_l3("10.0.0.1", "1.2.3.4", 5000, 443, 1, SYN, nullptr, 0);
  ASSERT_TRUE(view(syn).flow_view(f));
  EXPECT_EQ(f.tcp_flags & 0x02, 0x02); // SYN
  EXPECT_EQ(f.tcp_flags & 0x10, 0x00); // ACK clear -> client's opening SYN
  EXPECT_EQ(f.payload_len, 0u);

  const auto synack =
      build_l3("1.2.3.4", "10.0.0.1", 443, 5000, 1, SYN | ACK, nullptr, 0);
  ASSERT_TRUE(view(synack).flow_view(f));
  EXPECT_EQ(f.tcp_flags & 0x12, 0x12); // SYN+ACK -> the server's reply
}

TEST(FlowView, RejectsEmptyAndGarbage) {
  FlowView f;
  EXPECT_FALSE(Packet().flow_view(f));
  const uint8_t junk[] = {0x45, 0x00, 0x02, 0xff}; // starts like IPv4 but bogus
  EXPECT_FALSE(Packet(junk, sizeof(junk), 0).flow_view(f));
}

// Both directions of a connection must land on the same worker and the same
// cache entry, so the key cannot depend on which side sent the packet.
TEST(FlowView, KeyIsDirectionInsensitive) {
  const auto c2s = build_l3("10.0.0.1", "1.2.3.4", 5000, 443, 1, SYN, nullptr, 0);
  const auto s2c =
      build_l3("1.2.3.4", "10.0.0.1", 443, 5000, 1, SYN | ACK, nullptr, 0);
  EXPECT_EQ(view(c2s).flow_key(), view(s2c).flow_key());
}

TEST(PacketFlowKey, StableForFlowDistinctForOthers) {
  const auto ch = client_hello("a.com");
  // Same 5-tuple, different seq -> same routing key.
  const auto a = build_l3("10.0.0.1", "1.2.3.4", 1111, 443, 1, PSH | ACK,
                          ch.data(), ch.size());
  const auto b = build_l3("10.0.0.1", "1.2.3.4", 1111, 443, 999, PSH | ACK,
                          ch.data(), ch.size());
  // Different source port -> different key.
  const auto c = build_l3("10.0.0.1", "1.2.3.4", 2222, 443, 1, PSH | ACK,
                          ch.data(), ch.size());
  EXPECT_EQ(view(a).flow_key(), view(b).flow_key());
  EXPECT_NE(view(a).flow_key(), view(c).flow_key());
}

// --- view -> owned -> shell ------------------------------------------------

TEST(PacketBytes, MaterializeSurvivesSourceDestruction) {
  const auto ch = client_hello("owned.example.com");
  auto seg = build_l3("10.0.0.1", "1.2.3.4", 1234, 443, 1, PSH | ACK, ch.data(),
                      ch.size());
  Packet p = view(seg, 42);
  ASSERT_TRUE(p.is_view());
  p.materialize();
  EXPECT_FALSE(p.is_view());

  // Wipe and release the source bytes; the owning packet must be unaffected.
  std::fill(seg.begin(), seg.end(), uint8_t{0});
  seg.clear();
  seg.shrink_to_fit();

  // The copy still dissects, and its payload still reads as a TLS record.
  FlowView f;
  ASSERT_TRUE(p.flow_view(f));
  EXPECT_EQ(f.dst_port, 443);
  ASSERT_GE(f.payload_len, 2u);
  EXPECT_EQ(f.payload[0], 0x16);
  EXPECT_EQ(f.payload[1], 0x03);
  EXPECT_EQ(p.id(), 42u);
}

TEST(PacketBytes, MaterializeIsIdempotent) {
  const auto ch = client_hello("idem.example.com");
  const auto seg = build_l3("10.0.0.1", "1.2.3.4", 1234, 443, 1, PSH | ACK,
                            ch.data(), ch.size());
  Packet p = view(seg, 7);
  p.materialize();
  const uint8_t *first = p.data();
  p.materialize(); // second call must not reallocate or re-copy
  EXPECT_EQ(p.data(), first);
  EXPECT_EQ(p.id(), 7u);
}

TEST(PacketBytes, ReleaseBytesLeavesAShell) {
  const auto ch = client_hello("shell.example.com");
  const auto seg = build_l3("10.0.0.1", "1.2.3.4", 1234, 443, 1, PSH | ACK,
                            ch.data(), ch.size());
  Packet p = view(seg, 99);
  p.materialize();
  const uint32_t len = p.len();

  p.release_bytes();
  EXPECT_FALSE(p.has_bytes());
  EXPECT_EQ(p.data(), nullptr);
  EXPECT_EQ(p.id(), 99u);   // the shell still carries what the verdict needs
  EXPECT_EQ(p.len(), len);  // and still reports the original size
  EXPECT_TRUE(p.pending_verdict());
}

TEST(PacketBytes, MaterializeOnShellIsANoOp) {
  Packet p(nullptr, 0, 5);
  p.materialize();
  EXPECT_FALSE(p.has_bytes());
  EXPECT_EQ(p.id(), 5u);
}

// --- verdict / pending bookkeeping -----------------------------------------

TEST(PacketVerdict, DefaultsToAllowSoForgottenPathsFailOpen) {
  const auto seg = build_l3("10.0.0.1", "1.2.3.4", 1234, 443, 1, SYN, nullptr, 0);
  const Packet p = view(seg, 1);
  EXPECT_EQ(p.verdict(), Verdict::ALLOW);
}

TEST(PacketVerdict, ArrivingPacketIsPendingAndDefaultIsNot) {
  const auto seg = build_l3("10.0.0.1", "1.2.3.4", 1234, 443, 1, SYN, nullptr, 0);
  EXPECT_TRUE(view(seg, 1).pending_verdict());
  EXPECT_FALSE(Packet().pending_verdict()); // nothing to verdict
}

TEST(PacketMove, LeavesSourceInert) {
  const auto ch = client_hello("move.example.com");
  const auto seg = build_l3("10.0.0.1", "1.2.3.4", 1234, 443, 1, PSH | ACK,
                            ch.data(), ch.size());
  Packet src = view(seg, 77);
  src.materialize();

  Packet dst = std::move(src);
  EXPECT_EQ(dst.id(), 77u);
  EXPECT_TRUE(dst.has_bytes());
  EXPECT_TRUE(dst.pending_verdict());

  // The husk must not look like a submittable shell, or it would double-verdict
  // id 77 the moment anything handed it to the queue.
  EXPECT_FALSE(src.pending_verdict()); // NOLINT(bugprone-use-after-move)
  EXPECT_FALSE(src.has_bytes());
  EXPECT_EQ(src.id(), 0u);
  EXPECT_EQ(src.len(), 0u);
}
