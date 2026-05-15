// End-to-end through a real PacketWorker: packets go in via submit() on the
// producer side, cross the queue to the worker thread, and come back out as
// verdicts on the sink. Exercises the threading, the drain-on-stop path, and the
// invariant that matters most in production -- every packet handed to a worker
// gets exactly one verdict, because one that doesn't holds a kernel queue slot
// forever and hangs its connection.

#include "harness.hpp"
#include "packet_worker.hpp"

#include <cstring>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using namespace testpkt;

namespace {

struct WorkerFixture {
  FakeSink sink;
  std::set<std::string> blocked;
  std::unique_ptr<PacketWorker> worker;

  explicit WorkerFixture(std::set<std::string> block_these = {})
      : blocked(std::move(block_these)) {
    worker = std::make_unique<PacketWorker>(
        0,
        [this](const std::optional<std::string> &h) {
          return (h && blocked.count(*h) != 0) ? Verdict::BLOCK
                                               : Verdict::ALLOW;
        },
        sink);
  }

  void submit_all(const std::vector<Segment> &segs) {
    for (const auto &[bytes, id] : segs)
      worker->submit(owned(bytes, id));
  }

  // Stop the worker; on return every packet has been drained, flushed and
  // verdicted, so the sink can be read without further synchronization.
  void finish() { worker->stop(); }
};

// Every id in `segs` got exactly one verdict.
void expect_all_verdicted(const FakeSink &sink,
                          const std::vector<Segment> &segs) {
  for (const auto &[bytes, id] : segs) {
    (void)bytes;
    EXPECT_TRUE(sink.verdict_for(id).has_value())
        << "packet " << id << " was never verdicted";
  }
  EXPECT_EQ(sink.count(), segs.size());
  EXPECT_EQ(sink.double_submits(), 0u);
}

} // namespace

TEST(Worker, BlocksABlockedHostAndVerdictsEveryPacket) {
  WorkerFixture w({"blocked.example.com"});
  const auto segs = flow(client_hello("blocked.example.com"), 50000, 3);
  w.submit_all(segs);
  w.finish();

  expect_all_verdicted(w.sink, segs);
  // The SYN has no payload, so it is released on arrival; the data segments are
  // held until the hostname resolves, then dropped together.
  EXPECT_EQ(w.sink.verdict_for(segs.front().second), Verdict::ALLOW);
  EXPECT_EQ(w.sink.count_with(Verdict::BLOCK), segs.size() - 1);
}

TEST(Worker, AllowsAnUnblockedHost) {
  WorkerFixture w({"other.example.com"});
  const auto segs = flow(client_hello("fine.example.com"), 50001, 2);
  w.submit_all(segs);
  w.finish();

  expect_all_verdicted(w.sink, segs);
  EXPECT_EQ(w.sink.count_with(Verdict::ALLOW), segs.size());
}

TEST(Worker, SplitClientHelloIsBlockedEndToEnd) {
  // The bug this design exists to fix, driven all the way through a worker:
  // only the first segment looks like TLS, and the rest must still be captured.
  WorkerFixture w({"split.example.com"});
  const auto segs = flow(client_hello("split.example.com"), 50002, 4);
  w.submit_all(segs);
  w.finish();

  expect_all_verdicted(w.sink, segs);
  EXPECT_EQ(w.sink.count_with(Verdict::BLOCK), segs.size() - 1)
      << "every data segment of a blocked flow must be dropped";
}

// The reordered case, end to end: the segment that opens the TLS record arrives
// last, so only tracking from the SYN keeps the earlier ones.
TEST(Worker, ReorderedClientHelloIsBlockedEndToEnd) {
  WorkerFixture w({"reordered.example.com"});
  auto segs = flow(client_hello("reordered.example.com"), 50005, 3);
  std::reverse(segs.begin() + 1, segs.end());
  w.submit_all(segs);
  w.finish();

  expect_all_verdicted(w.sink, segs);
  EXPECT_EQ(w.sink.count_with(Verdict::BLOCK), segs.size() - 1)
      << "reordered segments of a blocked flow must still be dropped";
}

TEST(Worker, AllowsNonTlsTraffic) {
  const char *http = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  std::vector<uint8_t> payload(http, http + std::strlen(http));

  WorkerFixture w;
  const auto segs = flow(payload, 50003, 1);
  w.submit_all(segs);
  w.finish();

  expect_all_verdicted(w.sink, segs);
  EXPECT_EQ(w.sink.count_with(Verdict::ALLOW), segs.size());
}

// A flow that never resolves must not strand its held packets at shutdown.
TEST(Worker, StopVerdictsPacketsHeldByAnUnresolvedFlow) {
  const auto ch = client_hello("never.example.com");
  const std::vector<uint8_t> firstHalf(ch.begin(), ch.begin() + ch.size() / 2);

  WorkerFixture w;
  const std::vector<Segment> segs = {
      {build_l3("10.0.0.1", "1.2.3.4", 50004, 443, 1001, PSH | ACK,
                firstHalf.data(), firstHalf.size()),
       1}};
  w.submit_all(segs);
  w.finish(); // drain + flush

  expect_all_verdicted(w.sink, segs);
  EXPECT_EQ(w.sink.verdict_for(1), Verdict::ALLOW) << "must fail open";
}

// Nothing queued may be discarded by stop(): the loop only exits on an empty
// queue.
TEST(Worker, StopDrainsWhatIsStillQueued) {
  WorkerFixture w({"burst.example.com"});
  std::vector<Segment> all;
  uint32_t id = 1;
  for (uint16_t sport = 50100; sport < 50140; ++sport) {
    auto segs = flow(client_hello("burst.example.com"), sport, 2, id);
    id += static_cast<uint32_t>(segs.size());
    for (auto &s : segs)
      all.push_back(std::move(s));
  }
  w.submit_all(all);
  w.finish();

  expect_all_verdicted(w.sink, all);
}

TEST(Worker, KeepsConcurrentFlowsSeparate) {
  WorkerFixture w({"bad.example.com"});
  auto bad = flow(client_hello("bad.example.com"), 50200, 2, 1);
  auto good = flow(client_hello("good.example.com"), 50201, 2, 100);

  // Interleave the two flows packet by packet.
  std::vector<Segment> all;
  for (std::size_t i = 0; i < std::max(bad.size(), good.size()); ++i) {
    if (i < bad.size())
      all.push_back(bad[i]);
    if (i < good.size())
      all.push_back(good[i]);
  }
  w.submit_all(all);
  w.finish();

  expect_all_verdicted(w.sink, all);
  for (std::size_t i = 1; i < bad.size(); ++i) // skip the SYN
    EXPECT_EQ(w.sink.verdict_for(bad[i].second), Verdict::BLOCK);
  for (const auto &[bytes, gid] : good) {
    (void)bytes;
    EXPECT_EQ(w.sink.verdict_for(gid), Verdict::ALLOW);
  }
}
