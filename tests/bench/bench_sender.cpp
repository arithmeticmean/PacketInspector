// bench sender: offers load as fast as it can for a fixed duration.
//
// Every packet is built ONCE up front and then re-sent from a preallocated
// array, because crafting with pcpp costs far more than sending and would make
// this a benchmark of the packet builder. The only per-send work is stamping
// the current time into the buffer.
//
// It reports what it offered. Whether the inspector kept up is read from the
// router's interface counters by the driver script -- not from here, and not
// from the receiver, both of which can drop under load and would silently
// understate delivery.

#include "bench_common.hpp"

#include <arpa/inet.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/TcpLayer.h>

namespace {

[[noreturn]] void die(const std::string &msg) {
  std::fprintf(stderr, "bench_sender: %s\n", msg.c_str());
  std::exit(1);
}

// How many distinct prebuilt packets to cycle through.
//
// This is a correctness bound for the tls profile, not just a tuning knob. Each
// ring entry is one flow; once the ring wraps, the same ClientHello arrives
// again on the same flow at the same sequence number, which pcpp correctly
// treats as a retransmission and does not re-deliver -- so the packet is held
// until the idle sweep rather than decided. Keep offered_rate * duration below
// this, or the tls numbers measure the replay artifact instead of the inspector.
constexpr std::size_t kRing = 65536;

// Packets handed to pcpp per sendPackets() call. Batching amortizes the send
// path; too large and the first packet of a batch waits on the last.
constexpr std::size_t kBatch = 64;

} // namespace

int main(int argc, char **argv) {
  std::string iface, dst_mac, profile_s = "bulk";
  int seconds = 5;
  int payload_size = 256;
  long target_pps = 0; // 0 = unpaced
  int shard = 0, shards = 1;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&](const char *what) -> std::string {
      if (i + 1 >= argc)
        die(std::string(what) + " needs a value");
      return argv[++i];
    };
    if (a == "--iface") iface = next("--iface");
    else if (a == "--dst-mac") dst_mac = next("--dst-mac");
    else if (a == "--profile") profile_s = next("--profile");
    else if (a == "--seconds") seconds = std::stoi(next("--seconds"));
    else if (a == "--payload") payload_size = std::stoi(next("--payload"));
    else if (a == "--pps") target_pps = std::stol(next("--pps"));
    else if (a == "--shard") shard = std::stoi(next("--shard"));
    else if (a == "--shards") shards = std::stoi(next("--shards"));
    else die("unknown option: " + a);
  }
  if (iface.empty() || dst_mac.empty())
    die("usage: bench_sender --iface <dev> --dst-mac <mac> "
        "[--profile bulk|tls] [--seconds n] [--payload n] [--pps n] "
        "[--shard i --shards n]");

  const bench::Profile profile =
      profile_s == "tls" ? bench::Profile::Tls : bench::Profile::Bulk;

  auto *dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(iface);
  if (dev == nullptr)
    die("no such interface: " + iface);
  if (!dev->open())
    die("cannot open " + iface);

  const pcpp::MacAddress src_mac = dev->getMacAddress();
  const pcpp::MacAddress gw_mac(dst_mac);
  const auto hello = bench::client_hello(bench::kBenchHost);

  // --- build the ring once -------------------------------------------------

  std::vector<pcpp::RawPacket> ring;
  std::vector<std::size_t> stamp_at(kRing); // byte offset of the timestamp
  ring.reserve(kRing);

  // One sender process cannot saturate more than about one worker, so the
  // driver runs several in parallel. They must not generate the SAME flows: two
  // senders emitting identical 5-tuples would look like retransmissions to the
  // reassembler and be held rather than decided. Each shard therefore owns a
  // disjoint source-port block.
  //
  // Source ADDRESSES stay spread across the whole range in every shard, because
  // the address is what the kernel hashes to pick a queue -- partitioning those
  // instead would pin each sender to one worker and defeat the point.
  constexpr int kPortsPerShard = 10000;
  if (shard < 0 || shard >= shards)
    die("--shard must be in [0, --shards)");
  const int sport_base = 20000 + shard * kPortsPerShard;

  for (std::size_t i = 0; i < kRing; ++i) {
    const int host =
        bench::kFirstHost + static_cast<int>(i % bench::kHostCount);
    const std::string src = bench::kClientNet + std::to_string(host);
    const auto sport = static_cast<std::uint16_t>(
        sport_base + static_cast<int>((i / bench::kHostCount) % kPortsPerShard));

    pcpp::Packet pkt(2048);
    pcpp::EthLayer eth(src_mac, gw_mac);
    pkt.addLayer(&eth);

    const pcpp::IPv4Address src_ip(src), dst_ip(bench::kServerV4);
    pcpp::IPv4Layer ip(src_ip, dst_ip);
    ip.getIPv4Header()->timeToLive = 64;
    pkt.addLayer(&ip);

    pcpp::TcpLayer tcp(sport, bench::kServerPort);
    auto *th = tcp.getTcpHeader();
    th->windowSize = htons(65535);
    th->ackFlag = 1;
    th->pshFlag = 1;
    // The tls profile opens each flow at its ISN so the ClientHello is the
    // first byte of the stream; bulk traffic sits mid-stream on a flow the
    // inspector will never track.
    th->sequenceNumber = htonl(profile == bench::Profile::Tls ? 1001 : 500000);
    pkt.addLayer(&tcp);

    std::vector<std::uint8_t> payload;
    if (profile == bench::Profile::Tls) {
      payload = hello;
      stamp_at[i] = bench::kTlsRandomOffset;
    } else {
      payload.assign(static_cast<std::size_t>(payload_size) < bench::kStampLen
                         ? bench::kStampLen
                         : static_cast<std::size_t>(payload_size),
                     0x41);
      stamp_at[i] = 0;
    }
    pcpp::PayloadLayer pl(payload.data(), payload.size());
    pkt.addLayer(&pl);
    pkt.computeCalculateFields();

    // Copy the bytes into a buffer the RawPacket OWNS. `pkt` dies at the end
    // of this iteration, so storing a pointer into it would dangle -- and
    // because every iteration reuses the same heap block, every ring entry
    // would end up aliasing the same packet, collapsing all the source
    // addresses into one and sending every packet to a single queue.
    const pcpp::RawPacket *raw = pkt.getRawPacket();
    const int len = raw->getRawDataLen();
    auto *owned = new std::uint8_t[static_cast<std::size_t>(len)];
    std::memcpy(owned, raw->getRawData(), static_cast<std::size_t>(len));
    ring.emplace_back(owned, len, raw->getPacketTimeStamp(),
                      /*deleteRawDataAtDestructor=*/true,
                      pcpp::LINKTYPE_ETHERNET);

    // Offset of the timestamp within the whole frame, resolved once here so the
    // send loop does no layer walking at all.
    stamp_at[i] += static_cast<std::size_t>(raw->getRawDataLen()) -
                   payload.size();
  }

  // --- offer load ----------------------------------------------------------

  std::uint64_t sent = 0, failed = 0;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  const std::uint64_t t0 = bench::now_ns();

  std::size_t idx = 0;

  // Pacing. Sending flat out measures how deep the buffers are, not how much
  // the system can carry: packets pile up, latency becomes queueing delay, and
  // loss says only that something overflowed. A fixed offered rate is what
  // makes both numbers mean something.
  const double ns_per_pkt =
      target_pps > 0 ? 1e9 / static_cast<double>(target_pps) : 0.0;
  const std::uint64_t pace_start = bench::now_ns();

  while (std::chrono::steady_clock::now() < deadline) {
    // The ring is contiguous, so a slice of it can go to pcpp's bulk send
    // directly -- no gathering into a scratch array. Stop at the wrap point
    // rather than copying, and pick the slice up again next iteration.
    const std::size_t n = std::min<std::size_t>(kBatch, kRing - idx);

    for (std::size_t b = 0; b < n; ++b) {
      auto *data = const_cast<std::uint8_t *>(ring[idx + b].getRawData());
      bench::write_stamp(data + stamp_at[idx + b], bench::now_ns());
    }

    const int ok = dev->sendPackets(&ring[idx], static_cast<int>(n));
    sent += static_cast<std::uint64_t>(ok);
    failed += n - static_cast<std::uint64_t>(ok);
    idx = (idx + n) % kRing;

    // Wait until this many packets *should* have gone out. Spinning rather
    // than sleeping: at these rates a nanosleep's own latency is larger than
    // the gap being enforced.
    if (ns_per_pkt > 0.0) {
      const auto due = pace_start +
          static_cast<std::uint64_t>(static_cast<double>(sent) * ns_per_pkt);
      while (bench::now_ns() < due) { /* spin */ }
    }
  }

  const std::uint64_t t1 = bench::now_ns();
  dev->close();

  const double elapsed = static_cast<double>(t1 - t0) / 1e9;
  std::printf("SHARD %d SENT %llu FAILED %llu ELAPSED %.4f PPS %.0f\n", shard,
              static_cast<unsigned long long>(sent),
              static_cast<unsigned long long>(failed), elapsed,
              static_cast<double>(sent) / elapsed);
  return 0;
}
