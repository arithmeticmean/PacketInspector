// bench receiver: samples end-to-end latency. It does NOT count throughput.
//
// Counting delivered packets here would be wrong: libpcap drops under load, and
// those drops would be indistinguishable from the inspector dropping packets --
// silently understating delivery exactly when the numbers matter most. The
// driver reads delivery from the router's kernel interface counters instead.
//
// Latency tolerates sampling: losing some observations does not bias the
// percentiles, so a capture that drops is still a usable latency source. The
// capture's own drop count is reported anyway, so a run where it dropped so
// much that the sample is thin is visible rather than assumed.

#include "bench_common.hpp"

#include <arpa/inet.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/TcpLayer.h>

namespace {

// Latency histogram in microsecond buckets. A fixed array, so recording a
// sample is one increment with no allocation -- the callback runs on the
// capture path and anything slower would make the receiver the bottleneck.
constexpr std::size_t kMaxUs = 200000; // 200ms; anything slower is an overflow
std::vector<std::uint64_t> g_hist(kMaxUs + 1, 0);
std::uint64_t g_samples = 0;
std::uint64_t g_overflow = 0;
std::uint64_t g_unstamped = 0;

[[noreturn]] void die(const std::string &msg) {
  std::fprintf(stderr, "bench_receiver: %s\n", msg.c_str());
  std::exit(1);
}

void on_packet(pcpp::RawPacket *raw, pcpp::PcapLiveDevice *, void *) {
  pcpp::Packet pkt(raw, pcpp::TCP); // parse no deeper than TCP
  const auto *tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
  if (tcp == nullptr)
    return;

  const std::uint8_t *payload = tcp->getLayerPayload();
  const std::size_t len = tcp->getLayerPayloadSize();
  if (payload == nullptr)
    return;

  // Bulk packets carry the stamp at offset 0; TLS packets carry it inside the
  // ClientHello's random field. Try both -- the magic says which one hit.
  std::uint64_t sent_ns = 0;
  bool got = false;
  if (len >= bench::kStampLen && bench::read_stamp(payload, sent_ns))
    got = true;
  else if (len >= bench::kTlsRandomOffset + bench::kStampLen &&
           bench::read_stamp(payload + bench::kTlsRandomOffset, sent_ns))
    got = true;

  if (!got) {
    ++g_unstamped;
    return;
  }

  const std::uint64_t now = bench::now_ns();
  if (now <= sent_ns)
    return;
  const std::uint64_t us = (now - sent_ns) / 1000;
  if (us > kMaxUs) {
    ++g_overflow;
    return;
  }
  ++g_hist[us];
  ++g_samples;
}

// The latency at or below which `frac` of samples fall.
std::uint64_t percentile(double frac) {
  if (g_samples == 0)
    return 0;
  const auto want = static_cast<std::uint64_t>(
      static_cast<double>(g_samples) * frac);
  std::uint64_t seen = 0;
  for (std::size_t us = 0; us <= kMaxUs; ++us) {
    seen += g_hist[us];
    if (seen >= want)
      return us;
  }
  return kMaxUs;
}

} // namespace

int main(int argc, char **argv) {
  std::string iface;
  int seconds = 8;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&](const char *what) -> std::string {
      if (i + 1 >= argc)
        die(std::string(what) + " needs a value");
      return argv[++i];
    };
    if (a == "--iface") iface = next("--iface");
    else if (a == "--seconds") seconds = std::stoi(next("--seconds"));
    else die("unknown option: " + a);
  }
  if (iface.empty())
    die("usage: bench_receiver --iface <dev> [--seconds n]");

  auto *dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(iface);
  if (dev == nullptr)
    die("no such interface: " + iface);

  // A big kernel capture buffer and immediate mode: we would rather libpcap
  // keep up than batch, since batching would add its own latency to every
  // reading and we are measuring microseconds.
  pcpp::PcapLiveDevice::DeviceConfiguration cfg;
  cfg.packetBufferSize = 64 * 1024 * 1024;
  if (!dev->open(cfg))
    die("cannot open " + iface);

  if (!dev->setFilter("tcp and src net 10.98.1.0/24"))
    die("cannot set capture filter");
  if (!dev->startCapture(on_packet, nullptr))
    die("cannot start capture");

  std::this_thread::sleep_for(std::chrono::seconds(seconds));

  pcpp::IPcapDevice::PcapStats stats{};
  dev->getStatistics(stats);
  dev->stopCapture();
  dev->close();

  // Machine-readable: the driver parses this line.
  std::printf("SAMPLES %llu P50 %llu P99 %llu P999 %llu OVERFLOW %llu "
              "UNSTAMPED %llu CAPDROP %llu\n",
              static_cast<unsigned long long>(g_samples),
              static_cast<unsigned long long>(percentile(0.50)),
              static_cast<unsigned long long>(percentile(0.99)),
              static_cast<unsigned long long>(percentile(0.999)),
              static_cast<unsigned long long>(g_overflow),
              static_cast<unsigned long long>(g_unstamped),
              static_cast<unsigned long long>(stats.packetsDrop));
  return 0;
}
