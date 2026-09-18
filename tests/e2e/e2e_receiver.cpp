// e2e receiver: sniffs the far side of the router and checks, for every packet
// in the corpus, that it either arrived or did not -- whichever the case says.
//
// It captures rather than listening as a TCP server, because what is under test
// is which packets the inspector let through, not whether a connection could be
// established. A server socket would answer with SYN-ACKs and RSTs and tell us
// nothing about the packets we actually care about.
//
// Packets are matched on (family, source port, sequence number), which is
// unique per packet across the whole corpus by construction.

#include "e2e_cases.hpp"

#include <arpa/inet.h> // htonl/ntohl for the TCP header fields

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <string>
#include <thread>
#include <tuple>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/TcpLayer.h>

namespace {

// (is_ipv6, source port, sequence number)
using Key = std::tuple<bool, std::uint16_t, std::uint32_t>;

std::set<Key> g_seen;

[[noreturn]] void die(const std::string &msg) {
  std::fprintf(stderr, "e2e_receiver: %s\n", msg.c_str());
  std::exit(1);
}

void on_packet(pcpp::RawPacket *raw, pcpp::PcapLiveDevice *, void *) {
  pcpp::Packet pkt(raw);
  const auto *tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
  if (tcp == nullptr)
    return;

  bool v6 = false;
  if (pkt.isPacketOfType(pcpp::IPv6)) {
    v6 = true;
  } else if (!pkt.isPacketOfType(pcpp::IPv4)) {
    return;
  }

  g_seen.emplace(v6, ntohs(tcp->getTcpHeader()->portSrc),
                 ntohl(tcp->getTcpHeader()->sequenceNumber));
}

const char *red = "\033[31m";
const char *green = "\033[32m";
const char *dim = "\033[2m";
const char *reset = "\033[0m";

} // namespace

int main(int argc, char **argv) {
  std::string iface;
  int seconds = 20;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&](const char *what) -> std::string {
      if (i + 1 >= argc)
        die(std::string(what) + " needs a value");
      return argv[++i];
    };
    if (a == "--iface")
      iface = next("--iface");
    else if (a == "--seconds")
      seconds = std::stoi(next("--seconds"));
    else
      die("unknown option: " + a);
  }
  if (iface.empty())
    die("usage: e2e_receiver --iface <dev> [--seconds n]");

  auto *dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(iface);
  if (dev == nullptr)
    die("no such interface: " + iface);
  if (!dev->open())
    die("cannot open " + iface);

  // Only traffic the sender originated. Without the source filter we would also
  // capture the RSTs this namespace's own kernel sends back at SYNs for a port
  // nothing is listening on, and those would collide with our keys.
  if (!dev->setFilter("tcp and (src net 10.99.1.0/24 or src net fd00:99:1::/64)"))
    die("cannot set capture filter");

  if (!dev->startCapture(on_packet, nullptr))
    die("cannot start capture");

  // Long enough for the whole corpus plus the idle-sweep case, which is held
  // for ~10s by design before being released.
  std::fprintf(stderr, "e2e_receiver: capturing on %s for %ds\n", iface.c_str(),
               seconds);
  std::this_thread::sleep_for(std::chrono::seconds(seconds));
  dev->stopCapture();
  dev->close();

  // --- verdict ------------------------------------------------------------

  const auto cases = e2e::all_cases();
  std::size_t passed = 0, failed = 0;

  for (const e2e::TestCase &c : cases) {
    bool case_ok = true;
    for (const e2e::TestPacket &tp : c.packets) {
      const bool arrived =
          g_seen.count(Key{c.ipv6, c.sport, tp.seq}) > 0;
      if (arrived == tp.expect_arrival)
        continue;

      case_ok = false;
      ++failed;
      std::printf("%sFAIL%s  %-24s seq=%-6u %s\n", red, reset, c.name.c_str(),
                  tp.seq,
                  arrived ? "arrived, but should have been DROPPED"
                          : "was DROPPED, but should have arrived");
      std::printf("      %s%s%s\n", dim, tp.why.c_str(), reset);
    }
    if (case_ok) {
      ++passed;
      std::printf("%sPASS%s  %-24s %s(%zu packets)%s\n", green, reset,
                  c.name.c_str(), dim, c.packets.size(), reset);
    }
  }

  std::printf("\n%zu/%zu cases passed", passed, cases.size());
  if (failed != 0)
    std::printf(", %zu packet expectation(s) violated", failed);
  std::printf("\n");

  return failed == 0 ? 0 : 1;
}
