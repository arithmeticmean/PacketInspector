// e2e sender: puts the whole test corpus on the wire, and nothing else.
//
// Packets are crafted all the way down to the Ethernet header and injected
// straight onto the veth with libpcap, so the local TCP stack is never
// involved. That is the point: we need exact control of sequence numbers,
// flags and ordering -- including deliberately out-of-order segments, which no
// real stack would ever emit.
//
// It sends and exits. Whether anything arrived is the receiver's job.

#include "e2e_cases.hpp"

#include <arpa/inet.h> // htonl/ntohl for the TCP header fields

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/TcpLayer.h>

namespace {

// A short gap between packets. Without it, segments of one flow can reach the
// inspector faster than it dequeues them, and the reorder case stops being
// reliably out of order -- which would make the test flaky rather than strict.
constexpr auto kGap = std::chrono::milliseconds(4);

[[noreturn]] void die(const std::string &msg) {
  std::fprintf(stderr, "e2e_sender: %s\n", msg.c_str());
  std::exit(1);
}

std::string v4_source(std::uint8_t host) {
  return "10.99.1." + std::to_string(host);
}

std::string v6_source(std::uint8_t host) {
  char buf[64];
  std::snprintf(buf, sizeof(buf), "fd00:99:1::%x", host);
  return buf;
}

} // namespace

int main(int argc, char **argv) {
  std::string iface, dst_mac;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&](const char *what) -> std::string {
      if (i + 1 >= argc)
        die(std::string(what) + " needs a value");
      return argv[++i];
    };
    if (a == "--iface")
      iface = next("--iface");
    else if (a == "--dst-mac")
      dst_mac = next("--dst-mac");
    else
      die("unknown option: " + a);
  }
  if (iface.empty() || dst_mac.empty())
    die("usage: e2e_sender --iface <dev> --dst-mac <aa:bb:cc:dd:ee:ff>");

  auto *dev =
      pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(iface);
  if (dev == nullptr)
    die("no such interface: " + iface);
  if (!dev->open())
    die("cannot open " + iface);

  const pcpp::MacAddress src_mac = dev->getMacAddress();
  const pcpp::MacAddress gw_mac(dst_mac);

  const auto cases = e2e::all_cases();
  std::size_t sent = 0;

  for (const e2e::TestCase &c : cases) {
    for (const e2e::TestPacket &tp : c.packets) {
      pcpp::Packet pkt(1500);

      pcpp::EthLayer eth(src_mac, gw_mac);
      if (!pkt.addLayer(&eth))
        die("addLayer(eth) failed");

      // Built on the stack, so both branches have to stay alive until the
      // packet is sent -- hence declaring them here rather than inside the if.
      pcpp::IPv4Layer ip4;
      pcpp::IPv6Layer ip6;
      if (c.ipv6) {
        ip6 = pcpp::IPv6Layer(pcpp::IPv6Address(v6_source(c.host)),
                              pcpp::IPv6Address(e2e::kServerV6));
        // pcpp's constructor leaves this at 0, and a router discards a hop
        // limit of 0 before any rule sees the packet -- which looks exactly
        // like the inspector dropping it.
        ip6.getIPv6Header()->hopLimit = 64;
        if (!pkt.addLayer(&ip6))
          die("addLayer(ipv6) failed");
      } else {
        ip4 = pcpp::IPv4Layer(pcpp::IPv4Address(v4_source(c.host)),
                              pcpp::IPv4Address(e2e::kServerV4));
        ip4.getIPv4Header()->timeToLive = 64;
        if (!pkt.addLayer(&ip4))
          die("addLayer(ipv4) failed");
      }

      pcpp::TcpLayer tcp(c.sport, e2e::kServerPort);
      auto *th = tcp.getTcpHeader();
      th->sequenceNumber = htonl(tp.seq);
      th->windowSize = htons(65535);
      th->synFlag = (tp.flags & e2e::SYN) ? 1 : 0;
      th->ackFlag = (tp.flags & e2e::ACK) ? 1 : 0;
      th->finFlag = (tp.flags & e2e::FIN) ? 1 : 0;
      th->rstFlag = (tp.flags & e2e::RST) ? 1 : 0;
      th->pshFlag = (tp.flags & e2e::PSH) ? 1 : 0;
      if (!pkt.addLayer(&tcp))
        die("addLayer(tcp) failed");

      pcpp::PayloadLayer payload(tp.payload.data(), tp.payload.size());
      if (!tp.payload.empty() && !pkt.addLayer(&payload))
        die("addLayer(payload) failed");

      pkt.computeCalculateFields(); // lengths + checksums

      if (!dev->sendPacket(&pkt))
        die("send failed for " + c.name);
      ++sent;
      std::this_thread::sleep_for(kGap);
    }
  }

  dev->close();
  std::printf("e2e_sender: sent %zu packets across %zu cases\n", sent,
              cases.size());
  return 0;
}
