#pragma once

// The end-to-end test corpus: every packet the sender emits and what should
// have happened to it by the time it reaches the far side of the router.
//
// Both the sender and the receiver compile this table, so they cannot disagree
// about what was sent or what was expected. The sender walks it and puts the
// packets on the wire; the receiver walks it and checks each one either arrived
// or did not.
//
// Every case gets its OWN SOURCE ADDRESS. That is not cosmetic: the kernel
// picks an NFQUEUE by hashing (saddr, daddr, protocol), so distinct source
// addresses are what spreads the cases across workers when the suite runs with
// -j > 1. Every packet of a single case keeps the same address, which is what
// guarantees they all land on one worker and one reassembler -- the property
// the multi-worker run is really testing.

#include <cstdint>
#include <string>
#include <vector>

namespace e2e {

// TCP flag bits, matching the wire layout.
enum TcpFlag : std::uint8_t {
  FIN = 0x01,
  SYN = 0x02,
  RST = 0x04,
  PSH = 0x08,
  ACK = 0x10,
};

// One packet to put on the wire, and what should become of it.
struct TestPacket {
  std::uint32_t seq;
  std::uint8_t flags;
  std::vector<std::uint8_t> payload;

  // true  -> must reach the receiver (the inspector ACCEPTed it)
  // false -> must NOT reach the receiver (the inspector DROPped it)
  bool expect_arrival;

  // Printed next to a failure, so a red line explains itself.
  std::string why;
};

// One flow: a unique source address and source port, and the packets sent on it.
struct TestCase {
  std::string name;
  bool ipv6 = false;

  // Host part of the source address: 10.99.1.<host> or fd00:99:1::<host>.
  // Unique per case, which is what spreads cases over queues.
  std::uint8_t host = 0;

  std::uint16_t sport = 0;
  std::vector<TestPacket> packets;
};

// Hostnames the e2e blocklist contains. Kept here so the script that writes the
// blocklist file and the cases that rely on it cannot drift apart.
inline constexpr const char *kBlockedHost = "blocked.e2e.test";
inline constexpr const char *kWildcardSuffix = "wild.e2e.test";
inline constexpr const char *kAllowedHost = "allowed.e2e.test";

// Server side of the path.
inline constexpr const char *kServerV4 = "10.99.2.2";
inline constexpr const char *kServerV6 = "fd00:99:2::2";
inline constexpr std::uint16_t kServerPort = 443;

// A structurally valid TLS ClientHello carrying `host` in SNI. An empty host
// emits no server_name extension at all.
std::vector<std::uint8_t> client_hello(const std::string &host);

// How long the inspector waits before giving up on a flow that has gone quiet
// and releasing the packets it was holding. One case deliberately triggers it,
// so the receiver has to keep capturing past this.
inline constexpr int kIdleTimeoutSeconds = 10;

// The corpus.
std::vector<TestCase> all_cases();

} // namespace e2e
