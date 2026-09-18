#pragma once

// Shared between the bench sender and receiver: the traffic profiles, and where
// the send timestamp lives in each kind of packet.
//
// Latency is measured by stamping CLOCK_MONOTONIC into the packet before it
// goes out and reading it back on the far side. Both ends run on the same
// machine, and CLOCK_MONOTONIC is system-wide on Linux, so the two readings are
// directly comparable with no clock sync to arrange.

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace bench {

// Marks a packet as ours, so the receiver never times a stray packet.
inline constexpr std::uint32_t kMagic = 0xB3C4D5E6;

// Where the timestamp sits, per packet kind:
//
//   bulk  -- the payload is ours to shape, so it starts with
//            [magic(4)][send_ns(8)] and is padded out to the profile's size.
//
//   tls   -- the payload has to be a parseable ClientHello, so the stamp goes
//            in the 32-byte `random` field, which is genuinely random in real
//            traffic and is not read by SNI parsing. It sits at a fixed offset:
//            record header(5) + handshake header(4) + legacy_version(2).
inline constexpr std::size_t kTlsRandomOffset = 11;
inline constexpr std::size_t kStampLen = 12; // magic(4) + send_ns(8)

inline std::uint64_t now_ns() {
  timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull +
         static_cast<std::uint64_t>(ts.tv_nsec);
}

inline void write_stamp(std::uint8_t *at, std::uint64_t ns) {
  at[0] = static_cast<std::uint8_t>(kMagic >> 24);
  at[1] = static_cast<std::uint8_t>(kMagic >> 16);
  at[2] = static_cast<std::uint8_t>(kMagic >> 8);
  at[3] = static_cast<std::uint8_t>(kMagic);
  for (int i = 0; i < 8; ++i)
    at[4 + i] = static_cast<std::uint8_t>(ns >> (56 - 8 * i));
}

// Returns false when the magic is absent, i.e. not a packet we stamped.
inline bool read_stamp(const std::uint8_t *at, std::uint64_t &ns) {
  const std::uint32_t magic = (static_cast<std::uint32_t>(at[0]) << 24) |
                              (static_cast<std::uint32_t>(at[1]) << 16) |
                              (static_cast<std::uint32_t>(at[2]) << 8) | at[3];
  if (magic != kMagic)
    return false;
  ns = 0;
  for (int i = 0; i < 8; ++i)
    ns = (ns << 8) | at[4 + i];
  return true;
}

// What kind of traffic to generate.
//
//   Bulk -- payload-carrying packets on flows the inspector never tracks. This
//           is the path almost all real traffic takes: one dissect, one failed
//           hash lookup, one verdict. No pcpp::Packet is ever constructed.
//   Tls  -- every flow opens with a SYN and a full ClientHello, so every flow
//           is tracked, reassembled and resolved. The expensive path, and the
//           upper bound on what inspection costs.
enum class Profile { Bulk, Tls };

inline const char *profile_name(Profile p) {
  return p == Profile::Bulk ? "bulk" : "tls";
}

// The SNI the tls profile sends. Deliberately NOT on the blocklist: a blocked
// packet never reaches the far side, so it would contribute no latency sample
// and would not count as delivered. Blocking is correctness, measured by the
// e2e suite; this measures the cost of deciding.
inline constexpr const char *kBenchHost = "bench.allowed.test";

inline constexpr const char *kServerV4 = "10.98.2.2";
inline constexpr std::uint16_t kServerPort = 443;

// Source addresses are spread across 10.98.1.0/24. The kernel picks a queue by
// hashing (saddr, daddr, protocol), so this is the ONLY thing that spreads load
// across workers -- with a single source address every packet lands on one
// queue no matter how many workers are running.
inline constexpr const char *kClientNet = "10.98.1.";
inline constexpr int kFirstHost = 10;
inline constexpr int kHostCount = 200;

std::vector<std::uint8_t> client_hello(const std::string &host);

} // namespace bench
