#include "bench_common.hpp"

namespace bench {
namespace {
void u16(std::vector<std::uint8_t> &v, std::uint16_t x) {
  v.push_back(static_cast<std::uint8_t>(x >> 8));
  v.push_back(static_cast<std::uint8_t>(x));
}
} // namespace

// Same shape as the e2e builder. Kept separate rather than shared because the
// bench cares about one property the e2e does not: `random` must sit at a fixed
// offset so the send loop can stamp it without re-parsing the packet.
std::vector<std::uint8_t> client_hello(const std::string &host) {
  std::vector<std::uint8_t> ext;
  if (!host.empty()) {
    std::vector<std::uint8_t> entry;
    entry.push_back(0x00);
    u16(entry, static_cast<std::uint16_t>(host.size()));
    entry.insert(entry.end(), host.begin(), host.end());
    std::vector<std::uint8_t> list;
    u16(list, static_cast<std::uint16_t>(entry.size()));
    list.insert(list.end(), entry.begin(), entry.end());
    u16(ext, 0x0000);
    u16(ext, static_cast<std::uint16_t>(list.size()));
    ext.insert(ext.end(), list.begin(), list.end());
  }

  std::vector<std::uint8_t> body;
  body.push_back(0x03);
  body.push_back(0x03);
  for (int i = 0; i < 32; ++i)
    body.push_back(0xAB); // random -- the send loop overwrites the first 12
  body.push_back(0x00);
  u16(body, 2);
  body.push_back(0x13);
  body.push_back(0x01);
  body.push_back(0x01);
  body.push_back(0x00);
  u16(body, static_cast<std::uint16_t>(ext.size()));
  body.insert(body.end(), ext.begin(), ext.end());

  std::vector<std::uint8_t> hs;
  hs.push_back(0x01);
  hs.push_back(static_cast<std::uint8_t>(body.size() >> 16));
  hs.push_back(static_cast<std::uint8_t>(body.size() >> 8));
  hs.push_back(static_cast<std::uint8_t>(body.size()));
  hs.insert(hs.end(), body.begin(), body.end());

  std::vector<std::uint8_t> rec;
  rec.push_back(0x16);
  rec.push_back(0x03);
  rec.push_back(0x01);
  u16(rec, static_cast<std::uint16_t>(hs.size()));
  rec.insert(rec.end(), hs.begin(), hs.end());
  return rec;
}

} // namespace bench
