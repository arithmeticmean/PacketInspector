#include "e2e_cases.hpp"

namespace e2e {
namespace {

void u16(std::vector<std::uint8_t> &v, std::uint16_t x) {
  v.push_back(static_cast<std::uint8_t>(x >> 8));
  v.push_back(static_cast<std::uint8_t>(x));
}

std::vector<std::uint8_t> bytes(const char *s) {
  return std::vector<std::uint8_t>(s, s + std::char_traits<char>::length(s));
}

// The initial sequence number every flow starts from. The SYN consumes one, so
// data begins at kIsn + 1.
constexpr std::uint32_t kIsn = 1000;

// A SYN, which opens a flow and is always allowed through: nothing is known
// about the connection yet, and holding it would stall the very handshake that
// has to finish before a ClientHello can be sent.
TestPacket syn() {
  return {kIsn, SYN, {}, true, "a SYN is always allowed: nothing is known yet"};
}

} // namespace

std::vector<std::uint8_t> client_hello(const std::string &host) {
  std::vector<std::uint8_t> ext; // extensions block
  if (!host.empty()) {
    std::vector<std::uint8_t> entry; // name_type(1) name_len(2) name
    entry.push_back(0x00);
    u16(entry, static_cast<std::uint16_t>(host.size()));
    entry.insert(entry.end(), host.begin(), host.end());

    std::vector<std::uint8_t> list; // ServerNameList
    u16(list, static_cast<std::uint16_t>(entry.size()));
    list.insert(list.end(), entry.begin(), entry.end());

    u16(ext, 0x0000); // extension type: server_name
    u16(ext, static_cast<std::uint16_t>(list.size()));
    ext.insert(ext.end(), list.begin(), list.end());
  }

  std::vector<std::uint8_t> body;
  body.push_back(0x03);
  body.push_back(0x03); // legacy_version TLS 1.2
  for (int i = 0; i < 32; ++i)
    body.push_back(0xAB); // random
  body.push_back(0x00);   // session_id length
  u16(body, 2);
  body.push_back(0x13);
  body.push_back(0x01); // one cipher suite
  body.push_back(0x01);
  body.push_back(0x00); // compression: null
  u16(body, static_cast<std::uint16_t>(ext.size()));
  body.insert(body.end(), ext.begin(), ext.end());

  std::vector<std::uint8_t> hs; // handshake: msg_type(1) length(3)
  hs.push_back(0x01);
  hs.push_back(static_cast<std::uint8_t>(body.size() >> 16));
  hs.push_back(static_cast<std::uint8_t>(body.size() >> 8));
  hs.push_back(static_cast<std::uint8_t>(body.size()));
  hs.insert(hs.end(), body.begin(), body.end());

  std::vector<std::uint8_t> rec; // record: type(1) version(2) length(2)
  rec.push_back(0x16);
  rec.push_back(0x03);
  rec.push_back(0x01);
  u16(rec, static_cast<std::uint16_t>(hs.size()));
  rec.insert(rec.end(), hs.begin(), hs.end());
  return rec;
}

std::vector<TestCase> all_cases() {
  std::vector<TestCase> cases;

  const auto blocked = client_hello(kBlockedHost);
  const auto allowed = client_hello(kAllowedHost);
  const auto wildcard = client_hello(std::string("sub.") + kWildcardSuffix);
  const auto no_sni = client_hello("");

  // Split a payload into `n` roughly equal chunks, each with the right
  // sequence number for its offset.
  auto chunks = [](const std::vector<std::uint8_t> &data, std::size_t n) {
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> out;
    const std::size_t each = (data.size() + n - 1) / n;
    for (std::size_t off = 0; off < data.size(); off += each) {
      const std::size_t len = std::min(each, data.size() - off);
      out.emplace_back(kIsn + 1 + static_cast<std::uint32_t>(off),
                       std::vector<std::uint8_t>(data.begin() + off,
                                                 data.begin() + off + len));
    }
    return out;
  };

  // ---- IPv4 ---------------------------------------------------------------

  cases.push_back({"v4_blocked_simple",
                   false,
                   10,
                   41000,
                   {syn(),
                    {kIsn + 1, PSH | ACK, blocked, false,
                     "ClientHello for a blocklisted SNI must be DROPPED"}}});

  cases.push_back({"v4_allowed_simple",
                   false,
                   11,
                   41001,
                   {syn(),
                    {kIsn + 1, PSH | ACK, allowed, true,
                     "ClientHello for an unlisted SNI must pass"}}});

  {
    // The case the reassembler exists for -- and, under -j > 1, the case that
    // proves flow affinity: if these segments were spread across workers, no
    // single reassembler would ever see a whole ClientHello and the flow would
    // wrongly be allowed.
    TestCase c{"v4_blocked_split", false, 12, 41002, {syn()}};
    for (auto &[seq, data] : chunks(blocked, 4))
      c.packets.push_back({seq, PSH | ACK, data, false,
                           "segment of a split blocklisted ClientHello must be "
                           "DROPPED (needs reassembly + flow affinity)"});
    cases.push_back(std::move(c));
  }

  {
    // Same, delivered back to front, so pcpp has to buffer the later half until
    // the gap in front of it is filled.
    TestCase c{"v4_blocked_reorder", false, 13, 41003, {syn()}};
    auto parts = chunks(blocked, 2);
    for (auto it = parts.rbegin(); it != parts.rend(); ++it)
      c.packets.push_back({it->first, PSH | ACK, it->second, false,
                           "out-of-order segment of a blocklisted ClientHello "
                           "must be DROPPED"});
    cases.push_back(std::move(c));
  }

  cases.push_back({"v4_wildcard_blocked",
                   false,
                   14,
                   41004,
                   {syn(),
                    {kIsn + 1, PSH | ACK, wildcard, false,
                     "a subdomain of a *. blocklist entry must be DROPPED"}}});

  cases.push_back({"v4_non_tls",
                   false,
                   15,
                   41005,
                   {syn(),
                    {kIsn + 1, PSH | ACK, bytes("GET / HTTP/1.1\r\n\r\n"), true,
                     "plain HTTP carries no SNI and must pass"}}});

  cases.push_back(
      {"v4_pure_ack",
       false,
       16,
       41006,
       {{kIsn, ACK, {}, true,
         "a bare ACK on an untracked flow must pass without being tracked"}}});

  cases.push_back({"v4_no_sni",
                   false,
                   17,
                   41007,
                   {syn(),
                    {kIsn + 1, PSH | ACK, no_sni, true,
                     "a ClientHello with no server_name must pass"}}});

  {
    // BAIL 1: the record header declares a length past the 2^14 TLSPlaintext
    // maximum. Resolved immediately as "not a ClientHello" -- fail open.
    std::vector<std::uint8_t> bad{0x16, 0x03, 0x01, 0xff, 0xff,
                                  0x01, 0x00, 0x00, 0x40};
    bad.resize(80, 0xAA);
    cases.push_back({"v4_oversized_record",
                     false,
                     18,
                     41008,
                     {syn(),
                      {kIsn + 1, PSH | ACK, bad, true,
                       "an impossible record length must fail OPEN, not closed"}}});
  }

  {
    // Once a flow is decided against, the rest of the connection is dropped on
    // arrival without ever reaching the reassembler.
    TestCase c{"v4_blocked_then_more", false, 19, 41009,
               {syn(),
                {kIsn + 1, PSH | ACK, blocked, false,
                 "the ClientHello that triggers the block must be DROPPED"}}};
    std::uint32_t seq = kIsn + 1 + static_cast<std::uint32_t>(blocked.size());
    for (int i = 0; i < 3; ++i) {
      c.packets.push_back({seq, PSH | ACK, bytes("more-data"), false,
                           "traffic after the block must stay DROPPED"});
      seq += 9;
    }
    cases.push_back(std::move(c));
  }

  cases.push_back(
      {"v4_midstream_blocked",
       false,
       20,
       41010,
       {// No SYN at all: a connection already running when we attached. The
        // flow has to be picked up from the TLS record itself.
        {kIsn + 5000, PSH | ACK, blocked, false,
         "a ClientHello on a flow with no observed SYN must still be DROPPED"}}});

  {
    // BAIL 4: half a ClientHello and then silence. Nothing else will ever
    // release these -- only the idle sweep does, after ~10s, and it fails open.
    TestCase c{"v4_partial_hello_idle", false, 21, 41011, {syn()}};
    c.packets.push_back(
        {kIsn + 1, PSH | ACK,
         std::vector<std::uint8_t>(blocked.begin(),
                                   blocked.begin() + blocked.size() / 2),
         true,
         "a half ClientHello is held, then released by the idle sweep (~10s)"});
    cases.push_back(std::move(c));
  }

  {
    // A ClientHello fragmented across TWO TLS records. Legal per RFC 8446 s5.1,
    // and the standard way a client evades an SNI filter that assumes one
    // handshake message per record: the second record's 5-byte header lands in
    // the middle of the message, desynchronising a naive parser, which then
    // finds no hostname and -- failing open -- lets the flow through.
    //
    // Distinct from v4_blocked_split: that one is TCP segmentation, which
    // reassembly fixes. This one survives perfect reassembly.
    const std::vector<uint8_t> hs(blocked.begin() + 5, blocked.end());
    const std::size_t at = 20;
    std::vector<uint8_t> two;
    auto rec = [&](const uint8_t *q, std::size_t n) {
      two.push_back(0x16);
      two.push_back(0x03);
      two.push_back(0x01);
      u16(two, static_cast<std::uint16_t>(n));
      two.insert(two.end(), q, q + n);
    };
    rec(hs.data(), at);
    rec(hs.data() + at, hs.size() - at);

    cases.push_back({"v4_blocked_two_records",
                     false,
                     22,
                     41012,
                     {syn(),
                      {kIsn + 1, PSH | ACK, two, false,
                       "a ClientHello fragmented across two TLS records must "
                       "still be DROPPED -- reassembly alone does not fix this"}}});
  }

  // ---- IPv6 ---------------------------------------------------------------

  cases.push_back({"v6_blocked_simple",
                   true,
                   30,
                   41020,
                   {syn(),
                    {kIsn + 1, PSH | ACK, blocked, false,
                     "blocklisted SNI over IPv6 must be DROPPED"}}});

  cases.push_back({"v6_allowed_simple",
                   true,
                   31,
                   41021,
                   {syn(),
                    {kIsn + 1, PSH | ACK, allowed, true,
                     "unlisted SNI over IPv6 must pass"}}});

  {
    TestCase c{"v6_blocked_split", true, 32, 41022, {syn()}};
    for (auto &[seq, data] : chunks(blocked, 3))
      c.packets.push_back({seq, PSH | ACK, data, false,
                           "segment of a split blocklisted ClientHello over "
                           "IPv6 must be DROPPED"});
    cases.push_back(std::move(c));
  }

  cases.push_back({"v6_non_tls",
                   true,
                   33,
                   41023,
                   {syn(),
                    {kIsn + 1, PSH | ACK, bytes("PING\r\n"), true,
                     "non-TLS payload over IPv6 must pass"}}});

  return cases;
}

} // namespace e2e
