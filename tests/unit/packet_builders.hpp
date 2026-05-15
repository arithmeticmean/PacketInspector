#pragma once

// Small helpers that craft real L3 (IPv4/TCP) packets with pcpp, plus a minimal
// TLS ClientHello, so tests can exercise inspect()/reassembly on wire bytes.

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <arpa/inet.h> // htonl

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/TcpLayer.h>

namespace testpkt {

enum TcpFlag : uint8_t { FIN = 1, SYN = 2, RST = 4, PSH = 8, ACK = 16 };

// A structurally-valid TLS ClientHello record carrying `host` in the SNI
// extension. If `host` is empty, no server_name extension is emitted.
inline std::vector<uint8_t> client_hello(const std::string &host) {
  const auto u16 = [](std::vector<uint8_t> &v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
  };

  std::vector<uint8_t> ext; // extensions block body
  if (!host.empty()) {
    std::vector<uint8_t> entry; // name_type(1) name_len(2) name
    entry.push_back(0x00);
    u16(entry, static_cast<uint16_t>(host.size()));
    entry.insert(entry.end(), host.begin(), host.end());
    std::vector<uint8_t> list; // server_name_list
    u16(list, static_cast<uint16_t>(entry.size()));
    list.insert(list.end(), entry.begin(), entry.end());
    u16(ext, 0x0000); // extension type: server_name
    u16(ext, static_cast<uint16_t>(list.size()));
    ext.insert(ext.end(), list.begin(), list.end());
  }

  std::vector<uint8_t> body;
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
  u16(body, static_cast<uint16_t>(ext.size()));
  body.insert(body.end(), ext.begin(), ext.end());

  std::vector<uint8_t> hs; // handshake: type(1)=ClientHello + length(3)
  hs.push_back(0x01);
  hs.push_back(static_cast<uint8_t>(body.size() >> 16));
  hs.push_back(static_cast<uint8_t>(body.size() >> 8));
  hs.push_back(static_cast<uint8_t>(body.size()));
  hs.insert(hs.end(), body.begin(), body.end());

  std::vector<uint8_t> rec; // record: type(1)=handshake version(2) length(2)
  rec.push_back(0x16);
  rec.push_back(0x03);
  rec.push_back(0x01);
  u16(rec, static_cast<uint16_t>(hs.size()));
  rec.insert(rec.end(), hs.begin(), hs.end());
  return rec;
}

// One IPv4/TCP segment as L3 bytes (IP header onward), built with pcpp.
inline std::vector<uint8_t> build_l3(const char *src, const char *dst,
                                     uint16_t sport, uint16_t dport, uint32_t seq,
                                     uint8_t flags, const uint8_t *payload,
                                     std::size_t plen) {
  const pcpp::IPv4Address src_ip(src), dst_ip(dst);
  pcpp::IPv4Layer ip(src_ip, dst_ip);
  pcpp::TcpLayer tcp(sport, dport);

  pcpp::Packet p(256);
  p.addLayer(&ip);
  p.addLayer(&tcp);
  std::unique_ptr<pcpp::PayloadLayer> pl;
  if (payload != nullptr && plen != 0) {
    pl = std::make_unique<pcpp::PayloadLayer>(payload, plen);
    p.addLayer(pl.get());
  }

  ip.getIPv4Header()->timeToLive = 64;
  auto *th = tcp.getTcpHeader();
  th->sequenceNumber = htonl(seq);
  th->synFlag = (flags & SYN) ? 1 : 0;
  th->ackFlag = (flags & ACK) ? 1 : 0;
  th->finFlag = (flags & FIN) ? 1 : 0;
  th->rstFlag = (flags & RST) ? 1 : 0;
  th->pshFlag = (flags & PSH) ? 1 : 0;

  p.computeCalculateFields();
  const pcpp::RawPacket *raw = p.getRawPacket();
  return std::vector<uint8_t>(raw->getRawData(),
                              raw->getRawData() + raw->getRawDataLen());
}

} // namespace testpkt
