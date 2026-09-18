#include "cli.hpp"

#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <ostream>
#include <string>
#include <string_view>

namespace cli {
namespace {

constexpr const char *kProg = "PacketInspector";

void usage(std::ostream &os) {
  os << "usage: " << kProg << " [options] [blocklist]\n\n"
     << "Attach to an NFQUEUE and DROP flows whose TLS SNI is on the "
        "blocklist;\n"
     << "everything else is ACCEPTed.\n\n"
     << "options:\n"
     << "  -j <n>          workers to run. Each owns one NFQUEUE, one thread\n"
     << "                  and one reassembler                    (default 4)\n"
     << "  -nfq <n>        FIRST NFQUEUE number; worker i binds <n>+i, so the\n"
     << "                  set must match iptables --queue-balance (default "
        "0)\n"
     << "  -nfq-size <n>   NFQUEUE depth in packets, per worker    (default "
        "8192)\n"
     << "  -rcvbuf <n>     netlink recv buffer in bytes, TOTAL across workers\n"
     << "                                                     (default "
        "256MiB)\n"
     << "  -max-blocked <n>  blocked flows a worker remembers, so they cannot\n"
     << "                  crowd out flows still awaiting a verdict\n"
     << "                                            (default: a quarter of "
        "the\n"
     << "                                             flow cap, i.e. 16384)\n"
     << "  -b <path>       blocklist file (or pass it positionally)\n"
     << "                                                 (default "
        "blocklist.txt)\n"
     << "  -pin <cpu>      pin worker i to CPU <cpu> + i*stride; off by default\n"
     << "  -pin-stride <n> CPU stride between workers, for SMT   (default 1)\n"
     << "  -v, --verbose   log a line per resolved flow; off by default "
        "because\n"
     << "                  at load it costs a write() per flow\n"
     << "  --passthrough   allow every packet without inspecting; benchmark\n"
     << "                  baseline for the NFQUEUE round trip alone\n"
     << "  --stats <n>     print a counters line to stderr every n seconds\n"
     << "                                                        (default "
        "off)\n"
     << "  -h, --help      show this help and exit\n";
}

// Parse an unsigned decimal into [lo, hi]. Rejects empty, non-numeric, trailing
// junk, overflow, and out-of-range.
bool parse_uint(std::string_view s, unsigned long long lo,
                unsigned long long hi, unsigned long long &out) {
  if (s.empty())
    return false;
  const std::string tmp(s);
  errno = 0;
  char *end = nullptr;
  const unsigned long long v = std::strtoull(tmp.c_str(), &end, 10);
  if (errno != 0 || end == tmp.c_str() || *end != '\0' || v < lo || v > hi)
    return false;
  out = v;
  return true;
}

} // namespace

ParseResult parse(int argc, char **argv) {
  ParseResult r;
  Config &cfg = r.config;

  // Print message + usage to stderr, mark for exit(2), signal the caller.
  auto fail = [&](const std::string &msg) {
    std::cerr << kProg << ": " << msg << "\n";
    usage(std::cerr);
    r.should_exit = true;
    r.exit_code = 2;
  };

  // Fetch the value that must follow `flag`; fail if it's missing.
  auto value = [&](int &i, std::string_view flag, std::string &out) -> bool {
    if (i + 1 >= argc) {
      fail("option " + std::string(flag) + " requires a value");
      return false;
    }
    out = argv[++i];
    return true;
  };

  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    std::string val;
    unsigned long long n = 0;

    if (arg == "-h" || arg == "--help") {
      usage(std::cout);
      r.should_exit = true;
      r.exit_code = 0;
      return r;
    } else if (arg == "-j") {
      if (!value(i, arg, val))
        return r;
      if (!parse_uint(val, 1, 4096, n)) {
        fail("-j expects an integer 1..4096, got '" + val + "'");
        return r;
      }
      cfg.jobs = static_cast<std::size_t>(n);
    } else if (arg == "-nfq") {
      if (!value(i, arg, val))
        return r;
      if (!parse_uint(val, 0, 65535, n)) {
        fail("-nfq expects a queue number 0..65535, got '" + val + "'");
        return r;
      }
      cfg.queue_num = static_cast<std::uint16_t>(n);
    } else if (arg == "-nfq-size") {
      if (!value(i, arg, val))
        return r;
      if (!parse_uint(val, 1, std::numeric_limits<std::uint32_t>::max(), n)) {
        fail("-nfq-size expects a positive integer, got '" + val + "'");
        return r;
      }
      cfg.queue_maxlen = static_cast<std::uint32_t>(n);
    } else if (arg == "-max-blocked") {
      if (!value(i, arg, val))
        return r;
      if (!parse_uint(val, 1, std::numeric_limits<std::uint32_t>::max(), n)) {
        fail("-max-blocked expects a positive integer, got '" + val + "'");
        return r;
      }
      cfg.max_blocked_flows = static_cast<std::size_t>(n);
    } else if (arg == "-pin") {
      if (!value(i, arg, val))
        return r;
      if (!parse_uint(val, 0, 4095, n)) {
        fail("-pin expects a CPU number 0..4095, got '" + val + "'");
        return r;
      }
      cfg.pin_first_cpu = static_cast<int>(n);
    } else if (arg == "-pin-stride") {
      if (!value(i, arg, val))
        return r;
      if (!parse_uint(val, 1, 64, n)) {
        fail("-pin-stride expects 1..64, got '" + val + "'");
        return r;
      }
      cfg.pin_stride = static_cast<int>(n);
    } else if (arg == "-rcvbuf") {
      if (!value(i, arg, val))
        return r;
      if (!parse_uint(val, 1, std::numeric_limits<int>::max(), n)) {
        fail("-rcvbuf expects a positive byte count, got '" + val + "'");
        return r;
      }
      cfg.recv_buf_bytes = static_cast<int>(n);
    } else if (arg == "-b") {
      if (!value(i, arg, val))
        return r;
      cfg.blocklist_path = val;
    } else if (arg == "-v" || arg == "--verbose") {
      cfg.verbose = true;
    } else if (arg == "--passthrough") {
      cfg.passthrough = true;
    } else if (arg == "--stats") {
      if (!value(i, arg, val))
        return r;
      if (!parse_uint(val, 0, 86400, n)) {
        fail("--stats expects seconds 0..86400, got '" + val + "'");
        return r;
      }
      cfg.stats_interval_s = static_cast<unsigned>(n);
    } else if (!arg.empty() && arg.front() == '-') {
      fail("unknown option: " + std::string(arg));
      return r;
    } else {
      cfg.blocklist_path = std::string(arg); // bare positional = blocklist
    }
  }

  // Worker i binds queue_num + i, so the whole range has to stay inside the
  // 16-bit queue number space. Catch it here rather than as a bind failure on
  // worker 40000.
  if (cfg.queue_num + cfg.worker_count() - 1 > 65535) {
    fail("-nfq " + std::to_string(cfg.queue_num) + " with -j " +
         std::to_string(cfg.jobs) + " would need queues up to " +
         std::to_string(cfg.queue_num + cfg.worker_count() - 1) +
         ", past the 65535 maximum");
    return r;
  }
  return r;
}

} // namespace cli
