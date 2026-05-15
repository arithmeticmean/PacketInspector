// Command-line parsing for PacketInspector. Turns argv into a Config.
#pragma once

#include "config.hpp"

namespace cli {

// Result of parsing argv.
//   should_exit == false : `config` is ready to use.
//   should_exit == true  : the caller should return `exit_code` immediately
//                          (0 after --help, 2 after a usage error). Any message
//                          has already been printed.
struct ParseResult {
  Config config;
  bool should_exit = false;
  int exit_code = 0;
};

// Parse argv into a Config. Never throws; reports errors by printing usage and
// setting should_exit/exit_code.
ParseResult parse(int argc, char **argv);

} // namespace cli
