#include "blocklist.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>

namespace {

// Strip all whitespace from a line in place (hostnames contain none, so this
// both trims the ends and drops any stray spaces). Returns the same line.
std::string &parse_line(std::string &line) {
  line.erase(std::remove_if(line.begin(), line.end(),
                            [](unsigned char c) { return std::isspace(c); }),
             line.end());
  return line;
}

} // namespace

// Populate once, at init, from a text file: one entry per line. Blank lines and
// lines beginning with '#' are ignored. A leading "*." makes the rest a wildcard
// suffix; anything else is a full match. The stream is set to throw on an open
// failure. Read-only afterwards.
BlockList::BlockList(std::string fname_txt) {
  std::ifstream file;
  file.exceptions(std::ios::failbit | std::ios::badbit);
  file.open(fname_txt);               // throws std::ios_base::failure if missing
  file.exceptions(std::ios::goodbit); // plain reads below; EOF is expected

  std::string line;
  while (std::getline(file, line)) {
    parse_line(line);
    if (line.empty() || line.front() == '#')
      continue; // blank line or comment

    if (line.size() > 2 && line[0] == '*' && line[1] == '.')
      _wildcard.emplace(line.substr(2)); // "*.example.com" -> "example.com"
    else
      _exact.insert(std::move(line));
  }
}

bool BlockList::isHostnameBlocked(std::string_view hostname) const noexcept {
  if (_exact.find(hostname) != _exact.end())
    return true;

  // Walk parent domains: for "a.b.example.com" check "b.example.com",
  // "example.com", "com" against the wildcard suffixes. A hit means the hostname
  // is a subdomain of that "*.suffix" entry. One allocation-free lookup per dot.
  for (std::size_t dot = hostname.find('.'); dot != std::string_view::npos;
       dot = hostname.find('.', dot + 1)) {
    const std::string_view suffix = hostname.substr(dot + 1);
    if (suffix.empty())
      break;
    if (_wildcard.find(suffix) != _wildcard.end())
      return true;
  }
  return false;
}
