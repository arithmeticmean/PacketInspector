#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_set>

// An immutable hostname blocklist, populated once from a file at init and only
// read afterwards -- so concurrent isHostnameBlocked() calls from worker threads
// are safe without locking.
//
// Two entry kinds (one per line in the file):
//   example.com     full match     -> blocks exactly "example.com"
//   *.example.com   wildcard        -> blocks any subdomain of example.com
//                                      ("a.example.com", "a.b.example.com", ...),
//                                      but not the apex "example.com" itself.
// Matching is exact/case-sensitive; SNI host_names are normally lowercase, so
// keep blocklist entries lowercase.
class BlockList {
public:
  explicit BlockList(std::string fname_txt);

  // Blocked if `hostname` is a full-match entry or a subdomain of any wildcard
  // entry. Allocation-free lookup; read-only, safe to call concurrently.
  bool isHostnameBlocked(std::string_view hostname) const noexcept;

private:
  // Transparent hashing lets us look up a std::string_view (a hostname suffix)
  // without materializing a std::string.
  struct Hash {
    using is_transparent = void;
    std::size_t operator()(std::string_view s) const noexcept {
      return std::hash<std::string_view>{}(s);
    }
  };
  using HostSet = std::unordered_set<std::string, Hash, std::equal_to<>>;

  HostSet _exact;    // full-match hostnames
  HostSet _wildcard; // suffixes of "*.suffix" entries (subdomain match)
};
