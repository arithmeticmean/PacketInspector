#include "blocklist.hpp"

#include <exception>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

#include <gtest/gtest.h>

namespace {

// A blocklist file that belongs to exactly one test and deletes itself.
//
// It used to be one fixed path shared by every case, which broke in two ways:
// std::ofstream reports nothing on failure, so a file left behind by another
// user (a stray `sudo ctest` is enough) silently kept its old contents and the
// test then asserted against the wrong fixture; and two cases sharing a path
// cannot run under `ctest -j`. Hence the pid + test name, and the explicit
// check that the write actually happened.
class TempBlocklist {
public:
  explicit TempBlocklist(const std::string &content) {
    const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
    _path = std::filesystem::temp_directory_path() /
            ("blocklist_" + std::string(info != nullptr ? info->name() : "x") +
             "_" + std::to_string(::getpid()) + ".txt");

    std::ofstream out(_path);
    out << content;
    out.close();
    // Fail here, loudly, rather than let a stale or absent file turn into a
    // baffling assertion failure further down.
    EXPECT_TRUE(out.good()) << "could not write fixture " << _path;
  }

  ~TempBlocklist() {
    std::error_code ec;
    std::filesystem::remove(_path, ec);
  }

  TempBlocklist(const TempBlocklist &) = delete;
  TempBlocklist &operator=(const TempBlocklist &) = delete;

  std::string path() const { return _path.string(); }

private:
  std::filesystem::path _path;
};

} // namespace

TEST(BlockList, ExactMatch) {
  const TempBlocklist f("# a comment\nexact.example.com\n\nfoo.test\n");
  const BlockList bl(f.path());
  EXPECT_TRUE(bl.isHostnameBlocked("exact.example.com"));
  EXPECT_TRUE(bl.isHostnameBlocked("foo.test"));
  EXPECT_FALSE(bl.isHostnameBlocked("other.example.com"));
  EXPECT_FALSE(bl.isHostnameBlocked("")); // empty query
  // A comment line must not become an entry.
  EXPECT_FALSE(bl.isHostnameBlocked("# a comment"));
  // Exact entry is not a wildcard: subdomains are not covered.
  EXPECT_FALSE(bl.isHostnameBlocked("sub.exact.example.com"));
}

TEST(BlockList, WildcardMatchesSubdomainsNotApex) {
  const TempBlocklist f("*.blocked.com\n  *.ads.tracker.net  \n");
  const BlockList bl(f.path());
  EXPECT_TRUE(bl.isHostnameBlocked("www.blocked.com"));  // one label
  EXPECT_TRUE(bl.isHostnameBlocked("a.b.blocked.com"));  // deep
  EXPECT_TRUE(bl.isHostnameBlocked("x.ads.tracker.net")); // whitespace trimmed
  EXPECT_FALSE(bl.isHostnameBlocked("blocked.com"));      // apex not matched
  EXPECT_FALSE(bl.isHostnameBlocked("tracker.net"));
  EXPECT_FALSE(bl.isHostnameBlocked("notblocked.com"));
}

TEST(BlockList, MissingFileThrows) {
  EXPECT_THROW(BlockList("/definitely/no/such/blocklist.txt"), std::exception);
}
