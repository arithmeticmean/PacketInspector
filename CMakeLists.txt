cmake_minimum_required(VERSION 3.9)

project(PacketInspector VERSION 1.0 LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR
    "PacketInspector requires the Linux kernel (netfilter NFQUEUE). "
    "Detected CMAKE_SYSTEM_NAME='${CMAKE_SYSTEM_NAME}', which is not supported.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(PCAPPP_VERSION "v25.05" CACHE STRING
    "PcapPlusPlus release tag to fetch. Empty = v25.05.")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  set(_pcpp_re "ubuntu-.*aarch64")
else()
  set(_pcpp_re "ubuntu-24.04-gcc.*x86_64")
endif()
set(PCAPPP_ASSET_REGEX "${_pcpp_re}" CACHE STRING
    "Regex matching the prebuilt PcapPlusPlus release asset name.")

# Resolve the download URL from the GitHub releases API of pcap++.
function(pcpp_resolve_asset out_url out_tag)
  if(PCAPPP_VERSION STREQUAL "")
    set(api "https://api.github.com/repos/seladb/PcapPlusPlus/releases/latest")
  else()
    set(api "https://api.github.com/repos/seladb/PcapPlusPlus/releases/tags/${PCAPPP_VERSION}")
  endif()

  set(json "${CMAKE_BINARY_DIR}/pcapplusplus-release.json")
  message(STATUS "PcapPlusPlus: querying ${api}")
  file(DOWNLOAD "${api}" "${json}"
       STATUS st TLS_VERIFY ON
       HTTPHEADER "Accept: application/vnd.github+json"
       HTTPHEADER "User-Agent: cmake")
  list(GET st 0 code)
  list(GET st 1 msg)
  if(NOT code EQUAL 0)
    message(FATAL_ERROR "PcapPlusPlus: GitHub API request failed (${code}): ${msg}")
  endif()

  file(READ "${json}" data)
  string(JSON tag ERROR_VARIABLE e GET "${data}" "tag_name")
  if(e)
    message(FATAL_ERROR "PcapPlusPlus: could not parse release JSON: ${e}\n${data}")
  endif()

  string(JSON n_assets LENGTH "${data}" "assets")
  if(n_assets EQUAL 0)
    message(FATAL_ERROR "PcapPlusPlus: release ${tag} has no assets")
  endif()

  set(url "")
  math(EXPR last "${n_assets} - 1")
  foreach(i RANGE ${last})
    string(JSON name GET "${data}" "assets" ${i} "name")
    if(name MATCHES "${PCAPPP_ASSET_REGEX}")
      string(JSON url GET "${data}" "assets" ${i} "browser_download_url")
      break()
    endif()
  endforeach()
  if(url STREQUAL "")
    message(FATAL_ERROR
      "PcapPlusPlus: no asset in release ${tag} matched '${PCAPPP_ASSET_REGEX}'.\n"
      "Override with -DPCAPPP_ASSET_REGEX=<regex>.")
  endif()

  set(${out_url} "${url}" PARENT_SCOPE)
  set(${out_tag} "${tag}" PARENT_SCOPE)
endfunction()

pcpp_resolve_asset(PCAPPP_ASSET_URL PCAPPP_TAG)
message(STATUS "PcapPlusPlus: using tag ${PCAPPP_TAG}")
message(STATUS "PcapPlusPlus: downloading ${PCAPPP_ASSET_URL}")

include(FetchContent)
FetchContent_Declare(
  pcapplusplus
  URL "${PCAPPP_ASSET_URL}"
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(pcapplusplus)

# Consume the prebuilt package via its bundled config (imported targets +
# transitive libpcap/threads). No source is compiled for the library here.
find_package(PcapPlusPlus REQUIRED
             PATHS "${pcapplusplus_SOURCE_DIR}/lib/cmake/pcapplusplus"
             NO_DEFAULT_PATH)
# libnetfilter_queue + libmnl: the netlink queue API main.cpp is built on.
# Both ship pkg-config files; PkgConfig::NFQ bundles the include dirs and libs.
find_package(PkgConfig REQUIRED)
pkg_check_modules(NFQ IMPORTED_TARGET libnetfilter_queue libmnl)
if(NOT NFQ_FOUND)
  message(FATAL_ERROR
    "libnetfilter_queue / libmnl not found. Install them:\n"
    "  Arch:   sudo pacman -S libnetfilter_queue libmnl\n"
    "  Debian: sudo apt install libnetfilter-queue-dev libmnl-dev\n"
    "  Fedora: sudo dnf install libnetfilter_queue-devel libmnl-devel")
endif()

# The queue is *started* by an iptables rule in the FORWARD chain, so the
# utility that installs it is a hard requirement. REQUIRED makes configuration
# fail early if iptables is missing.
find_program(IPTABLES_EXECUTABLE NAMES iptables REQUIRED)
message(STATUS "nfqueue: iptables found at ${IPTABLES_EXECUTABLE}")

# A DISTINCT cache variable: find_program skips the search when its output
# variable is already set, so reusing IPTABLES_EXECUTABLE here would silently do
# nothing and leave IPv6 traffic bypassing the inspector entirely.
find_program(IP6TABLES_EXECUTABLE NAMES ip6tables)
if(IP6TABLES_EXECUTABLE)
  message(STATUS "nfqueue: ip6tables found at ${IP6TABLES_EXECUTABLE}")
else()
  set(IP6TABLES_EXECUTABLE "")
  message(WARNING
    "nfqueue: ip6tables not found. The inspector dissects IPv6, but no IPv6 "
    "rule can be installed, so that traffic will bypass it. Install iptables' "
    "IPv6 counterpart and re-run cmake to close this.")
endif()

# TCP destination ports treated as TLS by the generated nfqueue.sh (MODE=ports).
# Overridable at run time with PORTS=... ; see the script's header for the
# trade-off against MODE=ctdir.
set(NFQUEUE_TLS_PORTS "443,8443" CACHE STRING
    "Comma-separated TCP ports to feed to NFQUEUE in the default 'ports' mode.")

# One std::thread per worker.
find_package(Threads REQUIRED)

# NOTE: the unit build deliberately leaves out NFQueue and Worker. Everything
# they do is netlink and thread lifecycle, which cannot be exercised without
# root and a live queue -- that is what tests/e2e is for. What IS unit-tested is
# the logic those two only transport: dissection, blocklist matching, and the
# extractor.

# Collect all source files (C netlink layer + C++ application)
file(GLOB_RECURSE PROJECT_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
)

# Our target: N workers, each inspecting one NFQUEUE.
add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})

target_include_directories(${PROJECT_NAME}
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        PkgConfig::NFQ
        PcapPlusPlus::Pcap++
        Threads::Threads
)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)

# Generate the setup/teardown helper with the discovered iptables baked in.
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/nfqueue.sh.in"
    "${CMAKE_CURRENT_BINARY_DIR}/nfqueue.sh"
    @ONLY
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ WORLD_READ)

# ---------------------------------------------------------------------------
# Tests come in two independent flavours, both off by default:
#
#   -DPACKET_BUILD_TESTS=ON   tests/unit -- GoogleTest, pure logic, no root,
#                             no network. `ctest -L unit`
#   -DPACKET_BUILD_E2E=ON     tests/e2e  -- real TLS over real routed traffic
#                             through the real inspector. Needs root, because it
#                             creates network namespaces and iptables rules.
#                             `sudo ./build/e2e/run.sh`
#
# They share nothing on purpose: the unit build stays fast and runnable by
# anyone, and needing root never becomes a precondition for testing the logic.
if(NOT DEFINED PACKET_BUILD_TESTS AND DEFINED PACKET_BUILD_ALL_TESTS)
  set(PACKET_BUILD_TESTS ${PACKET_BUILD_ALL_TESTS})
endif()
option(PACKET_BUILD_TESTS "Build unit tests (tests/unit)" OFF)
option(PACKET_BUILD_E2E "Build end-to-end tests (tests/e2e); running them needs root" OFF)

if(PACKET_BUILD_TESTS)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
    GIT_SHALLOW TRUE
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  enable_testing()

  # Compile only the pure-logic sources (no main, no netfilter) alongside the
  # tests; the packet crafting in tests uses PcapPlusPlus.
  add_executable(unit_tests
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/test_blocklist.cpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/test_packet.cpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/test_extractor.cpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/src/packet.cpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/src/hostname_extractor.cpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/src/blocklist.cpp")

  target_include_directories(unit_tests PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/include"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit")

  target_link_libraries(unit_tests PRIVATE
      GTest::gtest_main
      PcapPlusPlus::Pcap++
      Threads::Threads)

  target_compile_options(unit_tests PRIVATE -Wall -Wextra)

  include(GoogleTest)
  gtest_discover_tests(unit_tests PROPERTIES LABELS unit)
endif()

# ---------------------------------------------------------------------------
# End-to-end: a TLS client and server either side of a routed path, with the
# real inspector in the middle. Separate binaries and a separate driver, so
# nothing here can be confused with the unit build.
if(PACKET_BUILD_E2E)
  # Two binaries plus a driver script.
  #
  #   e2e_sender    crafts the whole corpus with PcapPlusPlus and injects it
  #                 straight onto a veth, so the local TCP stack never touches
  #                 it and sequence numbers, flags and ordering are exactly what
  #                 the test says they are.
  #   e2e_receiver  sniffs the far side of the router and asserts, per packet,
  #                 that it arrived or did not.
  #
  # Both compile e2e_cases.cpp, so the corpus is defined once and the two
  # cannot drift apart about what was sent or what was expected.
  add_executable(e2e_sender
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/e2e_sender.cpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/e2e_cases.cpp")
  add_executable(e2e_receiver
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/e2e_receiver.cpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/e2e_cases.cpp")

  foreach(t e2e_sender e2e_receiver)
    target_include_directories(${t} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e")
    target_link_libraries(${t} PRIVATE PcapPlusPlus::Pcap++ Threads::Threads)
    target_compile_options(${t} PRIVATE -Wall -Wextra)
  endforeach()

  set(PACKETINSPECTOR_BIN "$<TARGET_FILE:${PROJECT_NAME}>")
  set(E2E_SENDER_BIN      "$<TARGET_FILE:e2e_sender>")
  set(E2E_RECEIVER_BIN    "$<TARGET_FILE:e2e_receiver>")
  set(NFQUEUE_SH          "${CMAKE_CURRENT_BINARY_DIR}/nfqueue.sh")

  # configure_file cannot expand generator expressions, so the driver is
  # written at build time, once the target paths are known.
  configure_file(
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/run.sh.in"
      "${CMAKE_CURRENT_BINARY_DIR}/e2e/run.sh.configured"
      @ONLY)
  file(GENERATE
      OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/e2e/run.sh"
      INPUT "${CMAKE_CURRENT_BINARY_DIR}/e2e/run.sh.configured"
      FILE_PERMISSIONS
          OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
          WORLD_READ WORLD_EXECUTE)

  add_custom_target(e2e ALL DEPENDS ${PROJECT_NAME} e2e_sender e2e_receiver)

  # Registered with CTest but labelled separately, so `ctest -L unit` never
  # trips over it. It fails with a clear message when not run as root.
  enable_testing()
  add_test(NAME e2e_tls_blocking
           COMMAND "${CMAKE_CURRENT_BINARY_DIR}/e2e/run.sh")
  set_tests_properties(e2e_tls_blocking PROPERTIES
      LABELS e2e
      TIMEOUT 300)
endif()

# ---------------------------------------------------------------------------
# Benchmark: -DPACKET_BUILD_BENCH=ON, then `sudo ./build/bench/run.sh [seconds]`
#
# Same namespace model as the e2e suite -- crafted packets, no real TCP or TLS
# -- but tuned for volume rather than coverage. Off by default and never wired
# into CTest: it takes minutes and its output is numbers to read, not a verdict
# to assert.
option(PACKET_BUILD_BENCH "Build the throughput/latency benchmark (needs root to run)" OFF)

if(PACKET_BUILD_BENCH)
  add_executable(bench_sender
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/bench/bench_sender.cpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/bench/bench_common.cpp")
  add_executable(bench_receiver
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/bench/bench_receiver.cpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/bench/bench_common.cpp")

  foreach(t bench_sender bench_receiver)
    target_include_directories(${t} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/bench")
    target_link_libraries(${t} PRIVATE PcapPlusPlus::Pcap++ Threads::Threads)
    # -O2 regardless of build type: a debug-build load generator measures the
    # load generator.
    target_compile_options(${t} PRIVATE -Wall -Wextra -O2)
  endforeach()

  set(PACKETINSPECTOR_BIN "$<TARGET_FILE:${PROJECT_NAME}>")
  set(BENCH_SENDER_BIN    "$<TARGET_FILE:bench_sender>")
  set(BENCH_RECEIVER_BIN  "$<TARGET_FILE:bench_receiver>")

  configure_file(
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/bench/run.sh.in"
      "${CMAKE_CURRENT_BINARY_DIR}/bench/run.sh.configured"
      @ONLY)
  file(GENERATE
      OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/bench/run.sh"
      INPUT "${CMAKE_CURRENT_BINARY_DIR}/bench/run.sh.configured"
      FILE_PERMISSIONS
          OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
          WORLD_READ WORLD_EXECUTE)

  add_custom_target(bench ALL DEPENDS ${PROJECT_NAME} bench_sender bench_receiver)
endif()
