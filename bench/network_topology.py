"""The machine and the wires: how this host is divided, and how the test network is built.

WHAT THIS FILE IS
    Everything about the environment the benchmark runs in, before any traffic
    exists. Two jobs:

      1. Decide which CPU cores belong to the traffic generator and which
         belong to PacketInspector.
      2. Build the virtual network the traffic flows through, and tear it down.

THE NETWORK
    Both measurement cases use the SAME wiring. That is deliberate: the only
    difference between them is whether the queue rule and the inspector exist,
    so any difference in the results belongs to the inspector and nothing else.
    A baseline over a shorter path would quietly charge the inspector for an
    extra virtual cable.

        root namespace                    inspector-ns
        ┌──────────────┐               ┌─────────────────┐
        │  generator-c ├═══ veth ═════▶│ dut-c 1.1.1.1   │
        │   1.1.1.2    │               │  forwarding on  │
        │  generator-s │◀══ veth ══════┤ dut-s 2.2.2.1   │
        │   2.2.2.2    │               └─────────────────┘
        └──────────────┘

    The generator's two interfaces stay in the root namespace so its control
    port is on the real loopback, where the Python client can reach it without
    a third namespace to reason about. That is only safe because those
    interfaces carry no IP addresses: the host stack has nothing to answer
    with, so it cannot reply to ARP for the synthetic endpoints or inject TCP
    resets into the generated connections. Per-interface forwarding is also
    switched off there, so a host that happens to have IP forwarding enabled
    globally cannot start routing this traffic behind our back.

THINGS LEARNED THE HARD WAY, ENCODED HERE
    * Receive processing for a virtual ethernet pair runs on whichever CPU sent
      the packet, unless RPS moves it. Without RPS on every interface, the
      kernel's packet work lands on the generator's own core and competes with
      it -- which once made a baseline appear 40% slower than a path doing
      strictly more work.
    * Segmentation offload (GRO in particular) must be off. Netfilter runs
      after GRO, so with it enabled the receiver merges frames into 64 KB
      super-packets that no wire ever carries, and every packet count becomes
      fiction.
    * The queue rule matches on input interface, not on addresses or ports.
      Everything arriving on the client-side link is the client-to-server
      direction by construction. An address match silently excluded the
      generator's ICMP latency stream, which would have made every latency
      number measure plain forwarding.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# --- names and addresses ---------------------------------------------------

INSPECTOR_NS = "pi-bench-dut"

GENERATOR_C, GENERATOR_S = "generator-c", "generator-s"
DUT_C, DUT_S = "dut-c", "dut-s"

# Fixed, locally-administered addresses rather than the random ones the kernel
# would assign, so the generator's configuration is a function of this file
# alone and never of what the last setup happened to produce.
MAC = {
    GENERATOR_C: "02:00:00:00:01:01",
    GENERATOR_S: "02:00:00:00:02:01",
    DUT_C: "02:00:00:00:01:02",
    DUT_S: "02:00:00:00:02:02",
}

DUT_C_IP, DUT_S_IP = "1.1.1.1", "2.2.2.1"
GENERATOR_C_IP, GENERATOR_S_IP = "1.1.1.2", "2.2.2.2"

# The traffic profile draws client addresses from the first range and server
# addresses from the second. The device under test routes both back to the one
# generator address on each side, so it never has to ARP more than twice no
# matter how many synthetic endpoints the profile invents.
CLIENT_NET, SERVER_NET = "16.0.0.0/8", "48.0.0.0/8"

QUEUE_CHAIN = "PIBENCH"   # our own chain, so teardown never has to guess
QUEUE_NUMBER = 100        # not 0, to stay clear of any real deployment

# 512 x 2 MB = 1 GB. The generator allocates its packet buffers from hugepages
# and fails unhelpfully without them.
HUGEPAGES_WANTED = 512


# --- running commands ------------------------------------------------------

def run(*args: str, namespace: str | None = None, check: bool = True,
        quiet: bool = False) -> subprocess.CompletedProcess:
    """Run a command, optionally inside a network namespace."""
    command = list(args)
    if namespace:
        command = ["ip", "netns", "exec", namespace, *command]
    return subprocess.run(
        command, check=check, text=True,
        stdout=subprocess.DEVNULL if quiet else subprocess.PIPE,
        stderr=subprocess.DEVNULL if quiet else subprocess.PIPE)


def run_output(*args: str, namespace: str | None = None) -> str:
    result = run(*args, namespace=namespace, check=False)
    return (result.stdout or "").strip()


# --- dividing the machine --------------------------------------------------

class CpuAllocation:
    """Who gets which CPU, worked out fresh for this machine on every run.

    Never written down anywhere. An assignment is only valid for the CPUs this
    process can actually use, and that changes with the machine, with cpusets
    and inside containers. A constant baked into a file does not fail loudly --
    it keeps producing numbers, just wrong ones.

    Three words that are easy to confuse, and are used precisely here:

      physical core   one of the machine's real cores; usually provides two
                      logical CPUs (hyperthreads)
      logical CPU     what taskset takes, numbered 0..n
      thread          what a program runs

    The layout, on a six-core machine:

        core 0  (cpu 0,1)   generator control + latency -- both light
        core 1  (cpu 2, -)  generator traffic; sibling deliberately idle
        core 2  (cpu 4, -)  second generator traffic thread, if enabled
        core 3  (cpu 6,7)   inspector receive + verdict threads
        core 4  (cpu 8,9)   inspector workers
        core 5  (cpu 10,11) kernel receive processing

    Why it is shaped that way:

      * The generator's traffic threads busy-poll. They never share a physical
        core with anything, including each other -- a contended one does not
        slow down gracefully, it stops producing the requested rate, which
        looks exactly like the software under test being slow.
      * The inspector gets one logical CPU per thread rather than being
        oversubscribed, and its two syscall-heavy infrastructure threads sit on
        a different physical core from its compute-heavy workers.
      * Kernel receive processing gets a physical core of its own rather than
        scavenging the hyperthread siblings of the inspector's cores.
    """

    def __init__(self, workers: int = 4, traffic_threads: int = 1,
                 receive_cores: int = 1) -> None:
        cores = self._physical_cores()
        self.physical_cores = len(cores)
        self.hyperthreaded = len(cores[0]) > 1

        # Threads the inspector runs: the workers, plus one that drains the
        # queue and one that writes verdicts back.
        self.workers = max(1, workers)
        inspector_threads = self.workers + 2
        per_core = len(cores[0])
        inspector_cores = -(-inspector_threads // per_core)  # ceiling division

        needed = 1 + traffic_threads + inspector_cores + receive_cores
        if self.physical_cores < needed:
            sys.exit(
                f"need {needed} physical cores for this layout, found "
                f"{self.physical_cores}.\n"
                f"  1 generator control, {traffic_threads} generator traffic, "
                f"{inspector_cores} inspector, {receive_cores} kernel receive.\n"
                f"  Reduce --workers, --traffic-threads or --receive-cores.")

        index = 0
        self.control_cpu = cores[index][0]
        self.latency_cpu = cores[index][1] if per_core > 1 else cores[index][0]
        index += 1

        # One traffic thread per physical core; the siblings stay unused, and
        # that waste is the point.
        self.traffic_cpus = [cores[index + n][0] for n in range(traffic_threads)]
        self.idle_cpus = [c for n in range(traffic_threads)
                          for c in cores[index + n][1:]]
        index += traffic_threads

        # Every logical CPU of the inspector's cores, one thread each. First
        # core carries the infrastructure threads, the rest carry workers.
        inspector_all: list[int] = []
        for n in range(inspector_cores):
            inspector_all.extend(cores[index + n])
        self.inspector_cpus = inspector_all[:inspector_threads]
        self.idle_cpus += inspector_all[inspector_threads:]
        index += inspector_cores

        # Kernel receive processing. Sized explicitly rather than given the
        # leftovers, because "56% busy" across four logical CPUs is over two
        # CPUs of real work -- a percentage that looks like spare capacity while
        # the total says otherwise. Anything past this stays idle.
        self.receive_cpus = [c for core in cores[index:index + receive_cores]
                             for c in core]
        self.idle_cpus += [c for core in cores[index + receive_cores:] for c in core]
        self.receive_cpu_mask = f"{sum(1 << c for c in self.receive_cpus):x}"

    @staticmethod
    def _physical_cores() -> list[list[int]]:
        """Online CPUs grouped by physical core, lowest core first."""
        groups: dict[tuple[int, ...], None] = {}
        for entry in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*"),
                            key=lambda p: int(p.name[3:])):
            online = entry / "online"
            if online.is_file() and online.read_text().strip() == "0":
                continue
            siblings = entry / "topology" / "thread_siblings_list"
            spec = siblings.read_text().strip() if siblings.is_file() else entry.name[3:]
            groups.setdefault(tuple(sorted(_expand_cpu_list(spec))), None)
        return [list(k) for k in groups]

    def roles(self) -> dict[str, list[int]]:
        """CPU groups by job, for reporting where the machine's time went."""
        return {
            "generator": [self.control_cpu, self.latency_cpu, *self.traffic_cpus],
            "inspector": list(self.inspector_cpus),
            "receive": list(self.receive_cpus),
        }

    def describe(self) -> str:
        kind = "hyperthreaded" if self.hyperthreaded else "no hyperthreading"
        join = lambda v: ",".join(map(str, v))  # noqa: E731
        return "\n".join([
            f"physical cores    : {self.physical_cores} ({kind})",
            f"generator control : cpu {self.control_cpu}",
            f"generator latency : cpu {self.latency_cpu}",
            f"generator traffic : cpu {join(self.traffic_cpus)}"
            f"  ({len(self.traffic_cpus)} thread(s), busy-polling, siblings kept free)",
            f"inspector         : cpu {join(self.inspector_cpus)}"
            f"  ({self.workers} workers + receive + verdict, one per cpu)",
            f"kernel receive    : cpu {join(self.receive_cpus)}"
            f"  (mask 0x{self.receive_cpu_mask})",
            f"deliberately idle : cpu {join(sorted(self.idle_cpus)) or 'none'}",
        ])


# --- where the machine's time actually goes --------------------------------
# Sampled around each data point, because the generator's own CPU figure says
# nothing about the rest of the machine -- and a generator quietly running at
# 97% while the software under test is barely working produces numbers that
# describe the generator.

def cpu_times() -> dict[int, tuple[int, int]]:
    """Per-CPU (busy, total) jiffies from /proc/stat."""
    out: dict[int, tuple[int, int]] = {}
    for line in Path("/proc/stat").read_text().splitlines():
        if not line.startswith("cpu") or line.startswith("cpu "):
            continue
        parts = line.split()
        try:
            cpu = int(parts[0][3:])
        except ValueError:
            continue
        values = [int(v) for v in parts[1:]]
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)  # idle + iowait
        out[cpu] = (total - idle, total)
    return out


def cpu_busy(before: dict, after: dict) -> dict[int, float]:
    """Per-CPU busy percentage between two samples."""
    out: dict[int, float] = {}
    for cpu, (busy_after, total_after) in after.items():
        busy_before, total_before = before.get(cpu, (0, 0))
        span = total_after - total_before
        if span > 0:
            out[cpu] = 100.0 * (busy_after - busy_before) / span
    return out


def _expand_cpu_list(spec: str) -> list[int]:
    """Turn "0-3" or "0,6" into a list of CPU numbers."""
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            low, high = part.split("-")
            out.extend(range(int(low), int(high) + 1))
        else:
            out.append(int(part))
    return out


def hugepage_counts() -> tuple[int, int]:
    info = Path("/proc/meminfo").read_text()

    def field(name: str) -> int:
        found = re.search(rf"{name}:\s+(\d+)", info)
        return int(found.group(1)) if found else 0

    return field("HugePages_Total"), field("HugePages_Free")


def require_hugepages() -> None:
    total, free = hugepage_counts()
    if free < HUGEPAGES_WANTED // 2:
        sys.exit(
            f"hugepages: only {free} free of {total}, not enough for the generator.\n"
            f"  sudo sysctl -w vm.nr_hugepages={HUGEPAGES_WANTED}\n"
            f"  (best done just after a reboot, while memory is unfragmented)")


# --- building the network --------------------------------------------------

def _silence_interface(interface: str, namespace: str | None = None) -> None:
    """No IPv6, no reverse-path filtering, no forwarding on this interface.

    Router advertisements and multicast listener reports are real packets that
    would land in the same counters we are trying to read.
    """
    for key, value in (
        (f"net.ipv6.conf.{interface}.disable_ipv6", "1"),
        (f"net.ipv4.conf.{interface}.rp_filter", "0"),
        (f"net.ipv4.conf.{interface}.accept_redirects", "0"),
        (f"net.ipv4.conf.{interface}.forwarding", "0"),
    ):
        run("sysctl", "-qw", f"{key}={value}",
            namespace=namespace, check=False, quiet=True)


def _disable_offloads(interface: str, namespace: str | None = None) -> None:
    """Turn off the offloads that would merge or split packets.

    Checksum offload is deliberately left alone: virtual ethernet marks frames
    as already-verified internally, and forcing real validation would add a
    cost no physical network card pays without changing any packet count.
    """
    for feature in ("gro", "gso", "tso", "lro", "sg", "rxvlan", "txvlan"):
        run("ethtool", "-K", interface, feature, "off",
            namespace=namespace, check=False, quiet=True)


def _prepare_interface(interface: str, namespace: str | None = None) -> None:
    run("ip", "link", "set", "dev", interface, "address", MAC[interface],
        namespace=namespace)
    _silence_interface(interface, namespace)
    _disable_offloads(interface, namespace)
    # Promiscuous mode is not strictly required, since every frame is addressed
    # to a real destination, but it removes a whole class of "the generator
    # sees nothing" dead ends.
    run("ip", "link", "set", "dev", interface, "promisc", "on", namespace=namespace)
    run("ip", "link", "set", "dev", interface, "up", namespace=namespace)


def _steer_receive_processing(interface: str, mask: str,
                              namespace: str | None = None) -> None:
    """Move this interface's kernel receive work onto the inspector's cores.

    Written through a shell inside the namespace because /sys/class/net is
    per-namespace: an interface living in the inspector's namespace simply does
    not appear under the root namespace's view, and writing there would
    silently do nothing at all.
    """
    run("sh", "-c",
        f"for q in /sys/class/net/{interface}/queues/rx-*; do "
        f"echo {mask} > \"$q/rps_cpus\" 2>/dev/null || true; done",
        namespace=namespace, check=False, quiet=True)


def tear_down() -> None:
    run("ip", "netns", "del", INSPECTOR_NS, check=False, quiet=True)
    for interface in (GENERATOR_C, GENERATOR_S, DUT_C, DUT_S):
        run("ip", "link", "del", interface, check=False, quiet=True)


def build(cpus: CpuAllocation) -> None:
    """Create the namespaces, cables and routes. Always from a clean slate."""
    tear_down()

    run("ip", "netns", "add", INSPECTOR_NS)
    run("ip", "link", "set", "lo", "up", namespace=INSPECTOR_NS)
    for key in ("net.ipv6.conf.all.disable_ipv6",
                "net.ipv6.conf.default.disable_ipv6"):
        run("sysctl", "-qw", f"{key}=1", namespace=INSPECTOR_NS,
            check=False, quiet=True)

    run("ip", "link", "add", GENERATOR_C, "type", "veth", "peer", "name", DUT_C)
    run("ip", "link", "add", GENERATOR_S, "type", "veth", "peer", "name", DUT_S)
    run("ip", "link", "set", DUT_C, "netns", INSPECTOR_NS)
    run("ip", "link", "set", DUT_S, "netns", INSPECTOR_NS)

    _prepare_interface(GENERATOR_C)
    _prepare_interface(GENERATOR_S)
    _prepare_interface(DUT_C, namespace=INSPECTOR_NS)
    _prepare_interface(DUT_S, namespace=INSPECTOR_NS)

    run("ip", "addr", "add", f"{DUT_C_IP}/24", "dev", DUT_C, namespace=INSPECTOR_NS)
    run("ip", "addr", "add", f"{DUT_S_IP}/24", "dev", DUT_S, namespace=INSPECTOR_NS)
    run("sysctl", "-qw", "net.ipv4.ip_forward=1", namespace=INSPECTOR_NS)
    run("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", namespace=INSPECTOR_NS)
    # _silence_interface switched per-interface forwarding off; this namespace
    # is the one place it has to be on.
    for interface in (DUT_C, DUT_S):
        run("sysctl", "-qw", f"net.ipv4.conf.{interface}.forwarding=1",
            namespace=INSPECTOR_NS)

    # Permanent neighbour entries, so no ARP ever happens on the data path and
    # nothing in the measurement depends on whether the generator answered one.
    run("ip", "neigh", "replace", GENERATOR_C_IP, "lladdr", MAC[GENERATOR_C],
        "dev", DUT_C, "nud", "permanent", namespace=INSPECTOR_NS)
    run("ip", "neigh", "replace", GENERATOR_S_IP, "lladdr", MAC[GENERATOR_S],
        "dev", DUT_S, "nud", "permanent", namespace=INSPECTOR_NS)

    run("ip", "route", "add", CLIENT_NET, "via", GENERATOR_C_IP, "dev", DUT_C,
        namespace=INSPECTOR_NS)
    run("ip", "route", "add", SERVER_NET, "via", GENERATOR_S_IP, "dev", DUT_S,
        namespace=INSPECTOR_NS)

    for interface, namespace in ((DUT_C, INSPECTOR_NS), (DUT_S, INSPECTOR_NS),
                                 (GENERATOR_C, None), (GENERATOR_S, None)):
        _steer_receive_processing(interface, cpus.receive_cpu_mask, namespace)


def add_queue_rule() -> None:
    """Send the client-to-server direction to the inspector's queue.

    Matched by input interface. Everything arriving on the client-side link is
    the client-to-server direction by construction -- the only direction that
    carries a hostname and the only one the inspector can act on.

    Two alternatives were tried and are worse. Matching destination ports ties
    the rule to whatever the traffic profile happens to use. Matching connection
    direction needs connection tracking, which the baseline never loads, so
    enabling it would add a per-connection cost the baseline never paid and then
    charge it to the inspector.

    --queue-bypass means packets are accepted when no program is listening,
    matching what the project's own production script does. That also makes
    overload fail open, which is precisely the behaviour worth measuring.
    """
    run("iptables", "-N", QUEUE_CHAIN, namespace=INSPECTOR_NS,
        check=False, quiet=True)
    run("iptables", "-F", QUEUE_CHAIN, namespace=INSPECTOR_NS)
    run("iptables", "-A", QUEUE_CHAIN, "-i", DUT_C, "-j", "NFQUEUE",
        "--queue-num", str(QUEUE_NUMBER), "--queue-bypass",
        namespace=INSPECTOR_NS)
    run("iptables", "-I", "FORWARD", "-j", QUEUE_CHAIN, namespace=INSPECTOR_NS)


def remove_queue_rule() -> None:
    """Take the rule out without rebuilding the network.

    This is what lets both measurement cases share one topology: the baseline
    is the same wiring with this rule absent.
    """
    while run("iptables", "-C", "FORWARD", "-j", QUEUE_CHAIN,
              namespace=INSPECTOR_NS, check=False, quiet=True).returncode == 0:
        run("iptables", "-D", "FORWARD", "-j", QUEUE_CHAIN,
            namespace=INSPECTOR_NS, check=False, quiet=True)
    run("iptables", "-F", QUEUE_CHAIN, namespace=INSPECTOR_NS,
        check=False, quiet=True)
    run("iptables", "-X", QUEUE_CHAIN, namespace=INSPECTOR_NS,
        check=False, quiet=True)


def describe_state(cpus: CpuAllocation) -> str:
    total, free = hugepage_counts()
    lines = [cpus.describe(), f"hugepages        : {free} free of {total}", ""]
    if INSPECTOR_NS not in run_output("ip", "netns", "list"):
        lines.append("network          : not built")
        return "\n".join(lines)

    lines += [
        "--- root namespace ---",
        run_output("ip", "-br", "link", "show", GENERATOR_C) or f"{GENERATOR_C}: absent",
        run_output("ip", "-br", "link", "show", GENERATOR_S) or f"{GENERATOR_S}: absent",
        f"--- {INSPECTOR_NS} ---",
        run_output("ip", "-br", "addr", "show", namespace=INSPECTOR_NS),
        run_output("ip", "route", namespace=INSPECTOR_NS),
        # -L -v -n rather than -S: the per-rule packet counters are the only way
        # to tell a rule that is present from a rule that is actually matching.
        "--- firewall (counters matter, not just presence) ---",
        run_output("iptables", "-L", "-v", "-n", namespace=INSPECTOR_NS) or "(none)",
    ]
    return "\n".join(lines)


def require_root(reason: str) -> None:
    """Re-run this program as root, keeping the interpreter uv chose.

    Elevating here rather than asking the user for `sudo uv run ...` matters:
    that would start uv again as root, against root's own cache, and build a
    second environment -- possibly downloading a second copy of Python -- to run
    the identical program.
    """
    import shutil

    if os.geteuid() == 0:
        return
    if os.environ.get("SUDO_USER"):
        sys.exit(f"must run as root ({reason}), and sudo did not grant it")
    sudo = shutil.which("sudo")
    if not sudo:
        sys.exit(f"must run as root ({reason}); sudo was not found")
    print(f"==> {reason} needs root -- re-running under sudo", file=sys.stderr)
    os.execv(sudo, [sudo, "-E", sys.executable,
                    str(Path(sys.argv[0]).resolve()), *sys.argv[1:]])
