"""Running PacketInspector under test, and reading the kernel's queue counters.

WHAT THIS FILE IS
    The software being measured, plus the one set of numbers only the kernel
    can supply.

WHAT IT STARTS
    The inspector binary this project builds, running inside the test
    namespace, pinned to the cores the machine allocation reserved for it, and
    bound to the packet queue the firewall rule feeds.

WHY THE KERNEL'S COUNTERS MATTER MORE THAN THE GENERATOR'S
    The generator can only tell you what it offered and what came back. Only
    the kernel knows how many packets it had to throw away because the program
    reading the queue could not keep up. And because the firewall rule accepts
    packets when the queue is full, a dropped packet is not merely lost
    throughput -- it is a connection travelling on uninspected, with its
    hostname never checked. For software whose whole job is blocking hostnames,
    that is the number that decides whether it is working.

A FAILURE THAT LOOKS LIKE SUCCESS
    Packet queues are per network namespace. A program can start cleanly, print
    a healthy banner and bind a queue in the wrong namespace, where no traffic
    will ever arrive. The firewall rule then finds nobody listening, accepts
    everything, and the benchmark produces a full set of plausible numbers that
    are really the baseline's. This file therefore refuses to proceed unless
    the queue actually appears in the namespace holding the rule.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import network_topology as net
from tls_traffic_profile import BLOCKED_HOSTNAME

HERE = Path(__file__).resolve().parent

# Built by this project's own CMake, one directory up. Deliberately not built
# here: if it is missing you wanted `cmake --build build`, and quietly building
# it would hide which binary the numbers came from.
INSPECTOR_BINARY = HERE.parent / "build" / "PacketInspector"

QUEUE_STATS_FILE = "/proc/net/netfilter/nfnetlink_queue"


def read_queue_counters() -> dict:
    """Kernel-side counters for our queue, read inside the test namespace.

    The kernel prints, per queue:

        number  peer_id  depth  copy_mode  copy_range  \\
        kernel_drops  userspace_drops  sequence  1

    `depth` is how many packets are sitting in the queue *right now*, not a
    running total -- a program that keeps up holds it at zero, so it reads as
    zero exactly when everything is working. The cumulative count is the
    sequence number, which increments once per packet queued. Getting these two
    the wrong way round makes a working setup look like a broken one.
    """
    text = net.run_output("cat", QUEUE_STATS_FILE, namespace=net.INSPECTOR_NS)
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 9 and fields[0] == str(net.QUEUE_NUMBER):
            return {
                "queued": int(fields[7]),            # cumulative
                "depth": int(fields[2]),             # instantaneous
                "kernel_drops": int(fields[5]),      # queue was full
                "userspace_drops": int(fields[6]),   # reader too slow
                "bound": True,
            }
    # No line at all means nothing is bound to the queue. Distinct from a line
    # of zeroes, which means bound but idle -- worth never conflating.
    return {"queued": 0, "depth": 0, "kernel_drops": 0,
            "userspace_drops": 0, "bound": False}


class PacketInspectorProcess:
    """The inspector as a context manager: starts on entry, stops on exit."""

    def __init__(self, cpus: net.CpuAllocation, output_dir: Path,
                 blocking: bool, queue_length: int = 16000,
                 max_blocked: int = 0) -> None:
        self.cpus = cpus
        self.output_dir = output_dir
        self.blocking = blocking
        # How many packets the kernel will hold for the inspector before it
        # starts discarding them; the inspector's own default is 8192.
        #
        # Deeper absorbs bigger bursts but is not a cure for sustained overload:
        # it delays the onset and turns dropped packets into very late ones. At
        # roughly a quarter of a million packets a second, 16000 packets is
        # about 64 ms of buffering, which is already the same order as a TCP
        # retransmit timeout -- so expect the tail latency to pay for it.
        self.queue_length = queue_length
        # Ceiling on remembered blocked flows, per worker. 0 leaves the
        # inspector to derive it from its flow cap.
        #
        # Worth sweeping: the security property depends only on there *being* a
        # bound, never on its size, so this is a pure speed/memory dial. Too
        # small and every retransmitted ClientHello is re-tracked, reassembled
        # and re-parsed instead of being dropped on one hash hit.
        self.max_blocked = max_blocked
        self.log = output_dir / "inspector.log"
        self.process: subprocess.Popen | None = None

    def __enter__(self) -> "PacketInspectorProcess":
        if not INSPECTOR_BINARY.is_file():
            sys.exit(f"the inspector is not built: {INSPECTOR_BINARY}\n"
                     f"  cmake -B build && cmake --build build")

        # The blocklist is never empty. When blocking is off it holds entries
        # that cannot match anything the traffic profile sends, so the lookup
        # still happens on every resolved connection but never succeeds. That
        # way the difference between the two cases is the cost of *blocking*,
        # not the cost of having a blocklist at all.
        blocklist = self.output_dir / "blocklist.txt"
        entries = ["# generated by packet_inspector.py",
                   "never-matches.bench.invalid",
                   "*.never-matches.bench.invalid"]
        if self.blocking:
            entries.append(BLOCKED_HOSTNAME)
        blocklist.write_text("\n".join(entries) + "\n")

        cpu_list = ",".join(map(str, self.cpus.inspector_cpus))
        # One thread per reserved logical CPU: the workers plus the two
        # infrastructure threads. The allocation already sized the CPU list for
        # exactly this, so the inspector is never oversubscribed against itself.
        threads = len(self.cpus.inspector_cpus)

        self.log_handle = self.log.open("w")
        self.process = subprocess.Popen(
            ["ip", "netns", "exec", net.INSPECTOR_NS,
             "taskset", "-c", cpu_list, str(INSPECTOR_BINARY),
             "-nfq", str(net.QUEUE_NUMBER), "-nfq-size", str(self.queue_length),
             "-j", str(threads), "-b", str(blocklist), "--stats", "5",
             *(["-max-blocked", str(self.max_blocked)] if self.max_blocked else [])],
            stdout=self.log_handle, stderr=subprocess.STDOUT,
            start_new_session=True)

        # It binds the queue while starting up. Traffic sent before that is
        # accepted uninspected and would silently not be measured.
        time.sleep(2)
        if not self.running():
            sys.exit(f"the inspector exited immediately. log: {self.log}")
        self._require_queue_bound()

        print(f"    inspector: pid {self.process.pid}, cpus {cpu_list}, "
              f"{threads} threads, queue length {self.queue_length}, "
              f"max blocked {self.max_blocked or 'derived'}, "
              f"{'blocking' if self.blocking else 'no blocklist matches'}, "
              f"queue {net.QUEUE_NUMBER} bound")
        return self

    def __exit__(self, *exc) -> None:
        if self.process and self.process.poll() is None:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=15)
            except (ProcessLookupError, PermissionError):
                pass
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.log_handle.close()

    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def _require_queue_bound(self) -> None:
        """Refuse to measure if the queue was bound somewhere else.

        A running process that printed its banner has not necessarily bound the
        queue where the traffic is. See this file's header for why that failure
        is worse than a crash.
        """
        if read_queue_counters()["bound"]:
            return
        assert self.process is not None
        ours = os.readlink(f"/proc/{self.process.pid}/ns/net")
        theirs = net.run_output("readlink", "/proc/self/ns/net",
                                namespace=net.INSPECTOR_NS)
        sys.exit(
            f"the inspector is running but queue {net.QUEUE_NUMBER} is not bound\n"
            f"in {net.INSPECTOR_NS}, so no traffic would ever reach it.\n"
            f"  inspector namespace: {ours}\n"
            f"  expected namespace : {theirs}\n"
            f"  (the same value means the bind failed; different values mean it\n"
            f"   started in the wrong namespace)\n"
            f"  log: {self.log}")
