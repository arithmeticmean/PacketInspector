#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.13"
# dependencies = []
# ///
"""Measure what PacketInspector costs: throughput lost and latency added.

WHAT THIS PROGRAM DOES
    Runs the same traffic through the same virtual network twice:

        baseline   packets forwarded normally, inspector absent
        inspected  identical path, plus the packet queue and PacketInspector
                   with a blocklist

    The difference between the two is the answer. Because the wiring, the cores
    and the traffic are identical, anything that changes belongs to the
    inspector and nothing else.

WHAT YOU GET
    Per offered rate: connections per second, gigabits per second, packets per
    second, round-trip latency at the median and 99th percentile, how much
    latency the inspector added, how many packets the kernel had to drop, and
    what share of connections completed.

    That last one is the correctness signal. The traffic aims a known fraction
    of connections at a hostname on the blocklist, so while blocking works the
    completed share sits at the allowed fraction. If it climbs toward 100% as
    load rises, connections that should have been blocked are getting through --
    the queue is overflowing and packets are being accepted uninspected.

RUNNING IT
    uv run main.py run                      both cases, default rates
    uv run main.py run --block-packet-ratio 0.2
    uv run main.py run -m 200 400 600 -d 20 -r 3
    uv run main.py status                   show the machine split and network
    uv run main.py down                     tear the network down

    uv is the entire setup step: the header above pins the interpreter and uv
    supplies one, with nothing to install. Commands needing root re-run
    themselves under sudo with that same interpreter, so no `sudo` prefix is
    wanted -- adding one starts a second uv as root for no reason.

    The one thing not handled automatically is the traffic generator itself:
    unpack TRex beside this program and reserve hugepages. Both are printed
    with exact commands if they are missing.

WHAT THESE NUMBERS ARE NOT
    The generator and the software under test share one processor package, one
    memory controller and one cache. These are regression-grade figures -- good
    for "did this change make it slower" -- not absolute capacity claims.
"""

from __future__ import annotations

import argparse
import csv
import json
import shlex
import statistics
import sys
from datetime import datetime
from pathlib import Path

import network_topology as net
import packet_inspector as inspector
import traffic_generator as generator
from tls_traffic_profile import ALLOWED_GROUP, BLOCKED_GROUP

HERE = Path(__file__).resolve().parent

CASES = ("baseline", "inspected")

CSV_COLUMNS = [
    "case", "multiplier", "run",
    "connections_per_sec", "gbps_sent", "gbps_received", "packets_per_sec",
    "active_connections", "connections_attempted", "connections_established",
    "established_pct", "generator_cpu_pct", "generator_tx_ratio",
    "latency_p50_us", "latency_p99_us", "latency_max_us", "latency_errors",
    "queued", "queue_depth", "kernel_drops", "userspace_drops",
    "inspector_running", "elapsed_s",
    # Per template group: what happened to each kind of connection separately.
    "allowed_attempted", "allowed_established", "allowed_rcvbyte",
    "allowed_bytes_per_conn",
    "blocked_attempted", "blocked_established", "blocked_rcvbyte",
    "blocked_bytes_per_conn",
    # Where the machine's time went, grouped by what each CPU was reserved for.
    "cpu_generator_pct", "cpu_generator_max_pct",
    "cpu_inspector_pct", "cpu_inspector_max_pct",
    "cpu_receive_pct", "cpu_receive_max_pct", "cpu_busiest",
]

TRAFFIC_GROUPS = [ALLOWED_GROUP, BLOCKED_GROUP]


# --- one sweep -------------------------------------------------------------

def sweep(case: str, args, cpus: net.CpuAllocation, profile: Path,
          output_dir: Path) -> list[dict]:
    """Run every rate for one case and return a row per repetition."""
    import contextlib

    config = output_dir / "trex_config.yaml"
    generator.write_configuration(cpus, config)

    rows: list[dict] = []
    with contextlib.ExitStack() as stack:
        running_inspector = None
        if case == "inspected":
            net.add_queue_rule()
            running_inspector = stack.enter_context(
                inspector.PacketInspectorProcess(
                    cpus, output_dir,
                    blocking=args.block_packet_ratio > 0,
                    queue_length=args.queue_length,
                    max_blocked=args.max_blocked))

        engine = stack.enter_context(
            generator.TrexEngine(config, cpus, output_dir / "trex-engine.log"))
        client = engine.client()
        client.connect()
        try:
            client.reset()
            client.load_profile(str(profile), tunables=profile_tunables(args))
            for multiplier in args.multipliers:
                for repetition in range(1, args.repeats + 1):
                    print(f"  m={multiplier:<7g} run {repetition}/{args.repeats} ... ",
                          end="", flush=True)
                    row = _one_point(client, args, case, multiplier, repetition,
                                     running_inspector, output_dir, cpus)
                    if row is None:
                        return rows
                    rows.append(row)
        finally:
            try:
                client.disconnect()
            except Exception:  # noqa: BLE001 - already unwinding
                pass

    if case == "inspected":
        net.remove_queue_rule()
    return rows


def _one_point(client, args, case: str, multiplier: float, repetition: int,
               running_inspector, output_dir: Path,
               cpus: net.CpuAllocation) -> dict | None:
    before = inspector.read_queue_counters() if running_inspector else None

    summary, raw = generator.measure_one_point(
        client, multiplier, args.duration, args.latency_pps,
        sample_queue=(lambda: inspector.read_queue_counters()["depth"])
        if running_inspector else None,
        groups=TRAFFIC_GROUPS, cpus=cpus)

    row = {"case": case, "multiplier": multiplier, "run": repetition, **summary}

    if running_inspector and before is not None:
        after = inspector.read_queue_counters()
        # Differences, not totals: the counters run for the life of the queue,
        # so only the change belongs to this data point. Depth is excluded --
        # it is an instantaneous reading, already sampled mid-run above.
        for name in ("queued", "kernel_drops", "userspace_drops"):
            row[name] = after[name] - before[name]
        row["inspector_running"] = running_inspector.running()

        # Stop on the first point rather than after the whole sweep. A run
        # where nothing reaches the queue still produces a full set of
        # believable numbers -- they are just the baseline's.
        if row["queued"] == 0:
            print("\n\nno packets reached the queue: the inspector is not in the "
                  "traffic path.\n"
                  f"  sudo ip netns exec {net.INSPECTOR_NS} iptables -L -v -n\n"
                  "  zero on the FORWARD jump means traffic is not being forwarded;\n"
                  "  packets on the jump but zero on the queue rule means the match "
                  "is wrong.\n"
                  f"  inspector log: {running_inspector.log}")
            return None

    (output_dir / f"{case}-m{multiplier:g}-run{repetition}.json").write_text(
        json.dumps(raw, indent=2, default=str))

    print(_progress_line(row))
    return row


def _progress_line(row: dict) -> str:
    parts = [f"cps={_fmt(row['connections_per_sec']):>9}",
             f"{_fmt(row['gbps_sent']):>5} Gbps",
             f"p50/p99={_fmt(row['latency_p50_us'])}/{_fmt(row['latency_p99_us'])}us",
             f"blk_rx={_fmt(row.get('blocked_bytes_per_conn'), 0)}B",
             f"cpu g/i/r={_fmt(row.get('cpu_generator_pct'), 0)}"
             f"/{_fmt(row.get('cpu_inspector_pct'), 0)}"
             f"/{_fmt(row.get('cpu_receive_pct'), 0)}%"]
    if row.get("kernel_drops") is not None:
        parts.append(f"drops={row['kernel_drops']}")
        if not row.get("inspector_running", True):
            parts.append("INSPECTOR DEAD")
    return "  ".join(parts)


def profile_tunables(args) -> dict:
    """Profile arguments, as the mapping TRex's loader expects.

    Not a list: the loader expands this with ** into keyword arguments and then
    builds a command-line flag from each key, so `block_packet_ratio` reaches
    the profile as --block_packet_ratio with an underscore. That is why the
    profile accepts both spellings.
    """
    tunables: dict = {}
    for item in shlex.split(args.tunables):
        if "=" not in item:
            sys.exit(f"--tunables entries must be key=value, got {item!r}")
        key, value = item.split("=", 1)
        tunables[key.lstrip("-").replace("-", "_")] = value
    tunables["block_packet_ratio"] = args.block_packet_ratio
    return tunables


# --- reporting -------------------------------------------------------------

def _fmt(value, places: int = 2) -> str:
    if value is None:
        return "-"
    return f"{value:.{places}f}" if isinstance(value, float) else str(value)


def _average(rows: list[dict], column: str):
    values = [float(r[column]) for r in rows
              if r.get(column) not in (None, "", "None")]
    return statistics.mean(values) if values else None


def report(rows: list[dict], warmup: int = 1) -> str:
    """Print baseline against inspected, with the difference between them."""
    by_case: dict[str, dict[float, list[dict]]] = {c: {} for c in CASES}
    for row in rows:
        by_case.setdefault(row["case"], {}).setdefault(
            float(row["multiplier"]), []).append(row)

    # The first repetition of each rate is warm-up and is discarded: the first
    # run at a new rate pays for caches and buffers the later ones inherit.
    for case in by_case:
        for rate in by_case[case]:
            kept = by_case[case][rate][warmup:]
            by_case[case][rate] = kept or by_case[case][rate]

    rates = sorted(set(by_case.get("baseline", {})) & set(by_case.get("inspected", {})))
    if not rates:
        return "not enough data to compare the two cases"

    out = []
    out.append("THROUGHPUT")
    out.append(f"{'rate':>6} | {'baseline':>9} {'inspected':>9} {'kept':>6} | "
               f"{'base Gbps':>9} {'insp Gbps':>9} | {'insp pps':>9}")
    out.append("-" * 72)
    for rate in rates:
        base, insp = by_case["baseline"][rate], by_case["inspected"][rate]
        b_cps, i_cps = _average(base, "connections_per_sec"), _average(insp, "connections_per_sec")
        kept = (100.0 * i_cps / b_cps) if (b_cps and i_cps) else None
        out.append(f"{rate:>6.0f} | {_fmt(b_cps, 0):>9} {_fmt(i_cps, 0):>9} "
                   f"{_fmt(kept, 1):>5}% | {_fmt(_average(base, 'gbps_sent'), 3):>9} "
                   f"{_fmt(_average(insp, 'gbps_sent'), 3):>9} | "
                   f"{_fmt(_average(insp, 'packets_per_sec'), 0):>9}")

    out.append("")
    out.append("LATENCY, microseconds, measured under load")
    out.append(f"{'rate':>6} | {'base p50':>8} {'insp p50':>8} {'added':>7} | "
               f"{'base p99':>8} {'insp p99':>8} {'added':>8} | {'insp max':>8}")
    out.append("-" * 78)
    for rate in rates:
        base, insp = by_case["baseline"][rate], by_case["inspected"][rate]
        b50, i50 = _average(base, "latency_p50_us"), _average(insp, "latency_p50_us")
        b99, i99 = _average(base, "latency_p99_us"), _average(insp, "latency_p99_us")
        add50 = (i50 - b50) if (b50 is not None and i50 is not None) else None
        add99 = (i99 - b99) if (b99 is not None and i99 is not None) else None
        out.append(f"{rate:>6.0f} | {_fmt(b50, 0):>8} {_fmt(i50, 0):>8} {_fmt(add50, 0):>7} | "
                   f"{_fmt(b99, 0):>8} {_fmt(i99, 0):>8} {_fmt(add99, 0):>8} | "
                   f"{_fmt(_average(insp, 'latency_max_us'), 0):>8}")

    out.append("")
    out.append("BLOCKING, from per-template-group counters")
    out.append(f"{'rate':>6} | {'allowed rx':>11} {'blocked rx':>11} | "
               f"{'blocked conns':>13} | verdict")
    out.append("-" * 74)
    for rate in rates:
        insp = by_case["inspected"][rate]
        allowed_rx = _average(insp, "allowed_bytes_per_conn")
        blocked_rx = _average(insp, "blocked_bytes_per_conn")
        blocked_n = _average(insp, "blocked_attempted")
        if blocked_rx is None or blocked_n in (None, 0):
            verdict = "no blocked traffic sent"
        elif blocked_rx < 50:
            verdict = "blocked"
        elif allowed_rx and blocked_rx > 0.5 * allowed_rx:
            verdict = "LEAKING -- blocked hostnames completing"
        else:
            verdict = f"partially leaking ({100 * blocked_rx / (allowed_rx or 1):.0f}%)"
        out.append(f"{rate:>6.0f} | {_fmt(allowed_rx, 0):>10}B {_fmt(blocked_rx, 0):>10}B | "
                   f"{_fmt(blocked_n, 0):>13} | {verdict}")

    out.append("")
    out.append("Server bytes received per attempted connection. The server sends 1400")
    out.append("bytes to anyone it hears from, so the allowed column should sit near")
    out.append("1400 and the blocked column near 0. Blocking happens at the")
    out.append("ClientHello, after the TCP handshake, so a blocked connection still")
    out.append("establishes -- only the missing reply distinguishes it.")
    out.append("")

    out.append("WHERE THE MACHINE'S TIME WENT, percent busy per reserved group")
    out.append(f"{'rate':>6} | {'generator':>19} | {'inspector':>19} | {'kernel recv':>19}")
    out.append(f"{'':>6} | {'base':>9} {'insp':>9} | {'base':>9} {'insp':>9} | "
               f"{'base':>9} {'insp':>9}")
    out.append("-" * 74)
    for rate in rates:
        base, insp = by_case["baseline"][rate], by_case["inspected"][rate]
        cells = []
        for column in ("cpu_generator_pct", "cpu_inspector_pct", "cpu_receive_pct"):
            cells.append(f"{_fmt(_average(base, column), 0):>9} "
                         f"{_fmt(_average(insp, column), 0):>9}")
        out.append(f"{rate:>6.0f} | " + " | ".join(cells))
    out.append("")
    out.append("A generator near 100% means the offered load is capped by the")
    out.append("generator, not by the software under test -- the numbers at that")
    out.append("rate describe TRex. Read this before any capacity claim.")
    out.append("")

    out.append("QUEUE HEALTH")
    out.append(f"{'rate':>6} | {'queued':>11} {'dropped':>11} {'drop share':>10} | verdict")
    out.append("-" * 74)
    for rate in rates:
        insp = by_case["inspected"][rate]
        queued = _average(insp, "queued") or 0
        dropped = _average(insp, "kernel_drops") or 0
        share = (100.0 * dropped / (queued + dropped)) if (queued + dropped) else 0.0
        verdict = "ok" if dropped == 0 else "packets accepted uninspected"
        out.append(f"{rate:>6.0f} | {queued:>11.0f} {dropped:>11.0f} {share:>9.1f}% | {verdict}")
    return "\n".join(out)


# --- commands --------------------------------------------------------------

def command_run(args) -> None:
    net.require_root("network namespaces, hugepages and raw packet access")
    cpus = net.CpuAllocation(workers=args.workers,
                             traffic_threads=args.traffic_threads,
                             receive_cores=args.receive_cores)
    net.require_hugepages()
    trex_dir = generator.trex_directory()

    profile = next((p for p in (Path(args.profile), HERE / args.profile,
                                trex_dir / args.profile) if p.is_file()), None)
    if profile is None:
        sys.exit(f"traffic profile not found: {args.profile}")

    if not 0.0 <= args.block_packet_ratio <= 1.0:
        sys.exit("--block-packet-ratio must be between 0.0 and 1.0")

    output_dir = Path(args.out) if args.out else (
        HERE / "results" / datetime.now().strftime("%Y%m%d-%H%M%S"))
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"==> building the network")
    net.build(cpus)
    _write_environment(output_dir, args, cpus, trex_dir, profile)

    print(f"    profile: {profile.name}, "
          f"{args.block_packet_ratio:.0%} of connections aimed at a blocked hostname")
    print(f"    rates:   {args.multipliers}, {args.duration}s x {args.repeats}")
    print(f"    output:  {output_dir}\n")

    rows: list[dict] = []
    for case in CASES:
        print(f"==> {case}")
        rows += sweep(case, args, cpus, profile, output_dir)
        print()

    results = output_dir / "results.csv"
    with results.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS,
                                extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    text = report(rows)
    (output_dir / "report.txt").write_text(text + "\n")
    _hand_back(output_dir)

    print(text)
    print(f"\nrows: {results}")


def _write_environment(output_dir: Path, args, cpus, trex_dir, profile) -> None:
    """Record the machine state. A number without it cannot be compared later."""
    total, free = net.hugepage_counts()
    governor = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    import os
    (output_dir / "environment.txt").write_text("\n".join([
        f"date          : {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"kernel        : {os.uname().release}",
        f"generator     : {trex_dir}",
        f"profile       : {profile}",
        f"block ratio   : {args.block_packet_ratio}",
        f"queue length  : {args.queue_length}",
        f"max blocked   : {args.max_blocked or 'derived'}",
        f"python        : {sys.executable} ({sys.version.split()[0]})",
        f"duration      : {args.duration}s x {args.repeats} runs",
        f"cpu governor  : {governor.read_text().strip() if governor.is_file() else 'unknown'}",
        f"hugepages     : {total} total, {free} free",
        f"load average  : {os.getloadavg()}",
        "",
        cpus.describe(),
    ]) + "\n")


def _hand_back(path: Path) -> None:
    """Give the results back to whoever invoked sudo.

    Everything here is created by the re-executed root process, so without this
    you would need root to read or delete your own output.
    """
    import os
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or not gid:
        return
    for item in [path.parent, path, *path.rglob("*")]:
        try:
            os.chown(item, int(uid), int(gid))
        except OSError:
            pass


def main() -> None:
    doc = __doc__ or ""
    parser = argparse.ArgumentParser(
        description=doc.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=doc)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("cpus", help="show how this machine would be divided"
                   ).set_defaults(handler=lambda a: print(net.CpuAllocation().describe()))
    sub.add_parser("status", help="show the machine split and the network"
                   ).set_defaults(handler=lambda a: print(
                       net.describe_state(net.CpuAllocation())))
    sub.add_parser("down", help="tear the network down").set_defaults(
        handler=lambda a: (net.require_root("network namespaces"),
                           net.tear_down(), print("network removed")))
    sub.add_parser("up", help="build the network and leave it up").set_defaults(
        handler=lambda a: (net.require_root("network namespaces"),
                           net.build(net.CpuAllocation()), print("network built")))

    run = sub.add_parser("run", help="measure both cases and report the difference")
    run.add_argument("-m", "--multipliers", type=float, nargs="+",
                     default=[200, 400, 600, 800, 1000],
                     help="offered traffic rates to sweep")
    run.add_argument("-d", "--duration", type=float, default=20,
                     help="seconds of traffic per data point")
    run.add_argument("-r", "--repeats", type=int, default=3,
                     help="repetitions per rate; the first is warm-up")
    run.add_argument("--block-packet-ratio", type=float, default=0.2,
                     help="fraction of connections aimed at a blocked hostname, "
                          "0.0 to 1.0 (default 0.2)")
    run.add_argument("-p", "--profile", default="tls_traffic_profile.py",
                     help="traffic profile to load")
    run.add_argument("-t", "--tunables", default="",
                     help='further profile settings: -t "key=value key2=value2"')
    run.add_argument("--queue-length", type=int, default=16000,
                     help="packets the kernel holds for the inspector before "
                          "discarding (default 16000; the inspector's own "
                          "default is 8192)")
    run.add_argument("--workers", type=int, default=4,
                     help="inspector reassembly workers; it also runs a receive "
                          "and a verdict thread, one logical cpu each (default 2)")
    run.add_argument("--traffic-threads", type=int, default=1,
                     help="generator traffic threads, each on its own physical "
                          "core (default 1; more needs multi-queue support)")
    run.add_argument("--receive-cores", type=int, default=1,
                     help="physical cores for kernel receive processing "
                          "(default 1; watch cpu_receive_max_pct for saturation)")
    run.add_argument("--max-blocked", type=int, default=0,
                     help="blocked flows the inspector remembers per worker; "
                          "0 lets it derive one (a quarter of its flow cap). "
                          "Pure speed dial -- blocking is correct at any size")
    run.add_argument("--latency-pps", type=int, default=1000,
                     help="rate of the latency measurement stream; 0 disables")
    run.add_argument("-o", "--out", help="output directory")
    run.set_defaults(handler=command_run)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
