#!/usr/bin/env python3
"""
compare_routing.py

Run with:
    sudo -E python3 compare_routing.py

Requirements:
    1. Matplotlib (can be installed through pip)
    2. Iperf3 (can be installed through apt)
    3. Pandas (can be installed through pip)
    4. Keep this file in the same folder as both controllers and topology

Compares three routing schemes:
    1. Dijkstra (shortest-path) — single path per destination
    2. Two-level routing — suffix-based multi-path (fat-tree paper)
    3. ECMP — 5-tuple hash-based multi-path (bonus)
"""

import os, sys, time, json, csv, signal, subprocess
from pathlib import Path

from mininet.log import setLogLevel
setLogLevel('warning')

CONTROLLER_APPS = {
    "dijkstra":  "sp_routing.py",
    "twolevel":  "ft_routing.py",
    "ecmp":      "ecmp_routing.py"
}

import fat_tree
import topo
from mininet.util import quietRun

RES_FILE = "results.csv"

RYU_CMD = ["ryu-manager", "--observe-links"]

def start_controller(app_path):
    proc = subprocess.Popen(RYU_CMD + [app_path],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    time.sleep(3)        # wait for socket 6653 to open
    return proc

def stop_controller(proc):
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()

# ── measurement helpers ────────────────────────────────────────────────────────

def run_latency(h_src, h_dst, count=10):
    """Measure average RTT (ms) with ping."""
    out = h_src.cmd(f"ping -c {count} {h_dst.IP()}")
    for line in out.splitlines():
        if "rtt min/avg" in line:
            avg_ms = float(line.split('/')[4])
            return round(avg_ms, 3)
    return None

def run_iperf_pair(src, dst, seconds=5):
    """Measure single-flow TCP throughput (Mbps) with iperf3."""
    dst.cmd("pkill -9 iperf3")
    dst.cmd("iperf3 -s -D > /dev/null 2>&1 &")
    time.sleep(1)

    out = src.cmd(f"iperf3 -c {dst.IP()} -t {seconds} -J")
    dst.cmd("pkill -9 iperf3")
    try:
        j = json.loads(out)
        mbits = j["end"]["sum_sent"]["bits_per_second"] / 1e6
        return round(mbits, 2)
    except Exception:
        return 0.0

def run_incast(sources, dst, seconds=5):
    """
    Incast: multiple sources send to one destination simultaneously.
    Measures aggregate throughput (Mbps).
    This stresses path diversity — ECMP/two-level should outperform SP.
    """
    dst.cmd("pkill -9 iperf3")
    ports = [5201 + i for i in range(len(sources))]
    for p in ports:
        dst.cmd(f"iperf3 -s -p {p} -D > /dev/null 2>&1 &")
    time.sleep(1)

    total = 0.0
    popens = []
    for src, port in zip(sources, ports):
        p = src.popen(["iperf3", "-c", dst.IP(), "-p", str(port),
                       "-t", str(seconds), "-J"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        popens.append(p)
    for p in popens:
        out, _ = p.communicate()
        try:
            j = json.loads(out.decode())
            total += j["end"]["sum_sent"]["bits_per_second"] / 1e6
        except Exception:
            pass

    dst.cmd("pkill -9 iperf3")
    return round(total, 2)

def run_stride(hosts, net, seconds=5):
    """
    Stride traffic pattern: h1→h5, h2→h6, h3→h7, h4→h8, ...
    Each host sends to a host k/2 positions away (cross-pod).
    This maximizes path diversity utilization.
    Returns aggregate throughput (Mbps).
    """
    k = 4
    stride = k * k // 4  # stride of k²/4 = 4 for k=4
    num_hosts = len(hosts)

    pairs = []
    for i in range(min(num_hosts, stride)):
        src_name = f"h{i + 1}"
        dst_idx = (i + stride) % num_hosts
        dst_name = f"h{dst_idx + 1}"
        src = net.get(src_name)
        dst = net.get(dst_name)
        if src and dst and src != dst:
            pairs.append((src, dst))

    if not pairs:
        return 0.0

    # Kill any existing iperf3
    for _, dst in pairs:
        dst.cmd("pkill -9 iperf3")

    # Start iperf3 servers
    port_base = 5201
    for idx, (_, dst) in enumerate(pairs):
        p = port_base + idx
        dst.cmd(f"iperf3 -s -p {p} -D > /dev/null 2>&1 &")
    time.sleep(1)

    # Start iperf3 clients
    total = 0.0
    popens = []
    for idx, (src, dst) in enumerate(pairs):
        p = port_base + idx
        proc = src.popen(["iperf3", "-c", dst.IP(), "-p", str(p),
                          "-t", str(seconds), "-J"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        popens.append(proc)

    for proc in popens:
        out, _ = proc.communicate()
        try:
            j = json.loads(out.decode())
            total += j["end"]["sum_sent"]["bits_per_second"] / 1e6
        except Exception:
            pass

    for _, dst in pairs:
        dst.cmd("pkill -9 iperf3")

    return round(total, 2)


# ── run one scheme ─────────────────────────────────────────────────────────────
def run_scheme(name, app_path):
    ctrl = start_controller(app_path)

    ft = topo.Fattree(4)
    net = fat_tree.make_mininet_instance(ft)
    net.start()
    time.sleep(5)  # let topology + table-miss rules get created

    h1, h2, h5, h9, h13 = net.get('h1', 'h2', 'h5', 'h9', 'h13')

    all_hosts = [net.get(f'h{i}') for i in range(1, 17)]

    res = {
        "scheme": name,
        "latency_same_switch_ms": run_latency(h1, h2),
        "latency_cross_pod_ms":  run_latency(h1, h9),
        "throughput_single_mbps": run_iperf_pair(h1, h9),
        "throughput_incast_mbps": run_incast([h1, h5, h13], h9),
        "throughput_stride_mbps": run_stride(all_hosts, net)
    }

    net.stop()
    stop_controller(ctrl)
    return res


def main():
    fieldnames = ["scheme",
                  "latency_same_switch_ms",
                  "latency_cross_pod_ms",
                  "throughput_single_mbps",
                  "throughput_incast_mbps",
                  "throughput_stride_mbps"]

    rows = []
    for name, app in CONTROLLER_APPS.items():
        print(f"\n{'='*50}")
        print(f"  Running {name} routing scheme...")
        print(f"{'='*50}")
        rows.append(run_scheme(name, app))

    # write to CSV
    with open(RES_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n{'='*50}")
    print("  RESULTS")
    print(f"{'='*50}")
    for r in rows:
        print(f"\n  {r['scheme'].upper()}:")
        for k, v in r.items():
            if k != 'scheme':
                print(f"    {k}: {v}")
    print(f"\nSaved to {RES_FILE}")

    # ── Generate plots ──
    try:
        import pandas as pd
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        df = pd.read_csv(RES_FILE).set_index("scheme")

        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        fig.suptitle("Fat-Tree Routing Scheme Comparison (k=4)",
                     fontsize=16, fontweight='bold')

        colors = ['#2196F3', '#4CAF50', '#FF9800']

        # Latency comparison
        lat_cols = ["latency_same_switch_ms", "latency_cross_pod_ms"]
        df[lat_cols].plot(kind='bar', ax=axes[0, 0], color=colors[:2],
                         edgecolor='black', linewidth=0.5)
        axes[0, 0].set_title("Latency (ms)", fontweight='bold')
        axes[0, 0].set_ylabel("RTT (ms)")
        axes[0, 0].legend(["Same Switch", "Cross Pod"], fontsize=8)
        axes[0, 0].tick_params(axis='x', rotation=0)

        # Single flow throughput
        df[["throughput_single_mbps"]].plot(kind='bar', ax=axes[0, 1],
                                            color=colors[0],
                                            edgecolor='black', linewidth=0.5,
                                            legend=False)
        axes[0, 1].set_title("Single Flow Throughput (Mbps)", fontweight='bold')
        axes[0, 1].set_ylabel("Mbps")
        axes[0, 1].tick_params(axis='x', rotation=0)

        # Incast throughput
        df[["throughput_incast_mbps"]].plot(kind='bar', ax=axes[1, 0],
                                            color=colors[1],
                                            edgecolor='black', linewidth=0.5,
                                            legend=False)
        axes[1, 0].set_title("Incast Throughput (3→1, Mbps)", fontweight='bold')
        axes[1, 0].set_ylabel("Mbps")
        axes[1, 0].tick_params(axis='x', rotation=0)

        # Stride throughput
        df[["throughput_stride_mbps"]].plot(kind='bar', ax=axes[1, 1],
                                            color=colors[2],
                                            edgecolor='black', linewidth=0.5,
                                            legend=False)
        axes[1, 1].set_title("Stride Throughput (Mbps)", fontweight='bold')
        axes[1, 1].set_ylabel("Mbps")
        axes[1, 1].tick_params(axis='x', rotation=0)

        plt.tight_layout()
        plt.savefig("comparison.png", dpi=150, bbox_inches='tight')
        print("Saved comparison.png")

        # Also create a summary bar chart
        fig2, ax2 = plt.subplots(figsize=(10, 6))
        throughput_cols = ["throughput_single_mbps", "throughput_incast_mbps",
                          "throughput_stride_mbps"]
        df[throughput_cols].plot(kind='bar', ax=ax2, color=colors,
                                edgecolor='black', linewidth=0.5)
        ax2.set_title("Throughput Comparison Across Routing Schemes",
                      fontsize=14, fontweight='bold')
        ax2.set_ylabel("Throughput (Mbps)")
        ax2.legend(["Single Flow", "Incast (3→1)", "Stride"],
                   fontsize=10)
        ax2.tick_params(axis='x', rotation=0)
        plt.tight_layout()
        plt.savefig("throughput_comparison.png", dpi=150, bbox_inches='tight')
        print("Saved throughput_comparison.png")

    except Exception as e:
        print(f"Warning: Could not generate plots: {e}")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Re-executing with sudo")
        os.execvp("sudo", ["sudo", "-E"] + sys.argv)
    main()
