#!/usr/bin/env python3
"""
Performance comparison experiment for Lab2.
Usage inside Mininet CLI:
  mininet> py exec(open('measure.py').read(), globals())
  mininet> py run_experiment(net, 'SP')   # or 'FT'

IMPORTANT: Run on a fresh Mininet session for each scheme.
Do NOT run pingall before this — let the experiment trigger flow installation.
"""

import time, re

def iperf_single(net, src_name, dst_name, duration=15):
    """Single iperf flow, returns Mbps."""
    dst = net.get(dst_name)
    src = net.get(src_name)
    dst.cmd('pkill -9 -f iperf 2>/dev/null; sleep 0.3')
    dst.cmd('iperf -s -D')
    time.sleep(1.0)
    result = src.cmd(f'iperf -c {dst.IP()} -t {duration} -f m')
    dst.cmd('pkill -9 -f iperf 2>/dev/null')
    m = re.search(r'(\d+\.?\d*)\s+Mbits/sec', result)
    return float(m.group(1)) if m else None

def iperf_parallel(net, pairs, duration=15):
    """Run iperf flows simultaneously, returns list of Mbps."""
    for src_name, dst_name in pairs:
        net.get(dst_name).cmd('pkill -9 -f iperf 2>/dev/null')
        net.get(src_name).cmd('pkill -9 -f iperf 2>/dev/null')
    time.sleep(0.5)

    for src_name, dst_name in pairs:
        net.get(dst_name).cmd('iperf -s -D')
    time.sleep(2.0)

    srcs = [net.get(s) for s, _ in pairs]
    dsts = [net.get(d) for _, d in pairs]
    for src, dst in zip(srcs, dsts):
        src.sendCmd(f'iperf -c {dst.IP()} -t {duration} -f m')
    outputs = [src.waitOutput() for src in srcs]

    for dst in dsts:
        dst.cmd('pkill -9 -f iperf 2>/dev/null')

    results = []
    for i, out in enumerate(outputs):
        print(f"      [flow {i}]: {out.strip()[-150:]}")
        m = re.search(r'(\d+\.?\d*)\s+Mbits/sec', out)
        results.append(float(m.group(1)) if m else None)
    return results

def ping_rtt(net, src_name, dst_name, count=20):
    time.sleep(1.0)
    src = net.get(src_name)
    dst = net.get(dst_name)
    result = src.cmd(f'ping -c {count} -i 0.5 {dst.IP()}')
    m = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', result)
    return float(m.group(1)) if m else None

def warmup(net, pairs):
    """
    Warm up the network: run a short ping between all test pairs so that
    ARP is resolved and flow entries are installed BEFORE iperf starts.
    """
    print("    Warming up (installing flows via ping)...")
    for src_name, dst_name in pairs:
        src = net.get(src_name)
        dst = net.get(dst_name)
        src.cmd(f'ping -c 3 -i 0.2 {dst.IP()} > /dev/null 2>&1')
    time.sleep(1.0)
    print("    Warmup done.")

def run_experiment(net, scheme_name):
    print(f"\n{'='*50}")
    print(f"  Running experiment: {scheme_name}")
    print(f"{'='*50}")
    results = {}

    all_pairs = [('h10002','h10202'), ('h10003','h10203'),
                 ('h10202','h10002'), ('h10203','h10003')]

    # Warm up ALL test paths so flows are pre-installed
    print("\n  Warming up all test paths...")
    warmup(net, all_pairs)

    # ------------------------------------------------------------------ #
    # Test 1: Single flow throughput (3 trials, take median)             #
    # ------------------------------------------------------------------ #
    print("\n[1] Single flow: 10.0.0.2 -> 10.2.0.2 (3 trials)")
    bws = []
    for t in range(3):
        bw = iperf_single(net, 'h10002', 'h10202', duration=12)
        if bw:
            bws.append(bw)
            print(f"      trial {t+1}: {bw:.2f} Mbps")
        time.sleep(1)
    median = sorted(bws)[len(bws)//2] if bws else None
    results['single_bw'] = median
    print(f"    Median: {median:.2f} Mbps" if median else "    FAILED")
    time.sleep(2)

    # Re-warm before parallel test
    print("\n  Re-warming for parallel test...")
    warmup(net, all_pairs)

    # ------------------------------------------------------------------ #
    # Test 2: Parallel flows (3 trials, take median per flow)            #
    # ------------------------------------------------------------------ #
    print("\n[2] Parallel flows (3 trials):")
    print("    Flow A: 10.0.0.2->10.2.0.2  (host byte 2)")
    print("    Flow B: 10.0.0.3->10.2.0.3  (host byte 3)")
    pairs = [('h10002', 'h10202'), ('h10003', 'h10203')]
    flow_bws = [[], []]
    for t in range(3):
        bws = iperf_parallel(net, pairs, duration=12)
        print(f"      trial {t+1}: A={bws[0]} B={bws[1]} Mbps")
        for i, b in enumerate(bws):
            if b: flow_bws[i].append(b)
        time.sleep(2)

    medA = sorted(flow_bws[0])[len(flow_bws[0])//2] if flow_bws[0] else None
    medB = sorted(flow_bws[1])[len(flow_bws[1])//2] if flow_bws[1] else None
    total = (medA or 0) + (medB or 0)
    results['parallel_bw_A'] = medA
    results['parallel_bw_B'] = medB
    results['parallel_bw_total'] = total
    print(f"    Flow A median: {medA:.2f} Mbps" if medA else "    Flow A: FAILED")
    print(f"    Flow B median: {medB:.2f} Mbps" if medB else "    Flow B: FAILED")
    print(f"    Total:         {total:.2f} Mbps")
    time.sleep(2)

    # ------------------------------------------------------------------ #
    # Test 3: Latency                                                     #
    # ------------------------------------------------------------------ #
    print("\n[3] Latency cross-pod: 10.0.0.2 -> 10.2.0.2 (20 pings)")
    rtt = ping_rtt(net, 'h10002', 'h10202', count=20)
    results['rtt_cross_pod'] = rtt
    print(f"    RTT: {rtt:.2f} ms" if rtt else "    FAILED")

    print("\n[3b] Latency intra-pod: 10.0.0.2 -> 10.0.1.2 (20 pings)")
    rtt2 = ping_rtt(net, 'h10002', 'h10012', count=20)
    results['rtt_intra_pod'] = rtt2
    print(f"    RTT: {rtt2:.2f} ms" if rtt2 else "    FAILED")

    print(f"\n{'='*50}")
    print(f"  FINAL RESULTS: {scheme_name}")
    print(f"{'='*50}")
    for k, v in results.items():
        print(f"  {k}: {v}")
    return results