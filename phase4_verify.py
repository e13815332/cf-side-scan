#!/usr/bin/env python3
"""Phase 4: 与 cfnb main.py check_availability 完全一致"""
import sys, json, time
import requests

INPUT = sys.argv[1] if len(sys.argv) > 1 else "/root/cf_hits.txt"
OUTPUT = sys.argv[2] if len(sys.argv) > 2 else "/root/verified.csv"
WORKERS = 32
CONNECT_T = 3
READ_T = 3

HEADER = "IP,Port,TLS,DC,Country,Region,Latency,DownloadSpeed,ASN\n"

def check(node_str):
    """与 cfnb check_availability 一模一样：无重试，ipv6优先，先查 success"""
    ip_port = node_str.split()[0]  # 取第一字段 IP:PORT
    try:
        resp = requests.get(
            "https://api.090227.xyz/check",
            params={"proxyip": ip_port},
            timeout=(CONNECT_T, READ_T)
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success") is True:
                probe = (data.get("probe_results", {}).get("ipv6") or
                         data.get("probe_results", {}).get("ipv4") or {})
                exit_info = probe.get("exit", {})
                if exit_info:
                    ip, port = ip_port.rsplit(":", 1)
                    return f"{ip},{port},TRUE,{exit_info.get('colo','')},{exit_info.get('country','')},{exit_info.get('region','')},,,AS{exit_info.get('asn','')}"
        return None
    except Exception:
        return None

lines = [l.strip() for l in open(INPUT) if l.strip() and not l.startswith("#")]
total = len(lines)
print(f"[Phase4] {total} hosts, {WORKERS} workers", flush=True)

t0 = time.time()
passed = 0

from concurrent.futures import ThreadPoolExecutor, as_completed

with open(OUTPUT, "w") as f:
    f.write(HEADER)
    BATCH = 500
    for ci in range(0, total, BATCH):
        chunk = lines[ci:ci+BATCH]
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futures = {ex.submit(check, ip): ip for ip in chunk}
            for ff in as_completed(futures):
                r = ff.result()
                if r:
                    f.write(r + "\n")
                    passed += 1
        print(f"\r  {min(ci+BATCH,total)}/{total} | {passed} passed", end="", flush=True)

elapsed = time.time() - t0
print(f"\n[Phase4] done: {passed}/{total} ({elapsed:.0f}s) -> {OUTPUT}")
