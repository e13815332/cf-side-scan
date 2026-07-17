#!/usr/bin/env python3
"""Phase 1: ASN → CIDR (RIPEStat)"""
import sys, json, time, urllib.request

ASN_FILE = "/root/cfscan/asn_list.txt"
OUT_FILE = "/root/cfscan/cidrs.txt"

def fetch(asn):
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    req = urllib.request.Request(url, headers={"User-Agent": "cfscan/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        return [p["prefix"] for p in data["data"]["prefixes"] if ":" not in p["prefix"]]
    except Exception as e:
        print(f"  AS{asn}: FAIL ({e})", flush=True)
        return []

asns = [l.strip() for l in open(ASN_FILE) if l.strip().isdigit()]
all_cidrs = set()
t0 = time.time()

for i, asn in enumerate(asns):
    prefixes = fetch(asn)
    all_cidrs.update(prefixes)
    elapsed = time.time() - t0
    rate = (i+1)/elapsed if elapsed > 0 else 0
    print(f"[{i+1}/{len(asns)}] AS{asn}: {len(prefixes)} prefixes ({rate:.1f}/s)", flush=True)
    time.sleep(0.5)  # 限速

sorted_cidrs = sorted(all_cidrs, key=lambda x: tuple(map(int, x.split("/")[0].split("."))))
with open(OUT_FILE, "w") as f:
    f.write("\n".join(sorted_cidrs) + "\n")

print(f"\nDone. {len(sorted_cidrs)} CIDRs → {OUT_FILE} ({time.time()-t0:.0f}s)")
