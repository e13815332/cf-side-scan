#!/bin/bash
# pipeline.sh — CF 反代 IP 扫描全流程（防爆内存版）
set -e

ASN_FILE="${ASN_FILE:-/root/cf-side-scan/asn_list.txt}"
PORTS="${PORTS:-443,8443}"
MASSCAN_RATE="${MASSCAN_RATE:-15000}"
CF_CONC="${CF_CONC:-800}"
OUT_DIR="${OUT_DIR:-/root}"

TS=$(date +%Y%m%d_%H%M%S)
CIDRS="$OUT_DIR/cidrs_$TS.txt"
OPEN="$OUT_DIR/open_ports_$TS.txt"
CFHITS="$OUT_DIR/cf_hits_$TS.txt"
VERIFIED="$OUT_DIR/verified_$TS.csv"

echo "========== $(date) pipeline start =========="
echo "ASN: $ASN_FILE   ports: $PORTS   rate: $MASSCAN_RATE   conc: $CF_CONC"

# ====== Phase 1: CIDR (逐个 ASN 写磁盘，排序用 disk sort) ======
echo ""
echo "===== Phase 1: CIDR ====="
> "$CIDRS"  # 清空
python3 -c "
import json,time,urllib.request,tempfile,os
asns=[l.strip() for l in open('$ASN_FILE') if l.strip().isdigit()]
done=0; t0=time.time()
for i,a in enumerate(asns):
  try:
    r=json.loads(urllib.request.urlopen(f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{a}',timeout=30).read())
    pfxs=[p['prefix'] for p in r['data']['prefixes'] if ':' not in p['prefix']]
    with open('$CIDRS','a') as f: f.write('\n'.join(pfxs)+'\n')
    print(f'[{i+1}/{len(asns)}] AS{a}: {len(pfxs)}',flush=True)
  except Exception as e:
    print(f'[{i+1}/{len(asns)}] AS{a}: FAIL',flush=True)
  time.sleep(0.5)
print(f'Sorting...',flush=True)
os.system(f'sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n $CIDRS -o $CIDRS')
print(f'Done. {os.popen(\"wc -l < $CIDRS\").read().strip()} CIDRs ({time.time()-t0:.0f}s)',flush=True)
"
echo "CIDRs: $(wc -l < $CIDRS)"

# ====== Phase 2: masscan (pipe 直出，不存原始文件) ======
echo ""
echo "===== Phase 2: masscan ====="
TMP_MASSCAN="$OUT_DIR/_masscan_tmp_$TS.txt"
masscan -iL "$CIDRS" -p "$PORTS" --rate "$MASSCAN_RATE" --retries 0 --wait 0 -oL "$TMP_MASSCAN"
grep "^open" "$TMP_MASSCAN" | awk '{print $4":"$3}' | sort -u > "$OPEN"
rm -f "$TMP_MASSCAN"
echo "Open: $(wc -l < $OPEN)"

# 系统调优：避免 TIME_WAIT 端口耗尽 + 文件描述符上限
ulimit -n 65536
sysctl -w net.netfilter.nf_conntrack_max=262144 > /dev/null 2>&1
sysctl -w net.ipv4.tcp_tw_reuse=1 > /dev/null
sysctl -w net.ipv4.ip_local_port_range="1024 65535" > /dev/null
sysctl -w net.ipv4.tcp_syn_retries=1 > /dev/null

# ====== Phase 3: cfscan (纯 TLS 证书检测，SetDeadline 防卡死 + SO_LINGER 防 TIME_WAIT) ======
echo ""
echo "===== Phase 3: cfscan ====="
cat "$OPEN" | cfscan --stdin -c "$CF_CONC" -connect-timeout 1s -o "$CFHITS" 2>"$OUT_DIR/scanner_$TS.log"
echo "CF IPs: $(wc -l < $CFHITS)"

# ====== Phase 4: API 验证 ======
echo ""
echo "===== Phase 4: API verify ====="
python3 /root/cf-side-scan/phase4_verify.py "$CFHITS" "$VERIFIED"

echo ""
echo "========== $(date) pipeline done =========="
echo "CIDR:     $(wc -l < $CIDRS)"
