# CF 三方反代 IP 扫描管线

全自动 CF 反代 IP 扫描：ASN → CIDR → masscan → cfscan → API 验证

## 依赖

- `masscan` (apt install masscan)
- Go 1.21+ (编译 cfscan)

## 快速开始

```bash
# 1. 编译 cfscan
go build -o cfscan cfscan.go
cp cfscan /usr/local/bin/

# 2. 准备 ASN 列表
# 编辑 asn_list.txt，一行一个 ASN 号

# 3. 运行
ASN_FILE=asn_list.txt ./pipeline.sh
```

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| ASN_FILE | asn_list.txt | ASN 列表 |
| PORTS | 443,8443 | 扫描端口 |
| MASSCAN_RATE | 15000 | masscan 速率 |
| CF_CONC | 800 | cfscan 并发 |
| OUT_DIR | /root | 输出目录 |

## 流程

1. **Phase 1** (phase1_cidr.py) - RIPEstat API 拉取 CIDR
2. **Phase 2** (masscan) - 全端口扫描
3. **Phase 3** (cfscan) - TLS 证书检测，筛选 CF 节点
4. **Phase 4** (phase4_verify.py) - API 二次验证

## 输出

- `verified_<ts>.csv` - 最终验证通过的 IP 列表
