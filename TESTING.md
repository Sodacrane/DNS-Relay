# DNS Relay 测试指令清单

本文档整理 DNS Relay 项目的完整测试流程。默认在 **WSL** 中运行，DNS Relay 监听端口统一使用 `1053`。

> 如果你的代码目录不同，请把下面命令中的项目路径替换成自己的实际路径。

## 0. 进入目录和编译

```bash
cd "/mnt/c/Users/32741/Downloads/to students 2026/to students/code"

mkdir -p cache logs pcaps stats
make
```

如果系统没有安装 `make` 或基础编译工具：

```bash
sudo apt update
sudo apt install build-essential dnsutils tcpdump
make
```

## 1. 终端 1：启动 DNS Relay

普通测试推荐使用：

```bash
./dnsrelay -dd -p 1053 --threads 4 114.114.114.114 dnsrelay.txt
```

如果老师要求上游 DNS 使用 `202.106.0.20`：

```bash
./dnsrelay -dd -p 1053 --threads 4 202.106.0.20 dnsrelay.txt
```

如果测试北邮内网 DNS，必须处于校园网或 VPN 环境：

```bash
./dnsrelay -dd -p 1053 --threads 4 10.3.9.4 dnsrelay.txt
```

或：

```bash
./dnsrelay -dd -p 1053 --threads 4 10.3.9.5 dnsrelay.txt
```

## 2. 基础三种情况测试

在终端 2 运行：

```bash
dig @127.0.0.1 -p 1053 www.666.com A
dig @127.0.0.1 -p 1053 www.bupt.com.cn A
dig @127.0.0.1 -p 1053 www.baidu.com A
```

预期结果：

| 域名 | 预期行为 |
| --- | --- |
| `www.666.com` | 返回 `NXDOMAIN`，被 `0.0.0.0` 拦截 |
| `www.bupt.com.cn` | 本地返回 `114.255.40.66` |
| `www.baidu.com` | 本地没有记录，转发到上游 DNS |

## 3. nslookup 测试

```bash
nslookup -port=1053 www.bupt.com.cn 127.0.0.1
nslookup -port=1053 www.baidu.com 127.0.0.1
```

## 4. 通配符拦截和通配符本地解析

```bash
dig @127.0.0.1 -p 1053 ads.bad.test A
dig @127.0.0.1 -p 1053 host.demo.test A
```

预期结果：

| 域名 | 预期行为 |
| --- | --- |
| `ads.bad.test` | 返回 `NXDOMAIN`，匹配 `*.bad.test` |
| `host.demo.test` | 返回 `10.10.10.10`，匹配 `*.demo.test` |

## 5. IPv6 / AAAA 测试

本地 AAAA 记录：

```bash
dig @127.0.0.1 -p 1053 host6.demo.test AAAA
```

转发 AAAA 查询：

```bash
dig @127.0.0.1 -p 1053 www.cloudflare.com AAAA
```

## 6. MX / PTR 转发测试

MX 查询不会直接返回 IP，而是返回邮件服务器域名：

```bash
dig @127.0.0.1 -p 1053 gmail.com MX
```

反向解析 PTR：

```bash
dig @127.0.0.1 -p 1053 -x 8.8.8.8
```

## 7. 缓存测试

连续查询两次同一个本地没有记录的域名：

```bash
dig @127.0.0.1 -p 1053 www.cloudflare.com A
dig @127.0.0.1 -p 1053 www.cloudflare.com A
```

查看日志：

```bash
tail -n 30 logs/dnsrelay.log
```

预期第一遍日志包含：

```text
FORWARD
CACHE_STORE
```

预期第二遍日志包含：

```text
CACHE_HIT
```

## 8. 持久化缓存测试

先启动 DNS Relay，然后查询一次：

```bash
dig @127.0.0.1 -p 1053 www.cloudflare.com A
```

在终端 1 按 `Ctrl+C` 停止 DNS Relay，再重新启动：

```bash
./dnsrelay -dd -p 1053 --threads 4 114.114.114.114 dnsrelay.txt
```

再次查询：

```bash
dig @127.0.0.1 -p 1053 www.cloudflare.com A
```

查看日志：

```bash
tail -n 40 logs/dnsrelay.log
```

如果缓存没有过期，日志中应看到：

```text
CACHE_LOAD
CACHE_HIT
```

## 9. LRU 缓存淘汰测试

终端 1 使用小缓存启动：

```bash
./dnsrelay -dd -p 1053 --cache-capacity 2 --threads 4 114.114.114.114 dnsrelay.txt
```

终端 2 运行：

```bash
dig @127.0.0.1 -p 1053 www.baidu.com A
dig @127.0.0.1 -p 1053 www.github.com A
dig @127.0.0.1 -p 1053 www.qq.com A
tail -n 50 logs/dnsrelay.log
```

预期日志中看到：

```text
CACHE_EVICT
```

## 10. 热重载测试

不重启终端 1 的 DNS Relay，在终端 2 运行：

```bash
dig @127.0.0.1 -p 1053 live.demo.test A
echo "10.10.10.31 live.demo.test" >> dnsrelay.txt
sleep 2
dig @127.0.0.1 -p 1053 live.demo.test A
```

预期第二次查询返回：

```text
10.10.10.31
```

查看日志：

```bash
tail -n 30 logs/dnsrelay.log
```

应看到：

```text
HOSTS_RELOAD
```

测试结束后可以删掉刚添加的记录：

```bash
sed -i '/10.10.10.31 live.demo.test/d' dnsrelay.txt
```

## 11. 多线程并发测试

```bash
for name in www.baidu.com www.cloudflare.com www.qq.com www.github.com host.demo.test ads.bad.test; do
  dig @127.0.0.1 -p 1053 "$name" A +short &
done
wait
```

查看日志：

```bash
tail -n 80 logs/dnsrelay.log
```

预期能看到多个请求交错处理，并包含本地命中、拦截、转发、缓存等记录。

## 12. 可视化统计测试

启动 DNS Relay 后运行一些查询，然后在 WSL 中打开 dashboard：

```bash
explorer.exe "$(wslpath -w stats/dashboard.html)"
```

也可以直接在 Windows 文件管理器中打开：

```text
C:\Users\32741\Downloads\to students 2026\to students\code\stats\dashboard.html
```

## 13. 上游超时重试与 SERVFAIL 测试

终端 1 使用不可达的文档测试地址作为上游 DNS：

```bash
./build/bin/dnsrelay -dd -p 1053 \
  --retry-timeout 2 \
  --retries 1 \
  -l logs/retry-test.log \
  192.0.2.1 dnsrelay.txt
```

终端 2 只发送一次客户端查询：

```bash
dig @127.0.0.1 -p 1053 www.example.com A +time=10 +tries=1
```

预期大约 2 秒后出现一次 `[retry]`，大约 4 秒后出现：

```text
[timeout] ... -> SERVFAIL
```

`dig` 应显示：

```text
status: SERVFAIL
```

检查日志：

```bash
grep -E 'RETRY|TIMEOUT|SERVFAIL' logs/retry-test.log
```

## 14. Wireshark 抓包测试

终端 1 启动 DNS Relay：

```bash
./dnsrelay -dd -p 1053 --threads 4 114.114.114.114 dnsrelay.txt
```

终端 2 抓包：

```bash
sudo tcpdump -i any -w pcaps/dnsrelay-forward.pcap 'udp port 53 or udp port 1053'
```

终端 3 跑查询：

```bash
dig @127.0.0.1 -p 1053 www.666.com A
dig @127.0.0.1 -p 1053 www.bupt.com.cn A
dig @127.0.0.1 -p 1053 www.baidu.com A
dig @127.0.0.1 -p 1053 www.cloudflare.com A
dig @127.0.0.1 -p 1053 www.cloudflare.com A
```

然后在终端 2 按 `Ctrl+C` 停止抓包。

在 Windows Wireshark 中打开：

```text
C:\Users\32741\Downloads\to students 2026\to students\code\pcaps\dnsrelay-forward.pcap
```

Wireshark 显示过滤器：

```text
dns || udp.port == 1053
```

重点检查：

| 查询 | 预期现象 |
| --- | --- |
| `www.666.com` | 返回 `NXDOMAIN`，且不转发上游 |
| `www.bupt.com.cn` | 本地直接返回 A 记录 `114.255.40.66` |
| `www.baidu.com` | 有 `1053` 客户端请求，也有 `53` 上游转发 |
| 第二次 `www.cloudflare.com` | 应该只有本地 `1053` 响应，没有新的上游 `53` 查询 |

