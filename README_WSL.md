# DNS Relay for WSL

This is the Linux/WSL version of the DNS Relay coursework program.

Enter the code directory first:

```bash
cd "/mnt/c/Users/tangyuan/Documents/GitHub/DNS-Relay"
```

## Build

Install the compiler tools first if this is a fresh WSL system:

```bash
sudo apt update
sudo apt install build-essential
```

```bash
make
```

The executable, object files, and dependency files are generated under `build/`,
so `src/` contains source `.cpp` files only.

If `make` is not installed:

```bash
mkdir -p build/bin
g++ -std=c++17 -Wall -Wextra -O2 -pthread -Iinclude -o build/bin/dnsrelay src/*.cpp
```

Runtime output files are kept out of the project root:

```text
cache/dnsrelay.cache
logs/dnsrelay.log
pcaps/*.pcap
stats/dashboard.html
```

Create the runtime directories once before testing:

```bash
mkdir -p cache logs pcaps stats
```

## Project layout

```text
include/
  cache.h           DNS response cache interface
  config.h          command-line configuration
  dns_protocol.h    DNS constants, parsing, response building, cache TTL helpers
  forward_table.h   forwarded query ID mapping and timeout cleanup
  local_db.h        local database records and matching
  relay.h           relay runtime and statistics
  relay_handlers.h  client/upstream packet handlers
  shared_state.h    shared state and mutex-protected runtime data
  stats_report.h    HTML statistics dashboard generator
  thread_pool.h     fixed worker thread pool
  udp_socket.h      UDP socket creation helpers
  utils.h           small string, time, socket formatting helpers
src/
  main.cpp          program entry
  cache.cpp         in-memory cache with TTL refresh
  config.cpp        argument parsing
  dns_protocol.cpp  DNS wire-format logic
  forward_table.cpp forwarded query table
  local_db.cpp      dnsrelay.txt parser and wildcard matching
  relay.cpp         relay startup, select loop, shutdown statistics
  relay_handlers.cpp client query and upstream response processing
  shared_state.cpp  thread-safe log/stat/cache/pending helpers
  stats_report.cpp  writes stats/dashboard.html
  thread_pool.cpp   worker queue and worker threads
  udp_socket.cpp    UDP bind/socket helpers
build/              generated executable/object/dependency files, ignored by git
Makefile
dnsrelay.txt
README_WSL.md
```

## Run

The command format remains compatible with the teacher's PPT. This version also
adds `-p` for WSL testing, `-l` for the log file, `--cache-file` for the persistent cache,
cache TTL/capacity options, `--stats-file` for the visual statistics dashboard,
`--threads` for concurrent client query processing, and timeout retry controls:

```bash
dnsrelay [-d|-dd] [-p listen-port] [-l log-file]
         [--cache-file file] [--no-cache-file]
         [--cache-min-ttl seconds] [--cache-max-ttl seconds]
         [--cache-capacity entries]
         [--stats-file file] [--no-stats] [--threads count]
         [--retry-timeout seconds] [--retries count]
         [dns-server-ipaddr] [filename]
```

On Linux/WSL, listening on UDP port 53 usually requires root permission:

```bash
sudo ./build/bin/dnsrelay -d 114.114.114.114 dnsrelay.txt
```

For quick testing without `sudo`, listen on a high port:

```bash
./build/bin/dnsrelay -dd -p 1053 114.114.114.114 dnsrelay.txt
```

Use a fixed worker thread pool for concurrent client query processing:

```bash
./build/bin/dnsrelay -dd -p 1053 --threads 4 114.114.114.114 dnsrelay.txt
```

The main thread receives UDP packets and upstream responses. Client query
processing is submitted to the worker pool. Shared runtime data such as the
cache, forwarding table, statistics, log file, and hot-reloaded local database
are protected by mutexes or shared locks.

Forwarded queries wait 2 seconds for an upstream response and retry once by
default. Configure the policy with `--retry-timeout` and `--retries`. If all
attempts fail, the relay returns `SERVFAIL` to the original client instead of
leaving it waiting for a silent timeout.

The program writes query logs and final statistics to `logs/dnsrelay.log` by default.
Use `--no-log` to disable logging.

The local database file is hot-reloaded at runtime. After editing `dnsrelay.txt`,
the running relay detects the file timestamp change, reloads the records, and
keeps serving queries without a restart. Reload events are printed in debug mode
and written to the log as `HOSTS_RELOAD`.

Forwarded DNS responses are cached in memory and also saved to
`cache/dnsrelay.cache` by default. When the program starts again, unexpired
cache entries are loaded automatically and can be returned without querying the
upstream DNS server again. Use `--no-cache-file` to disable the persistent file,
or `--cache-file path/to/file` to choose another cache file.

The cache TTL is calculated from the upstream DNS response and then clamped:

```text
cache_ttl = clamp(upstream_ttl, cache_min_ttl, cache_max_ttl)
```

Defaults keep upstream TTL unchanged (`cache_min_ttl=0`,
`cache_max_ttl=4294967295`) and limit the cache to 1024 entries. Use
`--cache-min-ttl`, `--cache-max-ttl`, and `--cache-capacity` to tune the policy.
When the cache exceeds its capacity, the least recently used entry is evicted.

Runtime statistics are written to `stats/dashboard.html` by default. Open this
file in a browser to view request counters and bar charts. Use `--no-stats` to
disable it, or `--stats-file path/to/file.html` to choose another output file.


## Local database format

`dnsrelay.txt` supports the original two-column coursework format:

```text
IPv4-or-IPv6-address domain-pattern
```

Examples:

```text
0.0.0.0 www.666.com
114.255.40.66 www.bupt.com.cn
10.10.10.10 *.demo.test
2001:db8::10 host6.demo.test
```

It also supports an RR-like format that is easier to extend:

```text
domain-pattern [ttl] [IN] A|AAAA address
```

Examples:

```text
www.example.test 120 IN A 10.10.10.20
host6.demo.test 60 IN AAAA 2001:db8::10
```

`0.0.0.0` keeps its special meaning: block the domain and return `NXDOMAIN`.

## Test

Install `dig` if needed:

```bash
sudo apt update
sudo apt install dnsutils
```

Test the three required cases:

```bash
dig @127.0.0.1 -p 1053 www.666.com A
dig @127.0.0.1 -p 1053 www.bupt.com.cn A
dig @127.0.0.1 -p 1053 www.baidu.com A
```

Expected behavior:

- `www.666.com` is in `dnsrelay.txt` with `0.0.0.0`, so the relay returns `NXDOMAIN` (`RCODE=3`).
- `www.bupt.com.cn` is in `dnsrelay.txt`, so the relay returns `114.255.40.66` directly.
- Other domains are forwarded to the upstream DNS server.

To make the system use the relay as DNS, run it on port 53 and configure DNS to `127.0.0.1`.

## Extension tests

This version adds several extension features that are useful for the report:

- DNS cache: forwarded responses are cached using `clamp(upstream_ttl, cache_min_ttl, cache_max_ttl)`.
- LRU cache eviction: the cache has a capacity limit and evicts the least recently used entry first.
- Persistent cache file: unexpired cache entries are saved under `cache/` and reloaded on restart.
- Wildcard blocking/answering: `dnsrelay.txt` supports entries such as `*.bad.test`.
- Query logs and statistics: each query is written to `logs/dnsrelay.log`; summary statistics print when the program exits.
- Visual statistics dashboard: request counters and bar charts are written to `stats/dashboard.html`.
- Thread pool concurrency: client DNS queries are processed by a fixed worker pool configured with `--threads`.
- Upstream retry: timed-out queries are retried a bounded number of times and end with `SERVFAIL`.


Test wildcard matching:

```bash
dig @127.0.0.1 -p 1053 ads.bad.test A
dig @127.0.0.1 -p 1053 host.demo.test A
dig @127.0.0.1 -p 1053 host6.demo.test AAAA
```

Expected behavior:

- `ads.bad.test` matches `0.0.0.0 *.bad.test`, so it returns `NXDOMAIN`.
- `host.demo.test` matches `10.10.10.10 *.demo.test`, so it returns `A 10.10.10.10`.
- `host6.demo.test` matches the local `AAAA` record and returns `2001:db8::10`.

Test cache by querying the same forwarded domain twice:

```bash
dig @127.0.0.1 -p 1053 www.baidu.com A
dig @127.0.0.1 -p 1053 www.baidu.com A
```

In the relay terminal or `logs/dnsrelay.log`, the first query should show `FORWARD`
and `CACHE_STORE`; the second should show `CACHE_HIT`. In Wireshark, the second
query should not create another packet from the relay to the upstream DNS server.

Test cache TTL clamping and LRU eviction by starting the relay with a small cache:

```bash
./build/bin/dnsrelay -dd -p 1053 --cache-min-ttl 30 --cache-max-ttl 60 --cache-capacity 2 114.114.114.114 dnsrelay.txt
```

Then query three different forwarded domains:

```bash
dig @127.0.0.1 -p 1053 www.baidu.com A
dig @127.0.0.1 -p 1053 www.github.com A
dig @127.0.0.1 -p 1053 www.qq.com A
grep "CACHE_STORE" logs/dnsrelay.log | tail
```

The log shows both `upstream_ttl` and the clamped `cache_ttl`. With capacity 2,
the third forwarded domain forces one older unused cache entry to be evicted,
which is logged as `CACHE_EVICT` and counted as `cache_evictions`.

Test thread pool concurrency by starting with multiple workers:

```bash
./build/bin/dnsrelay -dd -p 1053 --threads 4 114.114.114.114 dnsrelay.txt
```

Then run several queries at the same time from another terminal:

```bash
for name in www.baidu.com www.cloudflare.com www.qq.com www.github.com host.demo.test ads.bad.test; do
  dig @127.0.0.1 -p 1053 "$name" A +short &
done
wait
```

The relay terminal should show interleaved query handling while the dashboard
and final statistics continue to count all request types.

Test retry and final `SERVFAIL` with an unreachable documentation address:

```bash
./build/bin/dnsrelay -dd -p 1053 --retry-timeout 2 --retries 1 192.0.2.1 dnsrelay.txt
```

From another terminal:

```bash
dig @127.0.0.1 -p 1053 www.example.com A +time=10 +tries=1
```

The relay prints one `[retry]` line after about 2 seconds, then one `[timeout]`
line and returns `status: SERVFAIL` after about 4 seconds. The log contains
`RETRY`, `SERVFAIL`, and `TIMEOUT`.

View logs:

```bash
tail -f logs/dnsrelay.log
```

Open the visual dashboard from Windows Explorer or a browser:

```bash
explorer.exe "$(wslpath -w stats/dashboard.html)"
```

Test hot reload without restarting the relay:

```bash
dig @127.0.0.1 -p 1053 hot.demo.test A
echo "10.10.10.30 hot.demo.test" >> dnsrelay.txt
sleep 2
dig @127.0.0.1 -p 1053 hot.demo.test A
```

The first query is forwarded to the upstream DNS server. After the file reloads,
the second query should return `A 10.10.10.30` from the local database. Remove
the test line from `dnsrelay.txt` after the demo if it is no longer needed.

## Wireshark capture

For the report, capture the DNS packets and show the three required cases.
The most reliable WSL method is to capture a `.pcap` file in WSL, then open it
with Wireshark on Windows.

Terminal 1, start the relay:

```bash
./build/bin/dnsrelay -dd -p 1053 114.114.114.114 dnsrelay.txt
```

Terminal 2, capture loopback packets:

```bash
mkdir -p pcaps
sudo tcpdump -i lo -w pcaps/dnsrelay-test.pcap udp port 1053
```

Terminal 3, run tests:

```bash
dig @127.0.0.1 -p 1053 www.666.com A
dig @127.0.0.1 -p 1053 www.bupt.com.cn A
dig @127.0.0.1 -p 1053 www.baidu.com A
```

Stop `tcpdump` with `Ctrl+C`, then open `pcaps/dnsrelay-test.pcap` in Wireshark.
Use this display filter:

```text
dns || udp.port == 1053
```

If you also want to show forwarding to the upstream DNS server, capture all DNS
traffic instead:

```bash
mkdir -p pcaps
sudo tcpdump -i any -w pcaps/dnsrelay-forward.pcap 'udp port 53 or udp port 1053'
```

In Wireshark, good screenshots for the report are:

- `www.666.com`: response code is `No such name` / `NXDOMAIN`.
- `www.bupt.com.cn`: answer record is `A 114.255.40.66`.
- `www.baidu.com`: the relay receives the client query on port `1053`, then forwards a DNS query to upstream port `53`, and finally sends the response back to the client.
