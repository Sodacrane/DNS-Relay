# DNS Relay Client Frontend

This is a small local web client for manually querying the DNS Relay from a browser.

## Run

```bash
cd "/mnt/c/Users/32741/Downloads/to students 2026/to students/code/client_frontend"
python3 server.py
```

Open:

```text
http://127.0.0.1:5000
```

The client machine needs `dig`:

```bash
sudo apt install dnsutils
```

## Two-machine test

Run the relay on the relay machine:

```bash
cd "/mnt/c/Users/32741/Downloads/to students 2026/to students/code"
./dnsrelay -dd -p 1053 --threads 4 114.114.114.114 dnsrelay.txt
```

Run this frontend on the client machine, then enter:

```text
Relay Server: 10.29.235.155
Port: 1053
Domain: www.baidu.com
Type: A
```
