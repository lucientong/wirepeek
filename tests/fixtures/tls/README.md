# TLS fixtures

Wirepeek v1.2 decrypt coverage is primarily exercised by deterministic unit/integration
tests (known-answer HKDF/AEAD + synthetic TLS 1.3 HTTP/1 plaintext recovery).

To capture a local self-signed `pcap + keylog` pair for manual CLI checks:

```bash
# Terminal A
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj '/CN=localhost'
SSLKEYLOGFILE=$PWD/sslkeys.log openssl s_server -accept 8443 -cert cert.pem -key key.pem -www

# Terminal B
tcpdump -i lo0 -w tls13-http1.pcap 'port 8443' &
SSLKEYLOGFILE=$PWD/sslkeys.log curl -k https://127.0.0.1:8443/

# Analyze (OpenSSL-enabled build)
wirepeek --read tls13-http1.pcap --tls-keylog sslkeys.log --headless
```

Only store self-signed localhost traffic in this tree. Do not commit third-party or
production secrets.
