# Connect / Diag

## Connect
- Aether: bundled source tree; first run builds `aether` locally if no usable binary exists.
- Xray: bundled Linux x86_64 Xray Core + geoip/geosite data.
- Xray accepts one or many configs at once: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard INI, and SSH. Each profile gets an independent local health-probe route; the active Xray proxy remains on port 1819.
- Xray TUN: native TUN inbound with automatic system routing and automatic outbound-interface selection on supported systems.
- Settings: LAN sharing toggles the managed proxy between `127.0.0.1:1819` and `0.0.0.0:1819`; device non-loopback IPs are shown. Ping providers are editable and every loaded Xray profile is checked automatically every 30 seconds; the Live Status screen refreshes continuously.

### Xray live monitoring
The Live Status screen shows each config, protocol, server, ping, loss, status, and the last three Xray log lines inside a compact log box.

## Diag
Runs bounded tests for TCP, UDP/DNS, HTTP, HTTPS, IPv4, IPv6, latency, packet loss, jitter, download/upload throughput, and 18 important internet services. Results are shown in tables and combined into a weighted 0-100 diagnostic score.

## SNI Spoof
- `Connect → SNI Spoof` adds Custom, Auto and conditional Last Find modes.
- Custom asks for an IP and fake SNI; the selected Xray TLS/REALITY profile is cloned and the remote address/SNI are replaced.
- Auto uses ordered IPv4 candidates from `data/cf_subnets.txt` and ordered hostnames from `data/sni-list.txt`. Candidate pairs are tested through Xray SOCKS probe batches and the first successful pair is saved as `sni_spoof_last_find`.
- Last Find stays hidden until a successful Auto result exists. It reuses only the saved IP/SNI metadata with a newly supplied config.
- Auto scanning is bounded and concurrent: configurable IP/SNI limits, pair cap, batch size and probe timeout are available in Settings. User proxy credentials are not written into the Last Find record.
- The supplied upstream SNI-Spoofing source is bundled under `connect/sni-spoof/upstream/SNI-Spoofing-main/`; Spider's Linux path uses Xray TLS SNI override instead of the upstream Windows packet injector.


### Aether binary
The Connect → Aether integration uses the bundled prebuilt Linux x86_64 distribution at `connect/aether/aether`, with optional PT helpers under `connect/aether/pt/`. Installation does not compile Aether.
