# Spider Connect

Bundled components:
- Aether source (CluvexStudio/Aether), built on first use if no Aether binary is available.
- Xray Core Linux x86_64 bundle supplied with Spider.

Aether requires Rust 1.98+, C/C++ and CMake according to the upstream project.
Xray Proxy mode is generated on `127.0.0.1:1819`, or `0.0.0.0:1819` when LAN sharing is enabled in Settings.
Xray TUN mode uses Xray's native TUN inbound with automatic system routing when the host supports it.
