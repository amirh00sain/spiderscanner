#!/usr/bin/env python3
"""Spider SNI Spoof local TCP/UDP relay.

Xray connects to 127.0.0.1:40443. TCP and UDP are both forwarded to the selected
target IP:port. Xray itself generates the TLS/REALITY or QUIC ClientHello,
including the requested fake SNI, so protocol bytes are forwarded unchanged.
"""

from __future__ import annotations

import argparse
import signal
import socket
import threading
from typing import Dict, Optional, Tuple

BUFFER = 128 * 1024
STOP = threading.Event()


def parse_endpoint(value: str):
    value = value.strip()
    if value.startswith("["):
        host, _, tail = value[1:].partition("]")
        if not tail.startswith(":"):
            raise ValueError(f"invalid endpoint: {value!r}")
        return host, int(tail[1:])
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise ValueError(f"endpoint must be host:port: {value!r}")
    return host, int(port)


def relay_tcp(src: socket.socket, dst: socket.socket):
    try:
        while not STOP.is_set():
            data = src.recv(BUFFER)
            if not data:
                break
            dst.sendall(data)
    except (OSError, ConnectionError):
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle_tcp(client: socket.socket, target: Tuple[str, int]):
    upstream: Optional[socket.socket] = None
    try:
        client.settimeout(10)
        upstream = socket.create_connection(target, timeout=10)
        client.settimeout(None)
        upstream.settimeout(None)

        t = threading.Thread(target=relay_tcp, args=(client, upstream), daemon=True)
        t.start()
        relay_tcp(upstream, client)
        t.join(timeout=2)
    except (OSError, ConnectionError):
        pass
    finally:
        for sock in (client, upstream):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass


def run_tcp(listen: Tuple[str, int], target: Tuple[str, int], family: int):
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(0.5)
    server.bind(listen)
    server.listen(128)
    print(f"SNI TCP proxy listening on {listen[0]}:{listen[1]}", flush=True)

    try:
        while not STOP.is_set():
            try:
                client, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=handle_tcp, args=(client, target), daemon=True).start()
    finally:
        try:
            server.close()
        except OSError:
            pass


def run_udp(listen: Tuple[str, int], target: Tuple[str, int], family: int):
    server = socket.socket(family, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(0.5)
    server.bind(listen)
    print(f"SNI UDP proxy listening on {listen[0]}:{listen[1]}", flush=True)

    # One connected upstream socket per local Xray UDP client address.
    upstreams: Dict[Tuple[str, int], socket.socket] = {}
    lock = threading.Lock()

    def upstream_reader(client_addr, upstream_sock):
        try:
            while not STOP.is_set():
                data = upstream_sock.recv(BUFFER)
                if not data:
                    break
                server.sendto(data, client_addr)
        except (OSError, ConnectionError):
            pass
        finally:
            with lock:
                upstreams.pop(client_addr, None)
            try:
                upstream_sock.close()
            except OSError:
                pass

    try:
        while not STOP.is_set():
            try:
                data, client_addr = server.recvfrom(BUFFER)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                continue

            with lock:
                upstream_sock = upstreams.get(client_addr)
                if upstream_sock is None:
                    try:
                        upstream_sock = socket.socket(family, socket.SOCK_DGRAM)
                        upstream_sock.connect(target)
                        upstreams[client_addr] = upstream_sock
                        threading.Thread(
                            target=upstream_reader,
                            args=(client_addr, upstream_sock),
                            daemon=True,
                        ).start()
                    except OSError:
                        if upstream_sock:
                            upstream_sock.close()
                        continue

            try:
                upstream_sock.send(data)
            except (OSError, ConnectionError):
                with lock:
                    upstreams.pop(client_addr, None)
                try:
                    upstream_sock.close()
                except OSError:
                    pass
    finally:
        with lock:
            sockets = list(upstreams.values())
            upstreams.clear()
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass
        try:
            server.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description="Spider local SNI Spoof TCP/UDP relay")
    ap.add_argument("--listen", default="127.0.0.1:40443")
    ap.add_argument("--target", required=True, help="target IP/hostname:port")
    args = ap.parse_args()

    listen = parse_endpoint(args.listen)
    target = parse_endpoint(args.target)

    family = socket.AF_INET6 if ":" in listen[0] else socket.AF_INET

    def shutdown(*_):
        STOP.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    print(f"SNI proxy target: {target[0]}:{target[1]}", flush=True)

    tcp_thread = threading.Thread(
        target=run_tcp, args=(listen, target, family), daemon=True
    )
    udp_thread = threading.Thread(
        target=run_udp, args=(listen, target, family), daemon=True
    )
    tcp_thread.start()
    udp_thread.start()

    tcp_thread.join()
    udp_thread.join()


if __name__ == "__main__":
    main()
