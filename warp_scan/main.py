#!/usr/bin/env python3
"""
spider: Termux/Linux TCP/HTTPS endpoint scanner.

Scope:
- CDN TCP connectivity checks for Railway, Cloudflare, Fastly, and Amazon CloudFront.
- Cloudflare and Railway TCP/HTTPS connectivity checks.
- Advanced config replacement and DPI helpers.
- Multi-metric quality scoring: packet loss, latency, jitter, speed, reliability, and service validation.
"""
from __future__ import annotations
import argparse, base64, binascii, ipaddress, json, os, random, re, select, signal, socket, ssl, statistics, struct, subprocess, sys, time, copy, shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event, Lock, Thread
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH_OK = True
except ImportError:
    RICH_OK = False

APP = "spider"
VERSION = "1"
HOME = Path(os.environ.get("SPIDER_HOME", Path.home()/".spider"))
CACHE = HOME/"cache.json"
CONFIG = HOME/"config.json"
DEFAULT_CF_FILE = Path(__file__).resolve().parent.parent/"data"/"cf_subnets.txt"
DEFAULT_FASTLY_FILE = Path(__file__).resolve().parent.parent/"data"/"fastly_subnets.txt"
DEFAULT_CLOUDFRONT_FILE = Path(__file__).resolve().parent.parent/"data"/"cloudfront_subnets.txt"
DEFAULT_SNI_LIST_FILE = Path(__file__).resolve().parent.parent/"data"/"sni-list.txt"
RAW_CF_FILE_URL = "https://raw.githubusercontent.com/amirh00sain/spiderscanner/main/data/cf_subnets.txt"
FASTLY_IP_LIST_URL = "https://api.fastly.com/public-ip-list"
CLOUDFRONT_IP_LIST_URL = "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips"
DPI_DEFAULT_FILE = Path(__file__).resolve().parent.parent/"data"/"dpi-output.example.json"
FASTFETCH_LOGO = Path(__file__).resolve().parent.parent/"assets"/"amirh00sain.txt"
console = Console() if RICH_OK else None

# Railway TCP Proxy range currently targeted by Spider.
# Railway does not publish a fixed TCP-proxy IP range in its public docs;
# this scanner targets the observed Railway proxy block used by this project.
RAILWAY_TCP_START = ipaddress.ip_address("66.33.22.220")
RAILWAY_TCP_END = ipaddress.ip_address("66.33.22.250")
RAILWAY_TCP_CIDRS = [
    ipaddress.ip_network(f"{RAILWAY_TCP_START + i}/32")
    for i in range(int(RAILWAY_TCP_END) - int(RAILWAY_TCP_START) + 1)
]
RAILWAY_HTTPS = ipaddress.ip_network("69.46.46.0/24")

DEFAULTS = {
    "workers": 64,
    "max_in_flight": 128,
    "handshake_timeout": 1.5,
    "probe_count": 5,
    "quality_probe_limit": 25,
    "rate": 150.0,
    "cooldown": 300,
    "failure_threshold": 3,
    "tcp_ports": [443,80,8080,8443],
    "https_port": 443,
    "advanced_valid": 20,
    "advanced_max_candidates": 4096,
    "advanced_timeout": 1.0,
    "cf_max_candidates": 20000,
    "cdn_max_candidates": 20000,
    "score_weights": {"loss": 30.0, "latency": 20.0, "jitter": 15.0, "speed": 15.0, "reliability": 10.0, "service": 10.0},
    "sni_spoof_auto_ip_limit": 512,
    "sni_spoof_sni_limit": 64,
    "sni_spoof_max_candidates": 2048,
    "sni_spoof_batch_size": 64,
    "sni_spoof_timeout": 2.5,
}






















@dataclass
class Endpoint:
    ip: str
    port: int
    protocol: str = "tcp"
    status: str = "unknown"
    rtt_ms: float | None = None
    median_rtt_ms: float | None = None
    min_rtt_ms: float | None = None
    jitter_ms: float | None = None
    packet_loss: float = 100.0
    score: float = 0.0
    latency_score: float | None = None
    loss_score: float | None = None
    jitter_score: float | None = None
    speed_mbps: float | None = None
    speed_score: float | None = None
    reliability_score: float | None = None
    service_score: float | None = None
    source: str = ""
    error: str = ""

class State:
    def __init__(self):
        HOME.mkdir(parents=True, exist_ok=True)
        self.cfg = self.load_json(CONFIG, DEFAULTS.copy())
        self.cache = self.load_json(CACHE, {})
    def load_json(self,p,default):
        try: return json.loads(p.read_text())
        except Exception: return default
    def save(self):
        CONFIG.write_text(json.dumps(self.cfg,indent=2))
        CACHE.write_text(json.dumps(self.cache,indent=2))












def run_fastfetch():
    """Run fastfetch with the bundled dot-matrix amirh00sain logo when available."""
    logo = str(FASTFETCH_LOGO)
    exe = shutil.which("fastfetch")
    if not exe:
        return False
    try:
        subprocess.run(
            [exe, "--logo-type", "file", "--logo", logo, "--logo-padding-right", "3"],
            check=False,
            stdout=sys.stdout,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def print_fallback_logo():
    try:
        print(FASTFETCH_LOGO.read_text())
    except Exception:
        print(".   .  .  .   .  .  .   .   .  .  .   .")
        print("  . .   . .   .  .  .   .   .  .  .   .")
        print("   .    .     .  .  .   .   . . . .   .")


class StopController:
    """Live scan stop controller: Ctrl-C or q stops a running scan."""
    def __init__(self):
        self.event = Event()
        self._old_handler = None
        self._thread = None
        self._fd = None
        self._old_term = None

    def request(self, *_):
        self.event.set()

    def start(self):
        try:
            self._old_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, self.request)
        except Exception:
            pass
        if not sys.stdin.isatty():
            return self
        try:
            import termios, tty
            self._fd = sys.stdin.fileno()
            self._old_term = termios.tcgetattr(self._fd)
            tty.setcbreak(self._fd)
            def watch():
                while not self.event.is_set():
                    try:
                        ready, _, _ = select.select([sys.stdin], [], [], 0.20)
                        if ready:
                            ch = sys.stdin.read(1)
                            if ch.lower() == 'q':
                                self.request()
                                print('\n[!] Stop requested (q). Finishing in-flight probes...')
                                break
                    except Exception:
                        break
            self._thread = Thread(target=watch, daemon=True)
            self._thread.start()
        except Exception:
            self._fd = None
        return self

    def stop(self):
        self.request()

    def close(self):
        # Always stop and join the q-watcher before returning to the menu.
        # Otherwise the previous scan's background reader can consume the
        # first character of the next menu selection (for example `2`).
        try:
            self.request()
        except Exception:
            pass
        try:
            if self._thread is not None and self._thread.is_alive():
                self._thread.join(timeout=0.6)
        except Exception:
            pass
        try:
            if self._fd is not None and self._old_term is not None:
                import termios
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_term)
        except Exception:
            pass
        try:
            if self._old_handler is not None:
                signal.signal(signal.SIGINT, self._old_handler)
        except Exception:
            pass
        self._thread = None
        self._fd = None
        self._old_term = None
        self._old_handler = None


def endpoint_from_cache(state):
    vals=[]
    for k,v in state.cache.items():
        if v.get("status")=="verified" and not cooldown_active(v,state.cfg):
            vals.append(v)
    vals.sort(key=lambda x: (-x.get("score",0), x.get("median_rtt_ms",999999)))
    return vals


def cooldown_active(v,cfg):
    if v.get("failure_count",0) < cfg["failure_threshold"]: return False
    return time.time()-v.get("last_failure",0) < cfg["cooldown"]


def update_cache(state,e:Endpoint):
    k=f"{e.ip}:{e.port}"
    v=state.cache.get(k,{})
    if e.status=="verified":
        v.update({"ip":e.ip,"port":e.port,"protocol":e.protocol,"status":"verified",
                  "last_success":time.time(),"last_rtt_ms":e.rtt_ms,
                  "median_rtt_ms":e.median_rtt_ms,"jitter_ms":e.jitter_ms,"packet_loss":e.packet_loss,
                  "speed_mbps":e.speed_mbps,
                  "success_count":v.get("success_count",0)+1,"failure_count":0,"score":e.score})
    else:
        v.update({"ip":e.ip,"port":e.port,"protocol":e.protocol,
                  "failure_count":v.get("failure_count",0)+1,"last_failure":time.time()})
        v["status"]="dead"
    state.cache[k]=v


def _checksum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff




def _tcp_checksum_ipv4(src: bytes, dst: bytes, tcp: bytes) -> int:
    pseudo = src + dst + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(tcp))
    return _checksum16(pseudo + tcp)
















def _pad16(data: bytes) -> bytes:
    return data + b'\x00' * ((16 - len(data) % 16) % 16)















def _jitter_from_samples(samples):
    vals=[float(x) for x in samples if x is not None]
    if len(vals)<2: return 0.0
    return sum(abs(vals[i]-vals[i-1]) for i in range(1,len(vals)))/(len(vals)-1)


def _lower_is_better(value,good,bad,power=1.15):
    if value is None: return None
    value=max(0.0,float(value))
    if value<=good: return 100.0
    if value>=bad: return 0.0
    x=(value-good)/max(1e-9,bad-good)
    return 100.0*((1.0-x)**power)


def _higher_is_better(value,floor,ceiling):
    if value is None: return None
    value=max(0.0,float(value))
    if value<=floor: return 0.0
    if value>=ceiling: return 100.0
    return 100.0*((value-floor)/max(1e-9,ceiling-floor))**0.70


def _speed_scores(results):
    speeds=sorted(float(r['speed_mbps']) for r in results if r.get('speed_mbps') is not None and float(r.get('speed_mbps',0))>0)
    if not speeds: return
    if len(speeds)==1: ceiling=speeds[0]
    else:
        pos=0.95*(len(speeds)-1); lo=int(pos); hi=min(len(speeds)-1,lo+1); frac=pos-lo
        ceiling=speeds[lo]*(1-frac)+speeds[hi]*frac
    ceiling=max(0.001,ceiling)
    for row in results:
        speed=row.get('speed_mbps')
        row['speed_score']=round(min(100.0,100.0*(float(speed)/ceiling)**0.55),2) if speed else None


def _score_result(row,cfg):
    if row.get('status') not in ('verified','connected'):
        row['score']=0.0; return 0.0
    weights=dict(cfg.get('score_weights') or {'loss':30.0,'latency':20.0,'jitter':15.0,'speed':15.0,'reliability':10.0,'service':10.0})
    packet_loss=row.get('packet_loss')
    vals={
        'loss':None if packet_loss is None else _higher_is_better(100.0-float(packet_loss),0,100),
        'latency':_lower_is_better(row.get('median_rtt_ms',row.get('rtt_ms')),15.0,350.0,1.20),
        'jitter':_lower_is_better(row.get('jitter_ms'),2.0,120.0,1.10),
        'speed':row.get('speed_score'),
        'reliability':row.get('reliability_score'),
        'service':row.get('service_score'),
    }
    active=[(k,float(w),vals[k]) for k,w in weights.items() if float(w)>0 and vals.get(k) is not None]
    if not active:
        row['score']=0.0; return 0.0
    total_w=sum(w for _,w,_ in active)
    row['score']=round(max(0.0,min(100.0,sum((w/total_w)*float(v) for _,w,v in active))),2)
    row['loss_score']=round(vals['loss'],2) if vals['loss'] is not None else None
    row['latency_score']=round(vals['latency'],2) if vals['latency'] is not None else None
    row['jitter_score']=round(vals['jitter'],2) if vals['jitter'] is not None else None
    return row['score']


def score_endpoint(e,cfg):
    if e.status!='verified': return 0.0
    row=asdict(e); _score_result(row,cfg)
    e.score=row['score']; e.latency_score=row.get('latency_score'); e.loss_score=row.get('loss_score'); e.jitter_score=row.get('jitter_score')
    return e.score


def _ensure_cf_file(path):
    path=Path(path)
    if path.is_file():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    last=None
    try:
        from urllib.request import urlopen
        with urlopen(RAW_CF_FILE_URL, timeout=20) as r:
            data=r.read()
        if data:
            path.write_bytes(data)
            return path
    except Exception as exc:
        last=exc
    if shutil.which("curl"):
        try:
            proc=subprocess.run(["curl","-fsSL","--retry","2","--connect-timeout","10","--max-time","30",RAW_CF_FILE_URL],capture_output=True)
            if proc.returncode==0 and proc.stdout:
                path.write_bytes(proc.stdout)
                return path
            last=RuntimeError(proc.stderr.decode(errors="replace") if proc.stderr else "curl failed")
        except Exception as exc:
            last=exc
    raise FileNotFoundError(f"Cloudflare CIDR file is missing: {path}. Download failed: {last}")


def load_cidrs(path):
    path=_ensure_cf_file(path) if Path(path).resolve()==DEFAULT_CF_FILE.resolve() or not Path(path).is_file() else Path(path)
    out=[]
    for line in path.read_text().splitlines():
        line=line.strip()
        if not line or line.startswith("#"): continue
        try: out.append(ipaddress.ip_network(line,strict=False))
        except ValueError: pass
    return list(dict.fromkeys(out))


def _fetch_json(url, timeout=20):
    """Fetch JSON from a provider endpoint with urllib/curl fallback."""
    last=None
    try:
        req=Request(url,headers={"User-Agent":"Spider-CDN-Ranges/1.0"})
        with urlopen(req,timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as exc:
        last=exc
    if shutil.which("curl"):
        try:
            proc=subprocess.run(["curl","-fsSL","--retry","2","--connect-timeout","10","--max-time",str(timeout),url],capture_output=True)
            if proc.returncode==0 and proc.stdout:
                return json.loads(proc.stdout.decode("utf-8"))
            last=RuntimeError(proc.stderr.decode(errors="replace") if proc.stderr else "curl failed")
        except Exception as exc:
            last=exc
    raise RuntimeError(f"Could not fetch {url}: {last}")


def refresh_cdn_ranges():
    """Refresh Fastly and Amazon CloudFront IPv4 range snapshots from official endpoints."""
    updated=[]
    fastly_obj=_fetch_json(FASTLY_IP_LIST_URL)
    fastly=list(dict.fromkeys(str(x) for x in fastly_obj.get("addresses",[]) if x))
    DEFAULT_FASTLY_FILE.write_text(
        "# Fastly public IPv4 ranges — source: https://api.fastly.com/public-ip-list\n"
        + "# Refreshed automatically by Spider\n"
        + "\n".join(fastly) + "\n", encoding="utf-8"
    )
    updated.append(("Fastly",len(fastly),str(DEFAULT_FASTLY_FILE)))

    cf_obj=_fetch_json(CLOUDFRONT_IP_LIST_URL)
    global_ips=list(dict.fromkeys(str(x) for x in cf_obj.get("CLOUDFRONT_GLOBAL_IP_LIST",[]) if x))
    regional_ips=list(dict.fromkeys(str(x) for x in cf_obj.get("CLOUDFRONT_REGIONAL_EDGE_IP_LIST",[]) if x))
    combined=list(dict.fromkeys(global_ips+regional_ips))
    DEFAULT_CLOUDFRONT_FILE.write_text(
        "# Amazon CloudFront IPv4 edge ranges — source: https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips\n"
        + "# Refreshed automatically by Spider\n"
        + "# Global edge ranges\n"
        + "\n".join(global_ips) + "\n"
        + "# Regional edge ranges\n"
        + "\n".join(regional_ips) + "\n", encoding="utf-8"
    )
    updated.append(("Amazon CloudFront",len(combined),str(DEFAULT_CLOUDFRONT_FILE)))
    return updated


def cdn_provider_cidrs(provider, *, refresh=False):
    provider=provider.upper()
    if refresh:
        refresh_cdn_ranges()
    mapping={
        "FASTLY":DEFAULT_FASTLY_FILE,
        "AMAZON":DEFAULT_CLOUDFRONT_FILE,
        "CLOUDFRONT":DEFAULT_CLOUDFRONT_FILE,
    }
    if provider in mapping:
        return load_cidrs(mapping[provider])
    if provider=="CLOUDFLARE":
        return load_cidrs(DEFAULT_CF_FILE)
    raise ValueError(f"Unknown CDN provider: {provider}")


def _sample_hosts(net, count, randomize=True):
    host_count = max(0, net.num_addresses - 2)
    count = min(int(count), host_count)
    if count <= 0:
        return []
    if count >= host_count and net.version == 4:
        return list(net.hosts())
    host_bits = net.max_prefixlen - net.prefixlen
    if randomize:
        offsets = set()
        while len(offsets) < count:
            offsets.add(1 + random.getrandbits(host_bits) % max(1, host_count))
        offsets = list(offsets)
    else:
        step = max(1.0, host_count / count)
        offsets = [1 + int(i * step) for i in range(count)]
        offsets = list(dict.fromkeys(min(max(x, 1), net.num_addresses - 2) for x in offsets))
    return [ipaddress.ip_address(int(net.network_address) + off) for off in offsets]






def expand_candidates(cidrs, ports, order='ordered', limit=0):
    # Retained for Advanced/TCP compatibility.
    emitted = 0
    nets = list(cidrs)
    if order == 'random': random.shuffle(nets)
    for port in ports:
        for net in nets:
            if net.num_addresses <= 2:
                hosts = list(net)
            else:
                hosts = _sample_hosts(net, min(254, net.num_addresses - 2), randomize=(order == 'random'))
            for ip in hosts:
                yield str(ip), port
                emitted += 1
                if limit and emitted >= limit: return








def rank(items):
    return sorted(items,key=lambda e:(-e.score,e.median_rtt_ms or 999999))


def tcp_probe(ip,port,timeout=1.0):
    t=time.perf_counter()
    try:
        with socket.create_connection((ip,port),timeout=timeout):
            return True,(time.perf_counter()-t)*1000
    except Exception:
        return False,None


def https_probe(ip,port=443,timeout=1.5):
    t=time.perf_counter()
    try:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with socket.create_connection((ip,port),timeout=timeout) as raw:
            with ctx.wrap_socket(raw,server_hostname='cloudflare.com') as s:
                s.settimeout(timeout)
                s.sendall(b'HEAD / HTTP/1.0\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n')
                s.recv(64)
        return True,(time.perf_counter()-t)*1000
    except Exception:
        return False,None


def https_transfer_probe(ip,port=443,timeout=4.0,target_bytes=262144):
    """Measure real HTTPS body throughput; return None when unsupported."""
    t0=time.perf_counter()
    try:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with socket.create_connection((ip,port),timeout=timeout) as raw:
            with ctx.wrap_socket(raw,server_hostname='speed.cloudflare.com') as s:
                s.settimeout(timeout)
                req=(f'GET /__down?bytes={int(target_bytes)} HTTP/1.1\r\n'
                     'Host: speed.cloudflare.com\r\nConnection: close\r\n'
                     'User-Agent: Spider-SpeedProbe/1.0\r\n\r\n').encode()
                s.sendall(req)
                header=b''
                while b'\r\n\r\n' not in header and len(header)<16384:
                    chunk=s.recv(4096)
                    if not chunk: break
                    header+=chunk
                marker=header.find(b'\r\n\r\n')
                if marker<0: return None
                total=len(header)-marker-4
                while total<target_bytes and time.perf_counter()-t0<timeout:
                    chunk=s.recv(min(256*1024,target_bytes-total))
                    if not chunk: break
                    total+=len(chunk)
                elapsed=max(0.001,time.perf_counter()-t0)
                if total<32768: return None
                return (total*8.0/elapsed)/1_000_000.0
    except Exception:
        return None


def add_packet_loss(results,probe_fn,state,*,limit=None,speed_probe=None,stop=None):
    """Measure quality with an interruptible, bounded second pass.

    When Q/Ctrl+C stops the main scan, do not start another long quality pass.
    Instead, score the endpoints using the metrics already known from the
    successful connection probe (latency + service), so the results table can
    be rendered immediately and the caller can return to its menu.
    """
    if not results: return results
    stopped = bool(stop is not None and stop.event.is_set())
    attempts=max(3,int(state.cfg.get('probe_count',5)))
    visible=max(1,int(limit if limit is not None else state.cfg.get('quality_probe_limit',25)))
    ranked=sorted(results,key=lambda x:(-x.get('score',0),x.get('rtt_ms',999999)))

    # Q during the live scan must be a true stop: no post-scan network work.
    if stopped:
        for row in ranked:
            row.setdefault('packet_loss', None)
            row.setdefault('jitter_ms', None)
            row.setdefault('speed_mbps', None)
            row.setdefault('reliability_score', None)
            row['score_mode'] = 'partial'
            _score_result(row,state.cfg)
        return sorted(results,key=lambda x:(-x.get('score',0),x.get('median_rtt_ms',x.get('rtt_ms',999999))))

    timeout=float(state.cfg.get('advanced_timeout',1.0))
    for row in ranked[:visible]:
        if stop is not None and stop.event.is_set():
            break
        ip=row.get('ip'); port=int(row.get('port',443)); ok_count=0; attempted=0; rtts=[]
        for _ in range(attempts):
            if stop is not None and stop.event.is_set():
                break
            attempted += 1
            try: ok,rtt=probe_fn(ip,port,timeout)
            except Exception: ok,rtt=False,None
            if ok:
                ok_count+=1
                if rtt is not None: rtts.append(float(rtt))
        # An interrupt during a row should leave what we already measured,
        # rather than launching speed tests after the user asked to stop.
        if not rtts and row.get('rtt_ms') is not None: rtts=[float(row['rtt_ms'])]
        measured_attempts=max(1, attempted if (stop is not None and stop.event.is_set()) else attempts)
        row['attempts']=measured_attempts; row['success_count']=ok_count
        row['packet_loss']=round(100.0*(measured_attempts-ok_count)/measured_attempts,2) if measured_attempts else None
        if rtts:
            row['rtt_ms']=round(statistics.median(rtts),2)
            row['median_rtt_ms']=row['rtt_ms']
            row['min_rtt_ms']=round(min(rtts),2)
            row['jitter_ms']=round(_jitter_from_samples(rtts),2)
        row['reliability_score']=round(100.0*ok_count/max(1,measured_attempts),2)
        if speed_probe is not None and ok_count and not (stop is not None and stop.event.is_set()):
            try: speed=speed_probe(ip,port,max(3.0,timeout*3.0))
            except Exception: speed=None
            if speed is not None and speed>0: row['speed_mbps']=round(float(speed),3)
        _score_result(row,state.cfg)

    if not (stop is not None and stop.event.is_set()):
        _speed_scores(results)
    for row in results: _score_result(row,state.cfg)
    return sorted(results,key=lambda x:(-x.get('score',0),x.get('median_rtt_ms',x.get('rtt_ms',999999))))


def scan_range(net,kind,state,ports=None,order="ordered",limit=0,stop=None,target_valid=0,score_protocol=None):
    """Bounded live connectivity scan; accepts one network or a list of networks."""
    stop = stop or StopController().start()
    plist=[int(state.cfg["https_port"])] if kind=="https" else [int(x) for x in (ports or state.cfg["tcp_ports"])]
    workers=max(1,int(state.cfg["workers"]))
    max_in=max(workers,int(state.cfg.get("max_in_flight",workers*2)))
    nets=list(net) if isinstance(net,(list,tuple)) else [net]
    candidates=expand_candidates(nets,plist,order,limit)
    results=[]; submitted=0; finished=0; started=time.time(); stopped=False
    fn=https_probe if kind=="https" else tcp_probe
    timeout=float(state.cfg.get("advanced_timeout" if score_protocol else "handshake_timeout",1.0))
    ex=ThreadPoolExecutor(max_workers=workers)
    futs={}
    def consume(done_futures):
        nonlocal finished, stopped
        for f in as_completed(done_futures):
            # done_futures is a list/set of Future objects; futs is the
            # Future -> (ip, port) mapping. Never index the list with a Future.
            meta=futs.pop(f, None)
            if meta is None:
                continue
            ip,p=meta
            finished+=1
            try: ok,rtt=f.result()
            except Exception: ok,rtt=False,None
            if ok:
                row={"ip":ip,"port":p,"rtt_ms":round(rtt,2),"median_rtt_ms":round(rtt,2),"status":"connected","score":0.0,"service_score":100.0 if kind=="https" else None}
                results.append(row)
                print(f"[{len(results):03d}] ✓ {ip}:{p:<5} {rtt:7.1f} ms", flush=True)
                if target_valid and len(results)>=target_valid:
                    stop.request(); stopped=True
                    break
            if stop.event.is_set():
                stopped=True; break
    try:
        for ip,p in candidates:
            if stop.event.is_set(): stopped=True; break
            futs[ex.submit(fn,ip,p,timeout)]=(ip,p); submitted+=1
            if len(futs)>=max_in:
                consume(list(futs))
                if stop.event.is_set(): break
        if futs and not stop.event.is_set():
            consume(list(futs))
        elif futs and stop.event.is_set():
            for f in list(futs): f.cancel()
    except KeyboardInterrupt:
        stop.request(); stopped=True
    finally:
        try: ex.shutdown(wait=False,cancel_futures=True)
        except TypeError: ex.shutdown(wait=False)
        if stopped or stop.event.is_set():
            print(f"\n[!] Scan stopped — verified={len(results)}", flush=True)
        else:
            print(f"\nScan complete — probes={finished}/{submitted}, verified={len(results)}, time={time.time()-started:.1f}s", flush=True)

    ranked=sorted(results,key=lambda x:x.get("rtt_ms",999999))
    speed_probe=https_transfer_probe if any(int(r.get("port",0))==443 for r in ranked) else None
    try:
        return add_packet_loss(ranked,fn,state,speed_probe=speed_probe,stop=stop)
    finally:
        # Keep the Q watcher alive through the quality pass, then restore the
        # terminal and terminate the watcher once the results are ready.
        try: stop.close()
        except Exception: pass

def print_result(e):
    print(f"  ✓ {e.ip}:{e.port:<5} {e.median_rtt_ms:7.1f}ms loss={e.packet_loss:5.1f}% score={e.score:5.1f}")



def read_config_text(prompt="Paste config"):
    first=input(f"{prompt} (or @/path/to/config): ").strip()
    if first.startswith("@") and Path(first[1:]).is_file():
        return Path(first[1:]).read_text()
    if not first:
        return ""
    # Single-line configs (VLESS/Trojan/JSON one-liners) finish immediately.
    if "\n" not in first and (first.startswith(("vless://","vmess://","trojan://","ss://","http://","https://","{") ) and first.endswith(("}","/",""))):
        return first
    lines=[first]
    print("Paste remaining lines; submit an empty line to finish.")
    while True:
        line=input()
        if line=="": break
        lines.append(line)
    return "\n".join(lines)


def extract_server_and_port(text):
    text=text.strip()
    # JSON / JSON-like panel configs.
    try:
        obj=json.loads(text)
        found=None
        port=None
        def walk(x):
            nonlocal found,port
            if isinstance(x,dict):
                for k,v in x.items():
                    kl=str(k).lower()
                    if found is None and kl=="server" and isinstance(v,str): found=v
                    if port is None and kl in ("port","server_port","serverport"):
                        try: port=int(v)
                        except Exception: pass
                    walk(v)
            elif isinstance(x,list):
                for v in x: walk(v)
        walk(obj)
        return found,port,obj
    except Exception:
        pass
    # URI style proxy config.
    try:
        from urllib.parse import urlsplit
        if "://" in text:
            u=urlsplit(text)
            return u.hostname,u.port,None
    except Exception:
        pass
    m=re.search(r'(?im)^[\s\"]*server\s*[:=]\s*[\"\']?([^\"\'\s,}]+)', text)
    pm=re.search(r'(?im)^[\s\"]*(?:port|server_port)\s*[:=]\s*[\"\']?(\d+)', text)
    return (m.group(1) if m else None, int(pm.group(1)) if pm else None, None)


def replace_server_in_config(text,new_ip):
    text=text.strip()
    try:
        obj=json.loads(text)
        replaced=False
        def walk(x):
            nonlocal replaced
            if isinstance(x,dict):
                for k in list(x):
                    if str(k).lower()=="server" and isinstance(x[k],str):
                        x[k]=new_ip; replaced=True
                    else: walk(x[k])
            elif isinstance(x,list):
                for v in x: walk(v)
        walk(obj)
        if replaced:
            return json.dumps(obj,ensure_ascii=False,indent=2)
    except Exception:
        pass
    # URI form: replace host in netloc, preserving credentials/port/query.
    try:
        from urllib.parse import urlsplit,urlunsplit
        if "://" in text:
            u=urlsplit(text)
            if u.netloc:
                userinfo=""
                hp=u.netloc.rsplit("@",1)
                if len(hp)==2: userinfo=hp[0]+"@"; hostpart=hp[1]
                else: hostpart=hp[0]
                port_suffix=f":{u.port}" if u.port else ""
                try:
                    host_for_uri = f"[{new_ip}]" if ipaddress.ip_address(new_ip).version == 6 else new_ip
                except ValueError:
                    host_for_uri = new_ip
                return urlunsplit((u.scheme, userinfo+host_for_uri+port_suffix, u.path, u.query, u.fragment))
    except Exception:
        pass
    # key=value / YAML-ish text.
    pat=r'(?im)^(\s*[\"\']?server[\"\']?\s*[:=]\s*[\"\']?)([^\"\'\s,}]+)([\"\']?.*)$'
    return re.sub(pat,lambda m:m.group(1)+new_ip+m.group(3),text,count=1)


def _nested_get(obj, keys):
    found=None
    if isinstance(obj,dict):
        for k,v in obj.items():
            if str(k).lower() in keys and found is None: found=v
            got=_nested_get(v,keys)
            if found is None and got is not None: found=got
    elif isinstance(obj,list):
        for v in obj:
            got=_nested_get(v,keys)
            if found is None and got is not None: found=got
    return found


def _load_default_dpi_fields():
    try:
        obj=json.loads(DPI_DEFAULT_FILE.read_text())
        return obj.get("fingerprint","unsafe"), obj.get("finalmask",""), obj.get("cybersuit","")
    except Exception:
        return "unsafe", "", ""


def _quote_uri_value(value):
    from urllib.parse import quote
    return quote(str(value), safe="")


def build_dpi_config(text):
    """Return the complete input URI with Spider DPI parameters applied.

    The input URI is preserved except that fp/cs/fm are replaced with:
      fp=unsafe
      cs=<bundled cipher suites>
      fm=<bundled fragment-mask JSON>
    """
    text=text.strip()
    if text.startswith("@") and Path(text[1:]).is_file():
        text=Path(text[1:]).read_text(encoding="utf-8").strip()
    if "://" not in text or "@" not in text:
        raise ValueError("DPI expects a VLESS/Trojan/other URI config")

    from urllib.parse import urlsplit, urlunsplit, parse_qsl
    try:
        u=urlsplit(text)
    except Exception as exc:
        raise ValueError(f"Invalid config URI: {exc}") from exc
    if not u.scheme or not u.netloc:
        raise ValueError("Invalid config URI")

    fp, fm, cs = _load_default_dpi_fields()
    # This feature intentionally uses the Spider defaults, so the fingerprint
    # is always unsafe and the bundled finalmask/ciphersuite are always applied.
    fp="unsafe"
    pairs=[]
    for k,v in parse_qsl(u.query, keep_blank_values=True):
        if k.lower() in {"fp","fingerprint","cs","cybersuit","ciphersuite","cipher_suite","fm","finalmask","final_mask"}:
            continue
        pairs.append((k,v))
    pairs.extend((("fp",fp),("cs",cs),("fm",fm)))
    query="&".join(f"{_quote_uri_value(k)}={_quote_uri_value(v)}" for k,v in pairs)
    return urlunsplit((u.scheme,u.netloc,u.path,query,u.fragment))


def build_dpi_json(text):
    """Backward-compatible extractor for callers that still need JSON fields."""
    text=text.strip()
    if text.startswith("@") and Path(text[1:]).is_file():
        text=Path(text[1:]).read_text(encoding="utf-8").strip()
    default_fp, default_fm, default_cs = _load_default_dpi_fields()
    if "://" in text:
        from urllib.parse import urlsplit, parse_qs, unquote
        u=urlsplit(text)
        q=parse_qs(u.query,keep_blank_values=True)
        fp=(q.get("fp") or q.get("fingerprint") or [default_fp])[0]
        cs=(q.get("cs") or q.get("cybersuit") or q.get("ciphersuite") or [default_cs])[0]
        fm=(q.get("fm") or q.get("finalmask") or q.get("final_mask") or [default_fm])[0]
        return {"fingerprint":unquote(fp),"finalmask":unquote(fm),"cybersuit":unquote(cs)}
    try:
        obj=json.loads(text)
    except Exception as exc:
        raise ValueError("DPI input must be a JSON object/file or a VLESS/Trojan URI") from exc
    fp=_nested_get(obj,{"fp","fingerprint"}) or default_fp
    cs=_nested_get(obj,{"cs","cybersuit","ciphersuite","cipher_suite"}) or default_cs
    fm=_nested_get(obj,{"fm","finalmask","final_mask"}) or default_fm
    return {"fingerprint":fp,"finalmask":fm,"cybersuit":cs}


def advanced_config_scan(state, kind, base_config):
    server, port, obj = extract_server_and_port(base_config)
    if not server:
        raise ValueError("Could not find server/host in config")
    try:
        cfg_port=int(port or 443)
    except Exception:
        cfg_port=443
    if kind.upper()=="RAILWAY":
        cfg_port=443
    ui_choice([("1","Ordered"),("2","Random"),("0","Back")], f"{kind.title()} scan order")
    order_sel=input("\nSelect › ").strip()
    if order_sel=="0": return []
    if order_sel not in ("1","2"): return []
    order="ordered" if order_sel=="1" else "random"
    provider=kind.upper()
    if provider=="RAILWAY":
        cidrs=list(RAILWAY_TCP_CIDRS)
        cfg_port=443
        title="Railway"
        out_name="advanced-railway"
    elif provider=="CLOUDFLARE":
        cidrs=load_cidrs(DEFAULT_CF_FILE)
        title="Cloudflare"
        out_name="advanced-cloudflare"
    elif provider=="FASTLY":
        cidrs=cdn_provider_cidrs("FASTLY")
        cfg_port=443
        title="Fastly"
        out_name="advanced-fastly"
    elif provider in {"AMAZON", "CLOUDFRONT"}:
        cidrs=cdn_provider_cidrs("AMAZON")
        cfg_port=443
        title="Amazon CloudFront"
        out_name="advanced-amazon-cloudfront"
    else:
        raise ValueError("Unknown advanced scanner")
    ui_clear(); ui_header(state, f"ADVANCED {title.upper()} SCAN")
    print(f"Target: {server}:{cfg_port}  |  replacing server only")
    print("Only verified endpoints are shown live.")
    print("Each successful result is converted to a complete config with server replaced.")
    print("Press Q or Ctrl+C to stop.\n")

    def on_success(row):
        conf=replace_server_in_config(base_config, row["ip"])
        # Keep live output readable while still showing the actual generated config,
        # not merely the candidate IP. The complete config is also written after ranking.
        return conf

    results=[]
    stop=StopController().start()
    try:
        results=scan_cidrs_connectivity(
            state,cidrs,[cfg_port],order=order,
            limit=int(state.cfg.get("advanced_max_candidates",4096)),
            target_valid=int(state.cfg.get("advanced_valid",20)),
            stop=stop,
            success_renderer=on_success,
        )
    finally:
        try: stop.close()
        except Exception: pass
    results=sorted(results,key=lambda x:(-x.get("score",0),x.get("rtt_ms",999999)))
    out_dir=HOME/out_name
    return print_ranked_configs(base_config, results, out_dir, title)


def scan_cidrs_connectivity(state, cidrs, ports, order="ordered", limit=0, target_valid=0, stop=None, success_renderer=None):
    """Streaming success-only TCP scan across multiple CIDRs.

    When success_renderer is supplied, only verified candidates are rendered live
    and the renderer receives the full result row so Advanced can show the generated
    config rather than an IP-only line.
    """
    stop=stop or StopController().start()
    workers=max(1,int(state.cfg["workers"]))
    max_in=max(workers,int(state.cfg.get("max_in_flight",workers*2)))
    candidates=expand_candidates(cidrs,ports,order,limit)
    ex=ThreadPoolExecutor(max_workers=workers); futs={}; results=[]; stopped=False

    def handle_future(f):
        ip2,p2=futs.pop(f)
        try: ok,rtt=f.result()
        except Exception: ok,rtt=False,None
        if not ok:
            return False
        row={"ip":ip2,"port":p2,"rtt_ms":round(rtt,2),"median_rtt_ms":round(rtt,2),"status":"connected","score":0.0,"service_score":100.0 if int(p2)==443 else None}
        results.append(row)
        if success_renderer is not None:
            try:
                rendered=success_renderer(row)
            except Exception:
                rendered=None
            if rendered:
                print(f"[{len(results):03d}] ✓ {rtt:7.1f} ms ",flush=True)
                print(f"      {rendered}",flush=True)
            else:
                print(f"[{len(results):03d}] ✓ {ip2}:{p2:<5} {rtt:7.1f} ms ",flush=True)
        else:
            print(f"[{len(results):03d}] ✓ {ip2}:{p2:<5} {rtt:7.1f} ms ",flush=True)
        return True

    try:
        for ip,p in candidates:
            if stop.event.is_set(): stopped=True; break
            futs[ex.submit(tcp_probe,ip,p,float(state.cfg.get("advanced_timeout",1.0)))]=(ip,p)
            if len(futs)>=max_in:
                for f in as_completed(list(futs)):
                    handle_future(f)
                    if target_valid and len(results)>=target_valid:
                        stop.request(); stopped=True; break
                    if stop.event.is_set(): stopped=True; break
                if stop.event.is_set(): break
        if not stop.event.is_set():
            for f in as_completed(list(futs)):
                handle_future(f)
                if target_valid and len(results)>=target_valid:
                    stop.request(); stopped=True; break
                if stop.event.is_set():
                    stopped=True; break
        else:
            for f in list(futs): f.cancel()
    except KeyboardInterrupt:
        stop.request(); stopped=True
    finally:
        try: ex.shutdown(wait=False,cancel_futures=True)
        except TypeError: ex.shutdown(wait=False)
        print((f"\n[!] Scan stopped — verified={len(results)}" if stopped or stop.event.is_set() else f"\nScan complete — verified={len(results)}"),flush=True)
    ranked=sorted(results,key=lambda x:x.get("rtt_ms",999999))
    speed_probe=https_transfer_probe if any(int(r.get("port",0))==443 for r in ranked) else None
    return add_packet_loss(ranked,tcp_probe,state,speed_probe=speed_probe)

def ui_clear():
    if os.environ.get("SPIDER_NO_CLEAR") == "1":
        return
    if RICH_OK and console is not None:
        try:
            console.clear()
            return
        except Exception:
            pass
    # Fallback for minimal Termux/Linux terminals.
    try:
        if sys.stdout.isatty():
            subprocess.run(["clear"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    print("\033[2J\033[H", end="")


def ui_rule(char="─", width=78):
    return char * width


def ui_header(state, title="NETWORK SCANNER"):
    endpoints = len(endpoint_from_cache(state)) if state.cache else 0
    if RICH_OK:
        left = Text("SPIDER", style="bold cyan")
        left.append(f"  {title}", style="bold white")
        body = Text()
        body.append(f"v{VERSION}", style="dim")
        body.append(f"   Verified: {endpoints}", style="white")
        console.print(Panel(body, title=left, border_style="cyan", padding=(0,1)))
    else:
        print(ui_rule())
        print(f" SPIDER {title}  v{VERSION}")
        print(f" VERIFIED: {endpoints}")
        print(ui_rule())


def ui_pause(msg="Press Enter to continue..."):
    try: input(f"\n{msg}")
    except EOFError: pass


def ui_choice(items, title="Select"):
    if RICH_OK:
        table = Table(title=title, box=None, show_header=False, padding=(0,1))
        table.add_column("#", style="bold cyan", width=4)
        table.add_column("Option", style="white")
        for key, label in items:
            table.add_row(str(key), label)
        console.print(table)
    else:
        print(f"\n{title}")
        print(ui_rule("·", 54))
        for key,label in items:
            print(f" [{key}] {label}")
        print(ui_rule("·", 54))


def ui_result_table(results,title='Results',limit=25):
    if not results:
        if RICH_OK: console.print(Panel('No verified results.',title=title,border_style='yellow'))
        else: print('\nNo verified results.')
        return
    partial=any(r.get('score_mode')=='partial' for r in results)
    if partial:
        title += ' — partial scores (stopped early)'
    rows=results[:limit]
    if RICH_OK:
        t=Table(title=title,show_lines=False)
        for col in ('#','IP','Port','Ping','Jitter','Loss','Speed','Score'):
            t.add_column(col,justify='right' if col!='IP' else 'left')
        for i,r in enumerate(rows,1):
            def fmt(k,suffix=''):
                v=r.get(k,'—')
                if v is None: return '—'
                return f'{v:.1f}{suffix}' if isinstance(v,(int,float)) else str(v)
            t.add_row(str(i),str(r.get('ip','')),str(r.get('port','')),fmt('median_rtt_ms'),fmt('jitter_ms'),fmt('packet_loss','%'),fmt('speed_mbps'),fmt('score'))
        console.print(t)
    else:
        print(f'\n{title}'); print(ui_rule('─',112))
        print(f"{'#':>3} {'IP':<40} {'Port':>5} {'Ping':>8} {'Jitter':>9} {'Loss':>8} {'Speed':>10} {'Score':>7}")
        for i,r in enumerate(rows,1):
            ping=r.get('median_rtt_ms',r.get('rtt_ms',0)); jitter=r.get('jitter_ms','—'); score=r.get('score',0); loss=r.get('packet_loss','—'); speed=r.get('speed_mbps','—')
            jitter_s=f'{float(jitter):.1f}' if isinstance(jitter,(int,float)) else str(jitter)
            loss_s=f'{float(loss):.1f}%' if isinstance(loss,(int,float)) else str(loss)
            speed_s=f'{float(speed):.1f}' if isinstance(speed,(int,float)) else str(speed)
            print(f"{i:>3} {str(r.get('ip','')):<40} {str(r.get('port','')):>5} {float(ping):>8.1f} {jitter_s:>9} {loss_s:>8} {speed_s:>10} {float(score):>7.1f}")


def print_ranked_configs(base_config, results, out_dir, title):
    """Write and display complete configs with the verified IP installed as server.

    Advanced output intentionally does not expose an IP-only result table: each
    successful endpoint is represented by the actual ready-to-use config.
    """
    out_dir=Path(out_dir); out_dir.mkdir(parents=True,exist_ok=True)
    generated=[]
    safe_title=re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "advanced"
    for i,r in enumerate(results,1):
        ip=r["ip"] if isinstance(r,dict) else r.ip
        conf=replace_server_in_config(base_config,ip)
        safe_ip=ip.replace(':','_')
        path=out_dir/f"{safe_title}-{i:03d}-{safe_ip}.conf"
        path.write_text(conf,encoding="utf-8")
        generated.append((i,r,path,conf))

    if not generated:
        print("\nNo healthy configs generated.",flush=True)
        return []

    all_path=out_dir/(safe_title+"-all.txt")
    all_path.write_text("\n".join(conf for _,_,_,conf in generated)+"\n",encoding="utf-8")

    print(f"\nGenerated {len(generated)} ready-to-use configs -> {out_dir}")
    print(f"Combined output: {all_path}")
    print("\nRanked configs (server replaced with the verified endpoint):\n")
    if RICH_OK:
        for i,r,path,conf in generated[:30]:
            ping=r.get("median_rtt_ms",r.get("rtt_ms",0)); jitter=r.get("jitter_ms")
            loss=r.get("packet_loss"); speed=r.get("speed_mbps"); score=r.get("score",0)
            jitter_s=f"{float(jitter):.1f}" if isinstance(jitter,(int,float)) else "—"
            loss_s=f"{float(loss):.1f}%" if isinstance(loss,(int,float)) else "—"
            speed_s=f"{float(speed):.1f}Mbps" if isinstance(speed,(int,float)) else "N/A"
            console.print(Panel(
                conf,
                title=f"#{i:03d}  ✓ verified   ping={float(ping):.1f}ms  jitter={jitter_s}ms  loss={loss_s}  speed={speed_s}  score={float(score):.1f}",
                subtitle=str(path),
                border_style="green",
                padding=(0,1),
            ))
    else:
        for i,r,path,conf in generated[:30]:
            ping=float(r.get("median_rtt_ms",r.get("rtt_ms",0))); score=float(r.get("score",0))
            jitter=r.get("jitter_ms"); loss=r.get("packet_loss"); speed=r.get("speed_mbps")
            print(f"#{i:03d} ✓ verified  ping={ping:.1f}ms  jitter={float(jitter):.1f}ms  loss={float(loss):.1f}%  speed={float(speed):.1f}Mbps  score={score:.1f}" if all(isinstance(x,(int,float)) for x in (jitter,loss,speed)) else f"#{i:03d} ✓ verified  ping={ping:.1f}ms  score={score:.1f}")
            print(conf)
            print(f"file: {path}\n")

    if RICH_OK:
        console.print(Panel(
            f"Primary\n{generated[0][3]}\n\nFallbacks: {max(0,len(generated)-1)}\nCombined: {all_path}",
            title="Ready Configs",
            border_style="cyan",
        ))
    else:
        print("Primary")
        print(generated[0][3])
        print(f"Fallbacks: {max(0,len(generated)-1)}")
        print(f"Combined: {all_path}")
    return generated






def _tcp_rtt(host="1.1.1.1",port=443, count=8, timeout=2.0):
    samples=[]
    for _ in range(count):
        t=time.perf_counter()
        try:
            with socket.create_connection((host,port),timeout=timeout):
                samples.append((time.perf_counter()-t)*1000)
        except Exception:
            samples.append(None)
        time.sleep(0.12)
    ok=[x for x in samples if x is not None]
    if not ok: raise RuntimeError("TCP RTT test failed")
    jitter=(sum(abs(ok[i]-ok[i-1]) for i in range(1,len(ok)))/max(1,len(ok)-1)) if len(ok)>1 else 0.0
    return statistics.median(ok), jitter, ok


def _http_download(url, seconds=5):
    req=Request(url,headers={"User-Agent":"Spider-SpeedTest/2.0"})
    start=time.perf_counter(); total=0
    with urlopen(req,timeout=max(8,seconds+3)) as r:
        while time.perf_counter()-start < seconds:
            chunk=r.read(256*1024)
            if not chunk: break
            total += len(chunk)
    elapsed=max(0.001,time.perf_counter()-start)
    return (total*8/elapsed)/1_000_000, total, elapsed


def _http_upload(url, size_mb=4):
    payload=os.urandom(size_mb*1024*1024)
    start=time.perf_counter()
    req=Request(url,data=payload,method="POST",headers={"Content-Type":"application/octet-stream","Content-Length":str(len(payload)),"User-Agent":"Spider-SpeedTest/2.0"})
    with urlopen(req,timeout=20) as r: r.read(64)
    elapsed=max(0.001,time.perf_counter()-start)
    return (len(payload)*8/elapsed)/1_000_000, len(payload), elapsed


def run_speed_test():
    if RICH_OK:
        console.print(Panel("Ping and jitter use repeated TCP connects to 1.1.1.1:443.\nDownload/upload use Cloudflare's public speed-test HTTP endpoints.\nPress Ctrl+C to stop.", title="Speed Test", border_style="cyan"))
    else:
        print("Speed Test: TCP RTT + HTTP bandwidth test; Ctrl+C stops.")
    ping,jitter,_=_tcp_rtt()
    print(f"  Ping     : {ping:.1f} ms")
    print(f"  Jitter   : {jitter:.1f} ms")
    down,_,_=_http_download("https://speed.cloudflare.com/__down?bytes=10000000",seconds=5)
    print(f"  Download : {down:.2f} Mbps")
    up,_,_=_http_upload("https://speed.cloudflare.com/__up",size_mb=4)
    print(f"  Upload   : {up:.2f} Mbps")
    return {"ping_ms":round(ping,2),"jitter_ms":round(jitter,2),"download_mbps":round(down,2),"upload_mbps":round(up,2)}


# -------------------------
# Connect helpers (Aether / Xray)
# -------------------------
CONNECT_ROOT = Path(__file__).resolve().parent.parent / "connect"
AETHER_ROOT = CONNECT_ROOT / "aether"
AETHER_SOURCE_ARCHIVE = CONNECT_ROOT / "aether-source.zip"
XRAY_ROOT = CONNECT_ROOT / "xray"
XRAY_BINARY = XRAY_ROOT / "xray"
AETHER_BUILD = AETHER_ROOT / "aether"
CONNECT_STATE_FILE = HOME / "connect.json"
XRAY_CONFIG_DIR = HOME / "xray"
XRAY_CONFIG_FILE = XRAY_CONFIG_DIR / "config.json"
AETHER_CONFIG_DIR = HOME / "aether"
AETHER_SCRIPT = AETHER_ROOT / "aether.sh"
AETHER_LOG = HOME / "aether.log"
XRAY_LOG = HOME / "xray.log"
SNI_SPOOF_PROXY = CONNECT_ROOT / "sni-spoof" / "spoof_proxy.py"
SNI_SPOOF_LISTEN_HOST = "127.0.0.1"
SNI_SPOOF_LISTEN_PORT = 40443
CONNECT_PROC = {}


def _connect_state(state):
    cfg = state.cfg
    cfg.setdefault("lan_share_proxy", False)
    cfg.setdefault("aether_mode", "masque")
    cfg.setdefault("xray_tun_name", "spider-tun0")
    cfg.setdefault("xray_tun_mtu", 1500)
    cfg.setdefault("sni_spoof_auto_ip_limit", 512)
    cfg.setdefault("sni_spoof_sni_limit", 64)
    cfg.setdefault("sni_spoof_max_candidates", 2048)
    cfg.setdefault("sni_spoof_batch_size", 64)
    cfg.setdefault("sni_spoof_timeout", 2.5)
    cfg.setdefault("xray_ping_providers", [
        {"name":"Cloudflare","host":"1.1.1.1","port":443},
        {"name":"Google","host":"8.8.8.8","port":443},
        {"name":"Quad9","host":"9.9.9.9","port":443}
    ])
    return cfg


def get_local_ips():
    """Return local non-loopback addresses, best effort across Linux/Termux/iSH."""
    found=[]
    try:
        host=socket.gethostname()
        for item in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_DGRAM):
            addr=item[4][0].split('%',1)[0]
            if addr and not addr.startswith('127.') and addr != '::1':
                if addr not in found: found.append(addr)
    except Exception:
        pass
    # UDP connect does not send traffic but lets the kernel expose the chosen source address.
    for target in (("1.1.1.1",443),("8.8.8.8",443),("2606:4700:4700::1111",443)):
        family=socket.AF_INET6 if ':' in target[0] else socket.AF_INET
        try:
            with socket.socket(family,socket.SOCK_DGRAM) as s:
                s.settimeout(0.8); s.connect(target); addr=s.getsockname()[0].split('%',1)[0]
                if addr and not addr.startswith('127.') and addr != '::1' and addr not in found:
                    found.append(addr)
        except Exception: pass
    try:
        ip_cmd=shutil.which('ip')
        if ip_cmd:
            out=subprocess.run([ip_cmd,'-o','addr','show','scope','global'],capture_output=True,text=True,timeout=2,check=False).stdout
            for tok in out.split():
                if '/' in tok and (':' in tok or tok[0].isdigit()):
                    addr=tok.split('/',1)[0]
                    if addr not in found and addr not in {'127.0.0.1','::1'}: found.append(addr)
    except Exception: pass
    return found


def proxy_bind(state):
    return "0.0.0.0:1819" if bool(_connect_state(state).get("lan_share_proxy")) else "127.0.0.1:1819"


def split_bind(bind):
    host,_,port=bind.rpartition(':')
    return host or '127.0.0.1', int(port or 1819)


def port_in_use(host='127.0.0.1', port=1819):
    family=socket.AF_INET6 if ':' in host else socket.AF_INET
    try:
        with socket.socket(family,socket.SOCK_STREAM) as s:
            s.settimeout(0.25); return s.connect_ex((host,port)) == 0
    except Exception:
        return False


def _write_connect_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
    try: os.chmod(path,0o600)
    except Exception: pass


def aether_binary():
    if AETHER_BUILD.is_file() and os.access(AETHER_BUILD,os.X_OK): return AETHER_BUILD
    installed=shutil.which('aether')
    if installed: return Path(installed)
    return None


def ensure_aether_ready():
    # Aether is launched through the bundled ./aether.sh wrapper.
    if os.name == 'posix' and hasattr(os, 'uname') and os.uname().machine not in ('x86_64', 'amd64'):
        raise RuntimeError(f"Bundled Aether is Linux x86_64 only; detected {os.uname().machine}. Use a matching Aether build for this architecture.")
    if not AETHER_SCRIPT.is_file():
        raise FileNotFoundError(f"Aether launcher is missing. Expected {AETHER_SCRIPT}")
    if AETHER_BUILD.is_file():
        try:
            os.chmod(AETHER_BUILD, 0o755)
        except Exception:
            pass
    if not aether_binary():
        installed=shutil.which('aether')
        if not installed:
            raise FileNotFoundError(
                "Bundled Aether binary is missing. Expected connect/aether/aether (Linux x86_64)."
            )
    try:
        os.chmod(AETHER_SCRIPT, 0o755)
    except Exception:
        pass
    return AETHER_SCRIPT


def load_json_config_text(text):
    text=text.strip()
    if text.startswith('@') and Path(text[1:]).is_file():
        text=Path(text[1:]).read_text(encoding='utf-8')
    try:
        obj=json.loads(text)
    except Exception as exc:
        raise ValueError(f"Xray requires a valid JSON configuration: {exc}")
    if not isinstance(obj,dict):
        raise ValueError("Xray configuration root must be a JSON object")
    if not isinstance(obj.get('outbounds'),list) or not obj.get('outbounds'):
        raise ValueError("Xray configuration must contain at least one outbound")
    return obj


def prepare_xray_config(state,base_text,mode):
    obj=load_json_config_text(base_text)
    obj=copy.deepcopy(obj)
    inbounds=obj.get('inbounds') if isinstance(obj.get('inbounds'),list) else []
    # Remove only Spider-managed inbounds from previous runs.
    inbounds=[x for x in inbounds if not (isinstance(x,dict) and str(x.get('tag','')).startswith('spider-'))]
    if mode=='proxy':
        bind=proxy_bind(state); host,port=split_bind(bind)
        existing=None
        for x in inbounds:
            if isinstance(x,dict) and str(x.get('protocol','')).lower()=='socks':
                existing=x; break
        if existing is None:
            existing={'protocol':'socks','settings':{'auth':'noauth','udp':True},'sniffing':{'enabled':True,'destOverride':['http','tls','quic']},'tag':'spider-proxy'}
            inbounds.insert(0,existing)
        existing['listen']=host; existing['port']=port; existing['tag']='spider-proxy'
        existing.setdefault('settings',{})['udp']=True
        existing.setdefault('settings',{}).setdefault('auth','noauth')
        existing['sniffing']={'enabled':True,'destOverride':['http','tls','quic']}
    elif mode=='tun':
        if os.name!='posix':
            raise RuntimeError('Xray TUN mode in Spider is intended for Linux/macOS/other supported POSIX hosts.')
        name=str(_connect_state(state).get('xray_tun_name') or 'spider-tun0')
        try: mtu=max(576,int(_connect_state(state).get('xray_tun_mtu',1500)))
        except Exception: mtu=1500
        settings={'name':name,'mtu':mtu,'gateway':['172.19.0.1/30','fd00:1819::1/64'],'dns':['1.1.1.1','8.8.8.8'],'autoSystemRoutingTable':['0.0.0.0/0','::/0'],'autoOutboundsInterface':'auto'}
        existing=None
        for x in inbounds:
            if isinstance(x,dict) and str(x.get('protocol','')).lower()=='tun': existing=x; break
        if existing is None:
            existing={'protocol':'tun','tag':'spider-tun'}; inbounds.insert(0,existing)
        existing.clear(); existing.update({'protocol':'tun','settings':settings,'sniffing':{'enabled':True,'destOverride':['http','tls','quic']},'tag':'spider-tun'})
    else:
        raise ValueError('Unknown Xray mode')
    obj['inbounds']=inbounds
    return obj

def xray_binary():
    if XRAY_BINARY.is_file() and os.access(XRAY_BINARY,os.X_OK): return XRAY_BINARY
    found=shutil.which('xray')
    return Path(found) if found else None


def start_background_process(name,cmd,log_file,*,use_sudo=False,env=None,cwd=None):
    if name in CONNECT_PROC and CONNECT_PROC[name].poll() is None:
        raise RuntimeError(f"{name} is already running (PID {CONNECT_PROC[name].pid})")
    log_file.parent.mkdir(parents=True,exist_ok=True)
    f=open(log_file,'ab')
    actual=list(cmd)
    if use_sudo and os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()!=0:
        sudo=shutil.which('sudo')
        if not sudo:
            f.close(); raise RuntimeError('TUN mode needs root or sudo; sudo was not found.')
        actual=[sudo]+actual
    proc=subprocess.Popen(actual,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,start_new_session=True,env=env,cwd=str(cwd) if cwd else None)
    CONNECT_PROC[name]=(proc,f)
    time.sleep(0.4)
    if proc.poll() is not None:
        f.close(); raise RuntimeError(f"{name} exited immediately; see {log_file}")
    return proc


def stop_background_process(name):
    item=CONNECT_PROC.get(name)
    if not item: return False
    proc,f=item
    if proc.poll() is None:
        try: proc.terminate(); proc.wait(timeout=3)
        except Exception:
            try: proc.kill()
            except Exception: pass
    try: f.close()
    except Exception: pass
    CONNECT_PROC.pop(name,None)
    return True


def process_status(name):
    item=CONNECT_PROC.get(name)
    if not item: return 'stopped',None
    p=item[0]
    rc=p.poll()
    if rc is None: return 'running',p.pid
    try: item[1].close()
    except Exception: pass
    return f'exited({rc})',p.pid


def start_aether(state):
    script=ensure_aether_ready()
    if port_in_use(*split_bind(proxy_bind(state))):
        raise RuntimeError("Port 1819 is already in use. Stop the existing proxy before starting Aether.")
    AETHER_CONFIG_DIR.mkdir(parents=True,exist_ok=True)
    bind=proxy_bind(state)
    env=os.environ.copy()
    env.update({
        'AETHER_BIND':bind,
        'AETHER_SOCKS':bind,
        'AETHER_CONFIG':str(AETHER_CONFIG_DIR/'aether.toml'),
        'AETHER_PROTOCOL':'masque',
        'AETHER_SCAN':'balanced',
        'AETHER_QUICK_RECONNECT':'1',
        'PATH':str(AETHER_ROOT)+os.pathsep+str(AETHER_ROOT/'pt')+os.pathsep+env.get('PATH',''),
    })
    # Execute the bundled launcher as ./aether.sh from its own directory.
    return start_background_process(
        'aether',
        ['./aether.sh'],
        AETHER_LOG,
        env=env,
        cwd=AETHER_ROOT,
    )

def xray_load_base():
    if not XRAY_CONFIG_FILE.is_file(): return None
    try: return XRAY_CONFIG_FILE.read_text(encoding='utf-8')
    except Exception: return None


def _pct(v):
    from urllib.parse import unquote
    return unquote(v or "")


def _decode_b64(text):
    raw=text.strip()
    raw += "=" * (-len(raw) % 4)
    try: return base64.b64decode(raw).decode('utf-8')
    except Exception:
        try: return base64.urlsafe_b64decode(raw).decode('utf-8')
        except Exception: raise ValueError('Invalid base64 payload')


def _parse_host_port(value, default_port=None):
    from urllib.parse import urlsplit
    v=value.strip()
    if '://' in v:
        u=urlsplit(v); return u.hostname, (u.port or default_port)
    if v.startswith('['):
        host,_,tail=v[1:].partition(']')
        return host, (int(tail[1:]) if tail.startswith(':') else default_port)
    if v.count(':') == 1:
        host,port=v.rsplit(':',1)
        return host,int(port)
    return v,default_port


def _looks_like_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _valid_sni_name(value):
    value=str(value or '').strip().rstrip('.')
    if not value or len(value)>253 or '/' in value or ':' in value or ' ' in value:
        return False
    try:
        value.encode('idna')
    except Exception:
        return False
    labels=value.split('.')
    return all(label and len(label)<=63 and not label.startswith('-') and not label.endswith('-') for label in labels)


def _load_sni_spoof_list(limit=None):
    path=DEFAULT_SNI_LIST_FILE
    if not path.is_file():
        raise FileNotFoundError(f'SNI list is missing: {path}')
    out=[]; seen=set()
    for raw in path.read_text(errors='replace').splitlines():
        name=raw.strip()
        if not name or name.startswith('#') or not _valid_sni_name(name):
            continue
        key=name.lower()
        if key in seen: continue
        seen.add(key); out.append(name)
        if limit and len(out)>=int(limit): break
    if not out: raise ValueError('SNI list contains no usable hostnames')
    return out


def _first_ipv4_from_cf(limit):
    limit=max(1,int(limit))
    cidrs=load_cidrs(DEFAULT_CF_FILE)
    out=[]; seen=set()
    for net in cidrs:
        if getattr(net,'version',4)!=4: continue
        if net.num_addresses <= 2:
            candidates=list(net)
        else:
            start=int(net.network_address)+1
            end=int(net.broadcast_address)-1
            stop=min(end,start+limit-len(out)-1)
            candidates=(ipaddress.ip_address(x) for x in range(start,stop+1))
        for ip in candidates:
            txt=str(ip)
            if txt in seen: continue
            seen.add(txt); out.append(txt)
            if len(out)>=limit: return out
    return out


def _selected_profile_for_sni(parsed):
    profiles=[p for p in parsed.get('profiles',[]) if 'outbound' in p]
    if not profiles:
        raise ValueError('SNI Spoof needs an Xray outbound config (VLESS, VMess, Trojan, Shadowsocks or Hysteria2).')
    return profiles[0]


def _profile_target_host(profile):
    return str(profile.get('host') or '')


def _set_profile_server_ip(outbound, ip):
    proto=str(outbound.get('protocol','')).lower()
    settings=outbound.setdefault('settings',{})
    if proto in ('vless','vmess'):
        vnext=settings.get('vnext') or []
        if not vnext: raise ValueError(f'{proto.upper()} outbound has no vnext server')
        vnext[0]['address']=ip
        return
    if proto in ('trojan','shadowsocks'):
        servers=settings.get('servers') or []
        if not servers: raise ValueError(f'{proto.title()} outbound has no server')
        servers[0]['address']=ip
        return
    if proto=='hysteria':
        settings['address']=ip
        return
    raise ValueError(f'Protocol {proto} is not supported by SNI Spoof')


def _get_profile_security(outbound):
    ss=outbound.get('streamSettings') or {}
    return str(ss.get('security') or 'none').lower()


def _set_profile_server_endpoint(outbound, host, port):
    proto=str(outbound.get('protocol','')).lower()
    settings=outbound.setdefault('settings',{})
    if proto in ('vless','vmess'):
        vnext=settings.get('vnext') or []
        if not vnext:
            raise ValueError(f'{proto.upper()} outbound has no vnext server')
        vnext[0]['address']=host
        vnext[0]['port']=int(port)
        return
    if proto in ('trojan','shadowsocks'):
        servers=settings.get('servers') or []
        if not servers:
            raise ValueError(f'{proto.title()} outbound has no server')
        servers[0]['address']=host
        servers[0]['port']=int(port)
        return
    if proto=='hysteria':
        settings['address']=host
        settings['port']=int(port)
        return
    raise ValueError(f'Protocol {proto} is not supported by SNI Spoof')


def _apply_sni_spoof(profile, ip, fake_sni, *, local_endpoint=False, local_port=SNI_SPOOF_LISTEN_PORT):
    ob=copy.deepcopy(profile.get('outbound') or {})
    proto=str(ob.get('protocol','')).lower()
    if proto not in {'vless','vmess','trojan','shadowsocks','hysteria'}:
        raise ValueError(f'Protocol {proto or "unknown"} cannot use SNI Spoof in Xray.')
    security=_get_profile_security(ob)
    if security not in ('tls','reality'):
        raise ValueError(f'{proto.upper()} config must use TLS or REALITY for SNI Spoof (current security: {security}).')

    original_host=_profile_target_host(profile)
    original_port=int(profile.get('port') or 443)
    ss=ob.setdefault('streamSettings',{})

    if security=='tls':
        tls=ss.setdefault('tlsSettings',{})
        # Fake SNI is generated by Xray and sent as the ClientHello serverName.
        tls['serverName']=fake_sni
        ss['tlsSettings']=tls
    else:
        reality=ss.setdefault('realitySettings',{})
        reality['serverName']=fake_sni
        ss['realitySettings']=reality

    if local_endpoint:
        # Requested runtime endpoint: Xray -> 127.0.0.1:40443.
        _set_profile_server_endpoint(ob, SNI_SPOOF_LISTEN_HOST, local_port)
        host=SNI_SPOOF_LISTEN_HOST
        port=int(local_port)
    else:
        # Auto-scan probes still use direct Xray endpoints; the selected pair
        # is converted to the fixed local spoof relay when actually connected.
        _set_profile_server_endpoint(ob, ip, original_port)
        host=str(ip)
        port=original_port

    return {
        **profile,
        'outbound':ob,
        'host':host,
        'port':port,
        'spoof_sni':fake_sni,
        'spoof_ip':str(ip),
        'spoof_target_ip':str(ip),
        'spoof_target_port':original_port,
        'original_host':original_host,
        'original_port':original_port,
    }


def _start_sni_proxy(ip, port=443):
    if not SNI_SPOOF_PROXY.is_file():
        raise FileNotFoundError(f'SNI Spoof proxy is missing: {SNI_SPOOF_PROXY}')
    if process_status('sni-spoof-proxy')[0]=='running':
        stop_background_process('sni-spoof-proxy')
    if port_in_use(SNI_SPOOF_LISTEN_HOST,SNI_SPOOF_LISTEN_PORT):
        raise RuntimeError(f'SNI Spoof local port {SNI_SPOOF_LISTEN_PORT} is already in use.')

    cmd=[
        sys.executable,
        '-u',
        str(SNI_SPOOF_PROXY),
        '--listen',f'{SNI_SPOOF_LISTEN_HOST}:{SNI_SPOOF_LISTEN_PORT}',
        '--target', (f'[{ip}]:{int(port)}' if ':' in str(ip) else f'{ip}:{int(port)}'),
    ]
    proc=start_background_process('sni-spoof-proxy',cmd,HOME/'sni-spoof-proxy.log')

    deadline=time.time()+2.0
    while time.time()<deadline:
        if port_in_use(SNI_SPOOF_LISTEN_HOST,SNI_SPOOF_LISTEN_PORT):
            return proc
        if proc.poll() is not None:
            raise RuntimeError(f'SNI Spoof proxy exited; see {HOME / "sni-spoof-proxy.log"}')
        time.sleep(0.05)

    stop_background_process('sni-spoof-proxy')
    raise RuntimeError('SNI Spoof proxy did not start listening on 127.0.0.1:40443')

def _single_profile_parsed(parsed, profile):
    base=copy.deepcopy(parsed.get('base') or {})
    if isinstance(base,dict):
        base['outbounds']=[]
        base['inbounds']=[]
        base['routing']={'domainStrategy':(base.get('routing') or {}).get('domainStrategy','AsIs')}
    return {'base':base,'profiles':[profile],'source':parsed.get('source','json')}


def _find_free_port(host='127.0.0.1', start=23000, span=2000):
    for _ in range(64):
        port=random.randint(start,start+span-1)
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                if s.bind((host,port))==0: return port
        except OSError: pass
    raise RuntimeError('No free local TCP port available for SNI probe')


def _build_sni_scan_config(base, candidates):
    obj=copy.deepcopy(base or {})
    obj['log']={'loglevel':'warning'}
    obj['inbounds']=[]; obj['outbounds']=[]
    rules=[]
    for idx,c in enumerate(candidates):
        ob=copy.deepcopy(c['profile']['outbound']); ob['tag']=f'sni-scan-{idx}'; _strip_removed_xray_fields(ob)
        obj['outbounds'].append(ob)
        obj['inbounds'].append({'listen':'127.0.0.1','port':c['port'],'protocol':'socks','settings':{'auth':'noauth','udp':False},'tag':f'sni-probe-{idx}'})
        rules.append({'type':'field','inboundTag':[f'sni-probe-{idx}'],'outboundTag':f'sni-scan-{idx}'})
    obj['outbounds'].append({'protocol':'freedom','tag':'sni-direct'})
    obj['routing']={'domainStrategy':'AsIs','rules':rules}
    return obj


def _probe_sni_batch(state, profile, pairs, base=None):
    if not pairs: return []
    b=xray_binary()
    if not b: raise FileNotFoundError('Bundled Xray binary is missing')
    prepared=[]; used_ports=set()
    for idx,(ip,fake_sni) in enumerate(pairs):
        p=_apply_sni_spoof(profile,ip,fake_sni,local_endpoint=False)
        port=None
        for _ in range(64):
            candidate=_find_free_port(start=23000+(idx%8)*40,span=40)
            if candidate not in used_ports:
                port=candidate; used_ports.add(candidate); break
        if port is None: raise RuntimeError('Could not allocate unique SNI probe ports')
        prepared.append({'profile':p,'ip':ip,'sni':fake_sni,'port':port})
    base=copy.deepcopy(base or {'log':{'loglevel':'warning'}})
    cfg=_build_sni_scan_config(base,prepared)
    XRAY_CONFIG_DIR.mkdir(parents=True,exist_ok=True)
    scan_cfg=XRAY_CONFIG_DIR/'sni-spoof-scan.json'; _write_connect_json(scan_cfg,cfg)
    check=subprocess.run([str(b),'run','-test','-config',str(scan_cfg)],capture_output=True,text=True,timeout=20,check=False)
    if check.returncode!=0:
        detail=(check.stderr or check.stdout or 'unknown Xray config error').strip()
        raise RuntimeError('Xray SNI probe config test failed: '+detail[-1200:])
    stop_background_process('sni-spoof-scan')
    proc=start_background_process('sni-spoof-scan',[str(b),'run','-c',str(scan_cfg)],HOME/'sni-spoof-scan.log')
    timeout=float(state.cfg.get('sni_spoof_timeout',2.5))
    def one(c):
        try:
            rtt=_socks5_probe('127.0.0.1',c['port'],'1.1.1.1',443,timeout=timeout)
            return {**c,'ok':True,'rtt_ms':round(rtt,1),'error':''}
        except Exception as exc:
            return {**c,'ok':False,'rtt_ms':None,'error':str(exc)[:180]}
    try:
        with ThreadPoolExecutor(max_workers=min(16,len(prepared))) as ex:
            results=list(ex.map(one,prepared))
    finally:
        stop_background_process('sni-spoof-scan')
    return results


def _auto_sni_spoof_find(state, profile, base=None):
    ip_limit=max(1,int(state.cfg.get('sni_spoof_auto_ip_limit',512)))
    sni_limit=max(1,int(state.cfg.get('sni_spoof_sni_limit',64)))
    max_candidates=max(1,int(state.cfg.get('sni_spoof_max_candidates',2048)))
    batch_size=max(8,min(128,int(state.cfg.get('sni_spoof_batch_size',64))))
    ips=_first_ipv4_from_cf(ip_limit); snis=_load_sni_spoof_list(sni_limit)
    if not ips or not snis: raise RuntimeError('SNI Spoof auto scan has no IP/SNI candidates.')
    pairs=[]
    for fake_sni in snis:
        for ip in ips:
            pairs.append((ip,fake_sni))
            if len(pairs)>=max_candidates: break
        if len(pairs)>=max_candidates: break
    ui_clear(); ui_header(state,'SNI SPOOF / AUTO')
    print(f'Cloudflare IP candidates: {len(ips)}  |  Fake SNI candidates: {len(snis)}  |  Ordered pairs: {len(pairs)}')
    print('Order: first SNI × ordered IPs. Xray batches run concurrently; the earliest successful pair is selected.')
    print('Transport: Xray TLS/REALITY SNI override. No packet injector is required on Linux.')
    for off in range(0,len(pairs),batch_size):
        batch=pairs[off:off+batch_size]
        print(f'[{off+1}-{off+len(batch)}/{len(pairs)}] probing {len(batch)} pairs',flush=True)
        results=_probe_sni_batch(state,profile,batch,base=base)
        good=sorted((r for r in results if r.get('ok')),key=lambda r:batch.index((r['ip'],r['sni'])))
        if good:
            found=good[0]
            state.cfg['sni_spoof_last_find']={'ip':found['ip'],'sni':found['sni'],'rtt_ms':found.get('rtt_ms'),'found_at':time.time(),'source':'auto','original_host':profile.get('host'),'kind':profile.get('kind'),'tag':profile.get('tag')}
            state.save()
            print(f"\n[+] FOUND  IP={found['ip']}  SNI={found['sni']}  RTT={found.get('rtt_ms','—')} ms")
            return found
    raise RuntimeError('Auto SNI scan finished without a verified IP + fake SNI pair.')


def _start_sni_spoof_connection(state, parsed, profile, ip, fake_sni, label='custom'):
    if process_status('xray')[0]=='running':
        _stop_xray_watcher(state); stop_background_process('xray')
    original_port=int(profile.get('port') or 443)

    # Requested chain:
    #   Xray outbound server = 127.0.0.1
    #   Xray outbound port   = 40443
    #   local relay target   = selected spoof IP:original_port
    #   TLS/REALITY SNI      = fake_sni
    _start_sni_proxy(ip,original_port)
    spoofed=_apply_sni_spoof(
        profile,ip,fake_sni,
        local_endpoint=True,
        local_port=SNI_SPOOF_LISTEN_PORT,
    )
    spoof_parsed=_single_profile_parsed(parsed,spoofed)
    state.cfg['sni_spoof_active']={
        'ip':str(ip),
        'port':original_port,
        'sni':fake_sni,
        'mode':label,
        'local_server':SNI_SPOOF_LISTEN_HOST,
        'local_port':SNI_SPOOF_LISTEN_PORT,
        'started_at':time.time(),
        'tag':spoofed.get('tag',''),
    }
    state.save()
    try:
        proc,sess=start_xray_multi(state,'proxy',spoof_parsed)
    except Exception:
        stop_background_process('sni-spoof-proxy')
        raise
    if sess:
        sess[0]['spoof_sni']=fake_sni
        sess[0]['original_host']=profile.get('host')
        sess[0]['spoof_ip']=str(ip)
        sess[0]['spoof_port']=original_port
        sess[0]['spoof_proxy']=f'{SNI_SPOOF_LISTEN_HOST}:{SNI_SPOOF_LISTEN_PORT}'
        sess[0]['sni_spoof_mode']=label
        state.cfg['xray_session']['profiles']=sess
        state.save()
    return proc,sess


def sni_spoof_menu(state):
    last=state.cfg.get('sni_spoof_last_find'); has_last=isinstance(last,dict) and last.get('ip') and last.get('sni')
    while True:
        ui_clear(); ui_header(state,'CONNECT / SNI SPOOF')
        items=[('1','Custom — config + IP + fake SNI'),('2','Auto — scan Cloudflare IPs + sni-list.txt')]
        if has_last: items.append(('3',f"Last Find — {last['ip']} + {last['sni']}"))
        items.append(('0','Back')); ui_choice(items,'SNI Spoof')
        c=input('\nSelect › ').strip()
        try:
            if c=='0': return
            if c not in {'1','2','3'} or (c=='3' and not has_last): continue
            ui_clear(); ui_header(state,'SNI SPOOF')
            print('Supported: VLESS, VMess, Trojan, Shadowsocks, Hysteria2 with TLS/REALITY.')
            print('Xray connects to the selected IP while sending the requested SNI.')
            base_text=read_config_text('Xray config')
            if not base_text: continue
            parsed=parse_xray_connect_inputs(base_text); profile=_selected_profile_for_sni(parsed)
            if c=='1':
                ip=input('Spoof IP › ').strip()
                try: ipaddress.ip_address(ip)
                except ValueError: raise ValueError('Invalid IP address')
                fake_sni=input('Fake SNI › ').strip().rstrip('.')
                if not _valid_sni_name(fake_sni): raise ValueError('Invalid fake SNI hostname')
                proc,sess=_start_sni_spoof_connection(state,parsed,profile,ip,fake_sni,'custom')
                active_ip,active_sni=ip,fake_sni
            elif c=='2':
                found=_auto_sni_spoof_find(state,profile,parsed.get('base') or {})
                proc,sess=_start_sni_spoof_connection(state,parsed,profile,found['ip'],found['sni'],'auto')
                active_ip,active_sni=found['ip'],found['sni']
            else:
                proc,sess=_start_sni_spoof_connection(state,parsed,profile,str(last['ip']),str(last['sni']),'last-find')
                active_ip,active_sni=str(last['ip']),str(last['sni'])
            print(f'\n[+] Xray SNI Spoof started. PID={proc.pid}')
            print(f'[+] Spoof target: {active_ip}')
            print(f'[+] Fake SNI: {active_sni}')
            print(f'[+] Master proxy: {proxy_bind(state)}')
            render_xray_session(state); ui_pause()
            last=state.cfg.get('sni_spoof_last_find'); has_last=isinstance(last,dict) and last.get('ip') and last.get('sni')
        except KeyboardInterrupt:
            print('\nStopped.'); ui_pause()
        except Exception as e:
            print(f'\nError: {e}'); ui_pause()


def _stream_from_uri(q, scheme='vless'):
    from urllib.parse import parse_qs
    get=lambda *keys, default='': next((q[k][0] for k in keys if q.get(k)), default)
    network=get('type','network',default='tcp').lower()
    security=get('security','tls','type_security',default='')
    if security not in ('tls','reality','none',''): security='tls' if q.get('sni') else 'none'
    ss={'network':network}
    if network in ('ws','websocket'):
        ss['network']='ws'; ws={}
        path=_pct(get('path',default='/'))
        if path: ws['path']=path
        host=_pct(get('host',default=''))
        if host: ws['headers']={'Host':host}
        ss['wsSettings']=ws
    elif network in ('grpc',):
        ss['network']='grpc'; ss['grpcSettings']={'serviceName':_pct(get('serviceName','service',default=''))}
    elif network in ('xhttp','splithttp','httpupgrade'):
        ss['network']='xhttp' if network=='xhttp' else network
        if ss['network']=='xhttp':
            x={}
            path=_pct(get('path',default=''))
            if path: x['path']=path
            host=_pct(get('host',default=''))
            if host: x['host']=host
            if q.get('mode'): x['mode']=q['mode'][0]
            ss['xhttpSettings']=x
        elif ss['network']=='httpupgrade':
            ss['httpupgradeSettings']={'path':_pct(get('path',default='/'))}
            host=_pct(get('host',default=''))
            if host: ss['httpupgradeSettings']['host']=host
    if security in ('tls','reality'):
        ss['security']=security
        sni=_pct(get('sni','servername','serverName',default=''))
        if security=='tls':
            tls={}
            if sni: tls['serverName']=sni
            fp=get('fp','fingerprint',default='')
            if fp: tls['fingerprint']=fp
            if q.get('alpn'): tls['alpn']=[_pct(x) for x in q['alpn'][0].split(',') if x]
            ss['tlsSettings']=tls
        else:
            real={}
            if sni: real['serverName']=sni
            if get('fp','fingerprint',default=''): real['fingerprint']=get('fp','fingerprint')
            if get('pbk','publicKey',default=''): real['publicKey']=get('pbk','publicKey')
            if get('sid','shortId',default=''): real['shortId']=get('sid','shortId')
            ss['realitySettings']=real
    return ss


def _uri_to_xray(uri, idx=0):
    from urllib.parse import urlsplit, parse_qs
    u=urlsplit(uri.strip())
    scheme=u.scheme.lower(); tag=_pct(u.fragment) or f'{scheme.upper()} #{idx+1}'
    q=parse_qs(u.query,keep_blank_values=True)
    host=u.hostname; port=u.port
    if scheme=='vmess':
        payload=u.netloc + u.path
        data=json.loads(_decode_b64(payload))
        host=data.get('add') or data.get('address') or data.get('host')
        port=int(data.get('port') or 443)
        user={'id':data['id'],'alterId':int(data.get('aid') or data.get('alterId') or 0),'security':data.get('scy') or data.get('security') or 'auto','level':0}
        out={'tag':tag,'protocol':'vmess','settings':{'vnext':[{'address':host,'port':port,'users':[user]}]}}
        net=(data.get('net') or 'tcp').lower(); opts={}
        if net=='ws': opts={'network':'ws','wsSettings':{'path':data.get('path') or '/','headers':{'Host':data.get('host') or host}}}
        elif net=='grpc': opts={'network':'grpc','grpcSettings':{'serviceName':data.get('path') or ''}}
        else: opts={'network':net}
        tls=(data.get('tls') or '').lower()
        if tls=='tls': opts.update({'security':'tls','tlsSettings':{'serverName':data.get('sni') or data.get('host') or host,'fingerprint':data.get('fp') or 'chrome'}})
        if net in ('ws','grpc','tcp','httpupgrade','xhttp'): out['streamSettings']=opts
        return out, tag, host, port, 'VMess'
    if scheme=='vless':
        user=u.username or ''; out={'tag':tag,'protocol':'vless','settings':{'vnext':[{'address':host,'port':int(port or 443),'users':[{'id':_pct(user),'encryption':_pct((q.get('encryption') or ['none'])[0]),'level':0}]}]},'streamSettings':_stream_from_uri(q,'vless')}
        flow=(q.get('flow') or [''])[0]
        if flow: out['settings']['vnext'][0]['users'][0]['flow']=flow
        return out, tag, host, int(port or 443), 'VLESS'
    if scheme=='trojan':
        out={'tag':tag,'protocol':'trojan','settings':{'servers':[{'address':host,'port':int(port or 443),'password':_pct(u.username or u.path.lstrip('/')),'level':0}]},'streamSettings':_stream_from_uri(q,'trojan')}
        return out, tag, host, int(port or 443), 'Trojan'
    if scheme in ('ss','shadowsocks'):
        payload=u.username or u.netloc or ''
        if u.password:
            method=_pct(payload); password=_pct(u.password)
        else:
            decoded=_decode_b64(payload); decoded=decoded.rsplit('@',1)
            method,password=decoded[0].split(':',1); host2,port2=_parse_host_port(decoded[1],443); host=host2; port=port2
        out={'tag':tag,'protocol':'shadowsocks','settings':{'servers':[{'address':host,'port':int(port or 443),'method':method,'password':password}]}}
        return out, tag, host, int(port or 443), 'Shadowsocks'
    if scheme in ('hysteria2','hy2','hysteria'):
        password=_pct(u.username or u.password or u.path.lstrip('/'))
        hp=int(port or 443)
        out={'tag':tag,'protocol':'hysteria','settings':{'version':2,'address':host,'port':hp},'streamSettings':{'network':'hysteria','security':'tls','tlsSettings':{}}}
        if password: out['streamSettings']['hysteriaSettings']={'version':2,'auth':password}
        sni=_pct((q.get('sni') or [host])[0]); tls=out['streamSettings']['tlsSettings']; tls['serverName']=sni
        # Xray 26.9.x removed allowInsecure; a supplied insecure=1 cannot be
        # represented as a blanket trust toggle. Keep normal verification and
        # let the runtime report certificate failures, or use vcn/pcs in JSON.
        if q.get('alpn'): tls['alpn']=[_pct(x) for x in q['alpn'][0].split(',') if x]
        return out, tag, host, hp, 'Hysteria2'
    raise ValueError(f'Unsupported URI protocol: {scheme}')


def _parse_wg_ini(text, idx=0):
    current=None; blocks=[]
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith('#') or line.startswith(';'): continue
        if line.startswith('[') and line.endswith(']'):
            current={'section':line[1:-1].strip().lower()}; blocks.append(current); continue
        if '=' in line and current is not None:
            k,v=line.split('=',1); current[k.strip().lower()]=v.strip()
    iface=next((b for b in blocks if b['section']=='interface'),None)
    peer=next((b for b in blocks if b['section']=='peer'),None)
    if not iface or not peer or not iface.get('privatekey') or not peer.get('publickey') or not peer.get('endpoint'):
        raise ValueError('WireGuard config needs Interface PrivateKey and Peer PublicKey/Endpoint')
    addresses=[x.strip().split('/')[0] for x in re.split(r'[,\s]+',iface.get('address','')) if x.strip()]
    if not addresses: addresses=['10.0.0.2']
    allowed=[x.strip() for x in re.split(r'[,\s]+',peer.get('allowedips','0.0.0.0/0, ::/0')) if x.strip()]
    settings={'secretKey':iface['privatekey'],'address':addresses,'peers':[{'endpoint':peer['endpoint'],'publicKey':peer['publickey'],'allowedIPs':allowed}],'noKernelTun':True,'mtu':int(iface.get('mtu','1420')) if str(iface.get('mtu','')).isdigit() else 1420}
    if peer.get('presharedkey'): settings['peers'][0]['preSharedKey']=peer['presharedkey']
    if peer.get('persistentkeepalive') and str(peer['persistentkeepalive']).isdigit(): settings['peers'][0]['keepAlive']=int(peer['persistentkeepalive'])
    if iface.get('dns'): settings['remoteDNS']=[x.strip() for x in re.split(r'[,\s]+',iface['dns']) if x.strip()]
    tag=f'WireGuard #{idx+1}'
    host,port=_parse_host_port(peer['endpoint'],51820)
    return {'tag':tag,'protocol':'wireguard','settings':settings},tag,host,port,'WireGuard'


def _parse_ssh_uri(text, idx=0):
    from urllib.parse import urlsplit, parse_qs
    u=urlsplit(text.strip()); q=parse_qs(u.query,keep_blank_values=True)
    if u.scheme.lower()=='ssh':
        host=u.hostname; port=int(u.port or 22); user=_pct(u.username or '')
        password=_pct(u.password or '')
        key=_pct((q.get('key') or [''])[0])
    else:
        m=re.match(r'(?:(?P<user>[^@\s]+)@)?(?P<host>[^:\s]+)(?::(?P<port>\d+))?$',text.strip())
        if not m: raise ValueError('SSH config must be ssh://user@host:22 or user@host:22')
        host=m.group('host'); port=int(m.group('port') or 22); user=m.group('user') or '' ; password=''; key=''
        q={}
    if not host or not user: raise ValueError('SSH config needs username and host')
    return {'host':host,'port':port,'user':user,'password':password,'key':key,'tag':_pct(u.fragment) or f'SSH #{idx+1}'}, _pct(u.fragment) or f'SSH #{idx+1}', host, port, 'SSH'


def parse_xray_connect_inputs(text):
    """Parse one Xray JSON config or a mixed list of proxy URIs/WireGuard blocks."""
    raw=text.strip()
    if raw.startswith('@') and Path(raw[1:]).is_file(): raw=Path(raw[1:]).read_text(encoding='utf-8')
    try:
        obj=json.loads(raw)
        obs=obj.get('outbounds',[]) if isinstance(obj,dict) else []
        profiles=[]
        for i,o in enumerate(obs):
            if not isinstance(o,dict): continue
            proto=str(o.get('protocol','')).lower()
            if proto in {'vless','vmess','trojan','shadowsocks','hysteria','wireguard'}:
                p=copy.deepcopy(o); p.setdefault('tag',f'{proto.upper()} #{i+1}')
                host=_nested_get(p,{'address','server'})
                port=_nested_get(p,{'port','serverport','server_port'})
                profiles.append({'kind':proto.upper(),'tag':p['tag'],'outbound':p,'host':host,'port':int(port) if str(port).isdigit() else None})
        if profiles: return {'base':obj,'profiles':profiles,'source':'json'}
        raise ValueError('JSON contains no supported proxy outbounds')
    except json.JSONDecodeError:
        pass

    uri_schemes=('vless','vmess','trojan','ss','shadowsocks','hysteria2','hy2','hysteria','ssh')
    uri_lines=[]; wg_blocks=[]; current=[]; in_wg=False
    for raw_line in raw.splitlines():
        stripped=raw_line.strip()
        is_uri=any(stripped.lower().startswith(sc+'://') for sc in uri_schemes)
        if stripped.lower()=='[interface]':
            if current: wg_blocks.append('\n'.join(current))
            current=[raw_line]; in_wg=True; continue
        if in_wg and is_uri:
            if current: wg_blocks.append('\n'.join(current)); current=[]
            in_wg=False; uri_lines.append(stripped); continue
        if in_wg:
            current.append(raw_line)
        elif stripped:
            uri_lines.append(stripped)
    if current: wg_blocks.append('\n'.join(current))

    profiles=[]; errors=[]
    for i,block in enumerate(wg_blocks):
        try:
            o,tag,host,port,kind=_parse_wg_ini(block,i)
            profiles.append({'kind':kind.upper(),'tag':tag,'outbound':o,'host':host,'port':port})
        except Exception as e: errors.append(f'WireGuard block {i+1}: {e}')
    for i,line in enumerate(uri_lines):
        try:
            scheme=line.split('://',1)[0].lower() if '://' in line else ''
            if scheme=='ssh':
                ssh,tag,host,port,kind=_parse_ssh_uri(line,i)
                profiles.append({'kind':kind,'tag':tag,'ssh':ssh,'host':host,'port':port})
            else:
                o,tag,host,port,kind=_uri_to_xray(line,i)
                profiles.append({'kind':kind,'tag':tag,'outbound':o,'host':host,'port':port})
        except Exception as e: errors.append(f'line {i+1}: {e}')
    if not profiles:
        raise ValueError('No supported configs found. Supported: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard INI, SSH.')
    return {'base':None,'profiles':profiles,'source':'mixed','errors':errors}


def _strip_removed_xray_fields(obj):
    """Xray 26.9.x no longer accepts allowInsecure; remove legacy occurrences."""
    removed=[]
    def walk(x, path=''):
        if isinstance(x,dict):
            for k in list(x):
                if str(k)=='allowInsecure':
                    removed.append(path+'.allowInsecure' if path else 'allowInsecure')
                    del x[k]
                else:
                    walk(x[k], path+'.'+str(k) if path else str(k))
        elif isinstance(x,list):
            for i,v in enumerate(x): walk(v, f'{path}[{i}]')
    walk(obj)
    return removed


def _xray_runtime_config(state, parsed, mode):
    obj=copy.deepcopy(parsed.get('base') or {'log':{'loglevel':'warning'},'outbounds':[]})
    removed_legacy=_strip_removed_xray_fields(obj)
    obj['inbounds']=[x for x in (obj.get('inbounds') or []) if not (isinstance(x,dict) and str(x.get('tag','')).startswith('spider-'))]
    if removed_legacy:
        parsed.setdefault('warnings',[]).append('Removed legacy allowInsecure from Xray config; use verifyPeerCertByName (vcn) or pinnedPeerCertSha256 (pcs).')
    supported=[]
    for i,p in enumerate(parsed['profiles']):
        if 'outbound' in p:
            ob=copy.deepcopy(p['outbound']); _strip_removed_xray_fields(ob); ob['tag']=f'spider-out-{len(supported)}'; supported.append((p,ob))
        elif 'ssh' in p:
            p['adapter_port']=19200+i
            ob={'tag':f'spider-out-{len(supported)}','protocol':'socks','settings':{'servers':[{'address':'127.0.0.1','port':p['adapter_port']}]}}
            supported.append((p,ob))
    if not supported:
        raise ValueError('No supported proxy profiles to launch')
    existing_out=[x for x in (obj.get('outbounds') or []) if isinstance(x,dict) and not str(x.get('tag','')).startswith('spider-') and str(x.get('protocol','')).lower() not in {'freedom','blackhole'}]
    obj['outbounds']=existing_out+[ob for _,ob in supported]+[{'protocol':'freedom','tag':'spider-direct'}]
    if mode=='proxy':
        host,port=split_bind(proxy_bind(state))
        obj['inbounds'].append({'listen':host,'port':port,'protocol':'socks','settings':{'auth':'noauth','udp':True},'sniffing':{'enabled':True,'destOverride':['http','tls','quic']},'tag':'spider-proxy'})
    elif mode=='tun':
        if os.name!='posix': raise RuntimeError('Xray TUN mode is intended for POSIX hosts.')
        name=str(_connect_state(state).get('xray_tun_name') or 'spider-tun0')
        try: mtu=max(576,int(_connect_state(state).get('xray_tun_mtu',1500)))
        except Exception: mtu=1500
        tun_settings={'name':name,'mtu':mtu,'gateway':['172.19.0.1/30','fd00:1819::1/64'],'dns':['1.1.1.1','8.8.8.8'],'autoSystemRoutingTable':['0.0.0.0/0','::/0'],'autoOutboundsInterface':'auto'}
        obj['inbounds'].append({'protocol':'tun','settings':tun_settings,'sniffing':{'enabled':True,'destOverride':['http','tls','quic']},'tag':'spider-tun'})
    rules=[]
    for i,(p,ob) in enumerate(supported):
        p['probe_port']=19100+i; p['runtime_tag']=ob['tag']
        obj['inbounds'].append({'listen':'127.0.0.1','port':p['probe_port'],'protocol':'socks','settings':{'auth':'noauth','udp':False},'tag':f'spider-probe-{i}'})
        rules.append({'type':'field','inboundTag':[f'spider-probe-{i}'],'outboundTag':ob['tag']})
    active_tag=supported[0][1]['tag']
    if mode=='proxy': rules.insert(0,{'type':'field','inboundTag':['spider-proxy'],'outboundTag':active_tag})
    else: rules.insert(0,{'type':'field','inboundTag':['spider-tun'],'outboundTag':active_tag})
    old_rules=(obj.get('routing',{}).get('rules') or [])
    obj.setdefault('routing',{})['rules']=rules+[r for r in old_rules if not (isinstance(r,dict) and str(r.get('tag','')).startswith('spider-'))]
    return obj


def _start_ssh_adapter(profile):
    cfg=profile['ssh']; port=profile['adapter_port']; name=f"xray-ssh-{profile['tag']}"
    ssh=shutil.which('ssh')
    if not ssh: raise RuntimeError('OpenSSH client is not installed')
    cmd=[ssh,'-N','-D',f'127.0.0.1:{port}','-p',str(cfg['port']),'-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=30','-o','ServerAliveCountMax=2','-o','StrictHostKeyChecking=accept-new']
    if cfg.get('key'): cmd += ['-i',cfg['key']]
    env=os.environ.copy()
    if cfg.get('password'):
        sshpass=shutil.which('sshpass')
        if not sshpass: raise RuntimeError('SSH password config needs sshpass; use an SSH key or install sshpass')
        cmd=[sshpass,'-e']+cmd
        env['SSHPASS']=cfg['password']
    cmd += [f"{cfg['user']}@{cfg['host']}"]
    return name,start_background_process(name,cmd,HOME/f'{name}.log',env=env)


def start_xray_multi(state,mode,parsed):
    b=xray_binary()
    if not b: raise FileNotFoundError('Bundled Xray binary is missing')
    cfg=_xray_runtime_config(state,parsed,mode)
    _write_connect_json(XRAY_CONFIG_FILE,cfg)
    bind=split_bind(proxy_bind(state))
    if mode=='proxy' and port_in_use(*bind): raise RuntimeError('Port 1819 is already in use. Stop Aether/another proxy first.')
    check=subprocess.run([str(b),'run','-test','-config',str(XRAY_CONFIG_FILE)],capture_output=True,text=True,timeout=20,check=False)
    if check.returncode!=0:
        detail=(check.stderr or check.stdout or 'unknown Xray config error').strip()
        raise RuntimeError('Xray config test failed: '+detail[-1600:])
    ssh_adapters=[]
    for p in parsed['profiles']:
        if 'ssh' in p:
            if not shutil.which('ssh'): raise RuntimeError('SSH profile detected but OpenSSH client is not installed.')
            try: ssh_adapters.append(_start_ssh_adapter(p))
            except Exception as e: p['error']=str(e)
    cmd=[str(b),'run','-c',str(XRAY_CONFIG_FILE)]
    proc=start_background_process('xray',cmd,XRAY_LOG,use_sudo=(mode=='tun'))
    # Persist an immediately inspectable session state.
    session=[]
    for p in parsed['profiles']:
        session.append({'tag':p['tag'],'kind':p['kind'],'host':p.get('host'),'port':p.get('port'),'probe_port':p.get('probe_port'),'adapter_port':p.get('adapter_port'),'spoof_sni':p.get('spoof_sni'),'original_host':p.get('original_host'),'spoof_ip':p.get('host') if p.get('spoof_sni') else None,'ping_ms':None,'loss':None,'jitter_ms':None,'status':'starting','error':p.get('error','')})
    state.cfg['xray_session']={'mode':mode,'started_at':time.time(),'profiles':session}
    state.save()
    _start_xray_ping_watcher(state)
    return proc,session


def _socks5_probe(host,port,target='1.1.1.1',target_port=443,timeout=4.0):
    start=time.perf_counter()
    try:
        target_ip=ipaddress.ip_address(target)
        atyp=1 if target_ip.version==4 else 4
        addr=target_ip.packed
    except ValueError:
        target_bytes=target.encode('idna')
        if len(target_bytes)>255: raise ValueError('Ping provider hostname is too long')
        atyp=3; addr=bytes([len(target_bytes)])+target_bytes
    with socket.create_connection((host,port),timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b'\x05\x01\x00')
        if s.recv(2)!=b'\x05\x00': raise RuntimeError('SOCKS auth rejected')
        req=b'\x05\x01\x00'+bytes([atyp])+addr+struct.pack('!H',target_port)
        s.sendall(req); head=s.recv(4)
        if len(head)<4 or head[1]!=0: raise RuntimeError(f'SOCKS connect failed: {head[1] if len(head)>1 else "?"}')
        r_atyp=head[3]
        if r_atyp==1: s.recv(4)
        elif r_atyp==3:
            n=s.recv(1)[0]; s.recv(n)
        elif r_atyp==4: s.recv(16)
        s.recv(2)
    return (time.perf_counter()-start)*1000


def _ping_provider_hosts(state):
    cfg=_connect_state(state)
    vals=cfg.get('xray_ping_providers') or [{'name':'Cloudflare','host':'1.1.1.1','port':443},{'name':'Google','host':'8.8.8.8','port':443}]
    out=[]
    for x in vals:
        if isinstance(x,dict) and x.get('host'): out.append({'name':str(x.get('name') or x['host']),'host':str(x['host']),'port':int(x.get('port') or 443)})
        elif isinstance(x,str): out.append({'name':x,'host':x,'port':443})
    return out


def _profile_ping_once(profile, providers):
    local=profile.get('probe_port') or profile.get('adapter_port')
    if not local: return {'status':'unsupported','error':'No local adapter'}
    if not providers: providers=[{'name':'Cloudflare','host':'1.1.1.1','port':443}]
    provider_rows=[]; all_samples=[]; errors=[]
    for prov in providers:
        samples=[]
        for _ in range(3):
            try:
                samples.append(_socks5_probe('127.0.0.1',int(local),prov['host'],prov['port'],timeout=4.0))
            except Exception as e: errors.append(f"{prov['name']}: {e}")
            time.sleep(0.05)
        if samples:
            provider_rows.append({'name':prov['name'],'host':prov['host'],'ping_ms':round(statistics.median(samples),1),'loss':round((1-len(samples)/3)*100,1),'jitter_ms':round(max(samples)-min(samples),1) if len(samples)>1 else 0.0,'status':'PASS'})
            all_samples.extend(samples)
        else:
            provider_rows.append({'name':prov['name'],'host':prov['host'],'ping_ms':None,'loss':100.0,'jitter_ms':None,'status':'FAIL'})
    ok=[r for r in provider_rows if r['status']=='PASS']
    if not ok:
        return {'status':'FAIL','error':errors[-1] if errors else 'all providers failed','loss':100.0,'providers':provider_rows}
    ping=statistics.median([r['ping_ms'] for r in ok])
    jitter=statistics.median([r['jitter_ms'] for r in ok])
    loss=statistics.mean([r['loss'] for r in provider_rows])
    return {'status':'CONNECTED','ping_ms':ping,'jitter_ms':jitter,'loss':round(loss,1),'providers':provider_rows,'error':'' if len(ok)==len(provider_rows) else '; '.join(errors[-2:])}


def _start_xray_ping_watcher(state):
    if getattr(state,'_xray_watcher',None) and state._xray_watcher.is_alive(): return
    stop_event=Event(); state._xray_watcher_stop=stop_event
    def watch():
        first=True
        while not stop_event.is_set():
            sess=state.cfg.get('xray_session',{}).get('profiles',[])
            if not sess: return
            providers=_ping_provider_hosts(state)
            for p in sess:
                r=_profile_ping_once(p,providers)
                p.update(r); p['checked_at']=time.time()
            state.cfg['xray_last_ping']=time.time(); state.save()
            if first: first=False
            stop_event.wait(30.0)
    state._xray_watcher=Thread(target=watch,daemon=True); state._xray_watcher.start()


def _stop_xray_watcher(state):
    ev=getattr(state,'_xray_watcher_stop',None)
    if ev: ev.set()


def _tail_lines(path,n=3):
    try:
        lines=path.read_text(errors='replace').splitlines()
        return lines[-n:] or ['(no log output yet)']
    except Exception: return ['(log unavailable)']


def render_xray_session(state):
    sess=state.cfg.get('xray_session',{}).get('profiles',[])
    if not sess:
        print('No Xray session loaded.')
        return
    if RICH_OK:
        console.print(f"[dim]Auto ping interval: 30s  |  Providers: {', '.join(x['name'] for x in _ping_provider_hosts(state))}[/dim]")
        for i,p in enumerate(sess,1):
            ping='—' if p.get('ping_ms') is None else f"{float(p['ping_ms']):.1f} ms"
            jit='—' if p.get('jitter_ms') is None else f"{float(p['jitter_ms']):.1f} ms"
            loss='—' if p.get('loss') is None else f"{float(p['loss']):.1f}%"
            status=str(p.get('status','?'))
            server=str(p.get('host') or '—')
            title=f"#{i:02d}  {p.get('kind','?')}  —  {p.get('tag','')}"
            spoof_line=(f"\nSpoof: {p.get('spoof_ip')}:{p.get('spoof_port') or 443}  |  SNI: {p.get('spoof_sni')}  |  Local: {p.get('spoof_proxy') or '127.0.0.1:40443'}" if p.get('spoof_sni') else '')
            body=(f"Server: {server}:{p.get('port') or '—'}\n"
                  f"Ping: {ping}   |   Jitter: {jit}   |   Loss: {loss}   |   Status: {status}"+spoof_line)
            console.print(Panel(body,title=title,border_style='green' if status=='CONNECTED' else 'yellow' if status=='starting' else 'red'))
        console.print(Panel('\n'.join(_tail_lines(XRAY_LOG,3)),title='Xray log — last 3 lines',border_style='dim'))
    else:
        for i,p in enumerate(sess,1):
            ping='—' if p.get('ping_ms') is None else f"{float(p['ping_ms']):.1f} ms"
            jit='—' if p.get('jitter_ms') is None else f"{float(p['jitter_ms']):.1f} ms"
            loss='—' if p.get('loss') is None else f"{float(p['loss']):.1f}%"
            print(f"\n[{i:02d}] {p.get('kind','?')} — {p.get('tag','')}")
            print(f"  Server: {p.get('host') or '—'}:{p.get('port') or '—'}")
            if p.get('spoof_sni'):
                print(f"  Spoof: {p.get('spoof_ip')}:{p.get('spoof_port') or 443} | SNI: {p.get('spoof_sni')} | Local: {p.get('spoof_proxy') or '127.0.0.1:40443'}")
            print(f"  Ping: {ping} | Jitter: {jit} | Loss: {loss} | Status: {p.get('status','?')}")
        print('\n+---------------- Xray log (last 3 lines) ----------------+')
        for x in _tail_lines(XRAY_LOG,3): print('| '+x[:52].ljust(52)+' |')
        print('+---------------------------------------------------------+')


def xray_menu(state):
    while True:
        ui_clear(); ui_header(state,'CONNECT / XRAY')
        ui_choice([
            ('1','Proxy — all configs → SOCKS5 :1819'),
            ('2','TUN — all configs → system TUN'),
            ('3','Live status + ping + 3-line log'),
            ('4','Stop Xray'),
            ('0','Back')
        ],'Xray')
        c=input('\nSelect › ').strip()
        try:
            if c in ('1','2'):
                label='Proxy' if c=='1' else 'TUN'
                ui_clear(); ui_header(state,f'XRAY {label.upper()}')
                print('Paste Xray JSON, or one/multiple URI configs (one per line).')
                print('Supported: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard INI, SSH.')
                print('JSON with multiple outbounds is also accepted; each proxy gets an independent health probe.')
                base=read_config_text('Xray configs')
                if not base: continue
                parsed=parse_xray_connect_inputs(base)
                if parsed.get('warnings'):
                    print('\n[!] Compatibility notes:')
                    for w in parsed['warnings']: print('  - '+w)
                if parsed.get('errors'):
                    print('\n[!] Some lines were skipped:'); print('\n'.join('  - '+x for x in parsed['errors']))
                proc,sess=start_xray_multi(state,'proxy' if c=='1' else 'tun',parsed)
                print(f'\n[+] Xray {label} started. PID={proc.pid}')
                if c=='1': print(f'[+] Master proxy: {proxy_bind(state)}')
                else: print('[+] TUN mode: system routing requested')
                render_xray_session(state); ui_pause()
            elif c=='3':
                # Live screen: watcher probes every 30s; this view refreshes once per second.
                while True:
                    ui_clear(); ui_header(state,'XRAY LIVE STATUS')
                    render_xray_session(state)
                    print('\nAuto ping: every 30 seconds  |  Press Q to return')
                    try:
                        ready,_,_=select.select([sys.stdin],[],[],1.0) if sys.stdin.isatty() else ([],[],[])
                        if ready:
                            ch=sys.stdin.read(1)
                            if ch.lower()=='q': break
                    except (OSError,ValueError):
                        time.sleep(1)
            elif c=='4':
                _stop_xray_watcher(state)
                stopped=stop_background_process('xray')
                # Stop tracked SSH adapters too.
                for name in list(CONNECT_PROC):
                    if name.startswith('xray-ssh-'): stop_background_process(name)
                stop_background_process('sni-spoof-scan')
                stop_background_process('sni-spoof-proxy')
                print('Xray stopped.' if stopped else 'Xray is not tracked as running.'); ui_pause()
            elif c=='0': return
        except KeyboardInterrupt:
            print('\nStopped.'); ui_pause()
        except Exception as e:
            print(f'\nError: {e}'); ui_pause()


def aether_menu(state):
    while True:
        ui_clear(); ui_header(state,'CONNECT / AETHER')
        ui_choice([
            ('1','Start Aether — MASQUE / balanced scan'),
            ('2','Stop Aether'),
            ('3','Status / proxy'),
            ('0','Back')
        ],'Aether')
        c=input('\nSelect › ').strip()
        try:
            if c=='1':
                proc=start_aether(state)
                print(f'\n[+] Aether started. PID={proc.pid}')
                print(f'[+] SOCKS5: {proxy_bind(state)}')
                print(f'[+] Log: {AETHER_LOG}')
                ui_pause()
            elif c=='2':
                stopped=stop_background_process('aether'); print('Aether stopped.' if stopped else 'Aether is not tracked as running.'); ui_pause()
            elif c=='3':
                st,pid=process_status('aether')
                print(f'\nStatus: {st}' + (f'  PID={pid}' if pid else ''))
                print(f'Proxy : {proxy_bind(state)}')
                print(f'Log   : {AETHER_LOG}')
                ui_pause()
            elif c=='0': return
        except KeyboardInterrupt:
            print('\nStopped.'); ui_pause()
        except Exception as e:
            print(f'\nError: {e}'); ui_pause()


def connect_menu(state):
    while True:
        ui_clear(); ui_header(state,'CONNECT')
        ui_choice([
            ('1','Aether'),
            ('2','Xray'),
            ('3','SNI Spoof — Xray IP + fake SNI'),
            ('0','Back')
        ],'Connect')
        c=input('\nSelect › ').strip()
        if c=='1': aether_menu(state)
        elif c=='2': xray_menu(state)
        elif c=='3': sni_spoof_menu(state)
        elif c=='0': return


# -------------------------
# Full internet diagnostics
# -------------------------
DIAG_SITES=[
    ('Cloudflare','www.cloudflare.com'),('Google','www.google.com'),
    ("Let's Encrypt",'letsencrypt.org'),('Xbox','www.xbox.com'),
    ('AMD','www.amd.com'),('Python','www.python.org'),('Vercel','vercel.com'),
    ('GitHub','github.com'),('Microsoft','www.microsoft.com'),('Amazon','www.amazon.com'),
    ('npm','registry.npmjs.org'),('PyPI','pypi.org'),('Docker','www.docker.com'),
    ('Debian','www.debian.org'),('Arch Linux','archlinux.org'),('Steam','store.steampowered.com'),
    ('Wikipedia','www.wikipedia.org'),('Cloudflare DNS','one.one.one.one'),
]
DIAG_DNS=[('Cloudflare DNS','1.1.1.1'),('Google DNS','8.8.8.8'),('Quad9 DNS','9.9.9.9')]


def _result_status(ok): return 'PASS' if ok else 'FAIL'


def _safe_float(v):
    try: return float(v)
    except Exception: return None


def _score_lower_better(v,good,bad):
    if v is None: return None
    if v<=good: return 100.0
    if v>=bad: return 0.0
    return max(0.0,min(100.0,100.0*(bad-v)/(bad-good)))


def _score_higher_better(v,low,high):
    if v is None: return None
    if v<=low: return 0.0
    if v>=high: return 100.0
    return max(0.0,min(100.0,100.0*(v-low)/(high-low)))


def _dns_udp_query(server,timeout=2.0):
    tid=os.urandom(2)
    ident=int.from_bytes(tid,'big')
    name=b'\x07example\x03com\x00'
    packet=tid+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+name+b'\x00\x01\x00\x01'
    start=time.perf_counter(); family=socket.AF_INET6 if ':' in server else socket.AF_INET
    try:
        with socket.socket(family,socket.SOCK_DGRAM) as s:
            s.settimeout(timeout); s.sendto(packet,(server,53)); data,_=s.recvfrom(4096)
        if len(data)>=12 and int.from_bytes(data[:2],'big')==ident:
            return True,(time.perf_counter()-start)*1000
    except Exception: pass
    return False,None


def _repeated_udp_dns(server,count=3,timeout=1.0):
    samples=[]
    for _ in range(count):
        ok,rtt=_dns_udp_query(server,timeout)
        samples.append(rtt if ok else None)
    good=[x for x in samples if x is not None]
    loss=100.0*(len(samples)-len(good))/max(1,len(samples))
    jitter=_jitter_from_samples(good) if len(good)>1 else 0.0
    return {'ok':bool(good),'samples':len(samples),'success':len(good),'loss':loss,'jitter':jitter,'rtt':statistics.median(good) if good else None}


def _curl_probe(host,scheme='https',timeout=4,family=None):
    curl=shutil.which('curl')
    if not curl: return None
    url=f"{scheme}://{host}/"
    cmd=[curl,'-sS','-L','--connect-timeout',str(max(1,int(timeout))), '--max-time',str(max(1,int(timeout))),
         '--range','0-1023','-o','/dev/null','-w','%{http_code}|%{time_connect}|%{time_total}',url]
    if family==4: cmd.insert(1,'-4')
    elif family==6: cmd.insert(1,'-6')
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=max(3,int(timeout)+2),check=False)
        raw=(p.stdout or '').strip().split('|')
        if len(raw)==3:
            code=int(raw[0]) if raw[0].isdigit() else 0
            total=float(raw[2]) if raw[2] else 0.0
            return {'ok':p.returncode==0 and 100<=code<600,'status':code or None,'rtt':total*1000 if total else None,'error':(p.stderr or '').strip()[:160]}
        return {'ok':False,'status':None,'rtt':None,'error':(p.stderr or 'curl failed').strip()[:160]}
    except Exception as exc:
        return {'ok':False,'status':None,'rtt':None,'error':str(exc)[:160]}


def _http_probe(host,scheme='https',timeout=5):
    result=_curl_probe(host,scheme,min(4,timeout))
    if result is not None: return result
    import http.client
    port=443 if scheme=='https' else 80
    try:
        if scheme=='https': conn=http.client.HTTPSConnection(host,port=port,timeout=timeout,context=ssl.create_default_context())
        else: conn=http.client.HTTPConnection(host,port=port,timeout=timeout)
        start=time.perf_counter(); conn.request('GET','/',headers={'User-Agent':'Spider-Diag/1.0','Connection':'close'})
        resp=conn.getresponse(); resp.read(256); status=resp.status; conn.close()
        return {'ok':100<=status<600,'status':status,'rtt':(time.perf_counter()-start)*1000,'error':''}
    except Exception as exc:
        return {'ok':False,'status':None,'rtt':None,'error':str(exc)[:160]}


def _dual_stack_probe(host,port=443,timeout=3):
    out={'ipv4':None,'ipv6':None}
    # curl gives hard subprocess timeouts and a reliable family selector, avoiding
    # potentially long resolver stalls inside Python's getaddrinfo on broken DNS.
    for label,family in (('ipv4',4),('ipv6',6)):
        res=_curl_probe(host,'https',min(timeout,2),family=family)
        if res is not None:
            if res.get('status') is None and not res.get('error'):
                out[label]={'state':'FAIL','rtt':None,'error':'No response'}
            elif res.get('ok'):
                out[label]={'state':'PASS','rtt':res.get('rtt'),'error':''}
            else:
                err=res.get('error') or ('No usable '+('IPv4' if family==4 else 'IPv6')+' route')
                # curl's IPv6 resolver error is effectively unavailable, not a Python N/A case.
                out[label]={'state':'FAIL','rtt':None,'error':err[:120]}
            continue
        # Fallback when curl is unavailable.
        start=time.perf_counter(); seen=False; errors=[]
        fam=socket.AF_INET6 if family==6 else socket.AF_INET
        try:
            infos=socket.getaddrinfo(host,port,fam,socket.SOCK_STREAM)
            for info in infos[:2]:
                try:
                    s=socket.socket(fam,socket.SOCK_STREAM); s.settimeout(min(timeout,1.5)); s.connect(info[4]); s.close(); seen=True; break
                except Exception as exc: errors.append(str(exc))
            out[label]={'state':'PASS' if seen else 'FAIL','rtt':(time.perf_counter()-start)*1000 if seen else None,'error':'' if seen else (errors[-1][:120] if errors else 'connect failed')}
        except Exception as exc:
            out[label]={'state':'FAIL','rtt':None,'error':str(exc)[:120]}
    return out


def _system_ping(host,count=5,timeout=2,ipv6=False):
    exe=shutil.which('ping')
    if not exe: return None
    cmd=[exe,'-6' if ipv6 else '-4','-c',str(count),'-W',str(timeout),host]
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=count*(timeout+1)+2,check=False)
        out=p.stdout+'\n'+p.stderr
        m=re.search(r'(\d+(?:\.\d+)?)%\s*packet loss',out)
        loss=float(m.group(1)) if m else None
        vals=[float(x) for x in re.findall(r'time[=<]\s*(\d+(?:\.\d+)?)\s*ms',out)]
        if vals:
            return {'ok':True,'loss':loss if loss is not None else 0.0,'rtt':statistics.median(vals),'jitter':_jitter_from_samples(vals),'samples':vals}
        if p.returncode==0: return {'ok':True,'loss':loss if loss is not None else 0.0,'rtt':None,'jitter':None,'samples':[]}
    except Exception: pass
    return None


def _diag_ping(ipv6=False):
    host='2606:4700:4700::1111' if ipv6 else '1.1.1.1'
    sysres=_system_ping(host,3,1,ipv6=ipv6)
    if sysres: return sysres
    try:
        ping,jitter,samples=_tcp_rtt(host,443,3,1.0)
        return {'ok':True,'loss':0.0,'rtt':ping,'jitter':jitter,'samples':samples}
    except Exception:
        return {'ok':False,'loss':100.0,'rtt':None,'jitter':None,'samples':[]}


def _diag_speed():
    res={'download_mbps':None,'upload_mbps':None}
    try: res['download_mbps']=run_speed_test.__name__ and _http_download('https://speed.cloudflare.com/__down?bytes=10000000',seconds=5)[0]
    except Exception: pass
    try: res['upload_mbps']=_http_upload('https://speed.cloudflare.com/__up',size_mb=4)[0]
    except Exception: pass
    return res


def _diag_waiting(label, fn, *args, **kwargs):
    """Run a diagnostic stage while showing a live elapsed-seconds Waiting counter."""
    started=time.monotonic()
    stop=Event()

    def ticker():
        while not stop.wait(1.0):
            elapsed=int(time.monotonic()-started)
            print(f"\rWaiting {elapsed}s — {label}...", end='', flush=True)

    print(f"Waiting 0s — {label}...", end='', flush=True)
    thread=Thread(target=ticker, daemon=True)
    thread.start()
    try:
        return fn(*args, **kwargs)
    finally:
        stop.set()
        thread.join(timeout=0.2)
        elapsed=int(time.monotonic()-started)
        print(f"\r{' ' * 100}\r", end='', flush=True)
        print(f"✓ {label} ({elapsed}s)")


def run_full_diagnostics(state):
    ui_clear(); ui_header(state,'DIAG — FULL INTERNET TEST')
    print('Testing protocols, IP stacks, DNS/UDP, important sites, latency/loss/jitter and bandwidth.')
    print('TCP latency uses connect probes when ICMP is unavailable; HTTP status 2xx–5xx still means the service answered.\n')
    result={'protocols':{},'stacks':{},'sites':[],'speed':{},'ping':{}}

    # Baseline protocol probes are intentionally parallel and bounded so a broken
    # resolver or firewall cannot make the full diagnostic take several minutes.
    tcp_targets=[('Cloudflare','1.1.1.1',443),('Google','8.8.8.8',443),('Quad9','9.9.9.9',443)]
    def tcp_target(item):
        name,host,port=item; samples=[]
        for _ in range(3):
            try: ok,rtt=tcp_probe(host,port,1.0); samples.append(rtt if ok else None)
            except Exception: samples.append(None)
        good=[x for x in samples if x is not None]
        return name,host,port,good
    def _tcp_stage():
        with ThreadPoolExecutor(max_workers=3) as ex:
            return list(ex.map(tcp_target,tcp_targets))
    tcp_rows=_diag_waiting('TCP', _tcp_stage)
    tcp_ok=sum(1 for _,_,_,g in tcp_rows if g)
    all_tcp=[x for _,_,_,g in tcp_rows for x in g]
    result['protocols']['TCP']={'ok':tcp_ok>0,'success':tcp_ok,'total':len(tcp_rows),'rtt':statistics.median(all_tcp) if all_tcp else None,'loss':100*(len(tcp_rows)-tcp_ok)/len(tcp_rows)}

    def _udp_stage():
        with ThreadPoolExecutor(max_workers=3) as ex:
            vals=list(ex.map(lambda x:_repeated_udp_dns(x[1],3,1.0),DIAG_DNS))
        return [(n,h,r) for (n,h),r in zip(DIAG_DNS, vals)]
    udp=_diag_waiting('UDP / DNS', _udp_stage)
    udp_ok=sum(1 for _,_,r in udp if r['ok'])
    good_udp=[r['rtt'] for _,_,r in udp if r['rtt'] is not None]
    result['protocols']['UDP']={'ok':udp_ok>0,'success':udp_ok,'total':len(udp),'rtt':statistics.median(good_udp) if good_udp else None,'loss':sum(r['loss'] for _,_,r in udp)/len(udp)}

    http_targets=['example.com','neverssl.com','httpforever.com']
    def _http_stage():
        with ThreadPoolExecutor(max_workers=3) as ex:
            return list(ex.map(lambda h:_http_probe(h,'http',2),http_targets))
    http_rows=_diag_waiting('HTTP', _http_stage)
    result['protocols']['HTTP']={'ok':any(x['ok'] for x in http_rows),'success':sum(x['ok'] for x in http_rows),'total':len(http_rows),'rtt':statistics.median([x['rtt'] for x in http_rows if x['rtt'] is not None]) if any(x['rtt'] for x in http_rows) else None,'loss':100*sum(not x['ok'] for x in http_rows)/len(http_rows)}

    # Run HTTPS/site checks concurrently; network timeouts must not serialize the entire diagnostic.
    def site_probe(item):
        label,host=item
        dual=_dual_stack_probe(host,443,1.5)
        https=_http_probe(host,'https',3)
        http=_http_probe(host,'http',3)
        return {'name':label,'host':host,'ipv4':dual['ipv4'],'ipv6':dual['ipv6'],'https':https,'http':http}

    def _sites_stage():
        with ThreadPoolExecutor(max_workers=min(18,len(DIAG_SITES))) as ex:
            return list(ex.map(site_probe,DIAG_SITES))
    site_results=_diag_waiting('HTTPS / sites', _sites_stage)
    result['sites']=site_results

    https_probe_rows=[x['https'] for x in site_results[:6]]
    result['protocols']['HTTPS']={'ok':any(x['ok'] for x in https_probe_rows),'success':sum(x['ok'] for x in https_probe_rows),'total':len(https_probe_rows),'rtt':statistics.median([x['rtt'] for x in https_probe_rows if x['rtt'] is not None]) if any(x['rtt'] for x in https_probe_rows) else None,'loss':100*sum(not x['ok'] for x in https_probe_rows)/len(https_probe_rows)}

    result['ping']['ipv4']=_diag_waiting('IPv4 ping', _diag_ping, False)
    result['ping']['ipv6']=_diag_waiting('IPv6 ping', _diag_ping, True)
    result['stacks']=_diag_waiting('IPv4 / IPv6 stack', _dual_stack_probe, 'www.cloudflare.com', 443, 1.5)

    result['speed']=_diag_waiting('Speed test', _diag_speed)
    # Weighted diagnostic score; unavailable metrics are excluded rather than treated as zero.
    components=[]
    proto_scores=[]
    for p in ('TCP','UDP','HTTP','HTTPS'):
        d=result['protocols'][p]
        success=100.0*(d['success']/max(1,d['total']))
        loss=max(0.0,min(100.0,float(d.get('loss',100))))
        proto_scores.append(0.7*success+0.3*(100-loss))
    components.append(('Protocols',sum(proto_scores)/len(proto_scores),0.30))
    s4=result['stacks'].get('ipv4',{}); s6=result['stacks'].get('ipv6',{})
    stack_vals=[]
    if s4.get('state')!='N/A': stack_vals.append(100.0 if s4.get('state')=='PASS' else 0.0)
    if s6.get('state')!='N/A': stack_vals.append(100.0 if s6.get('state')=='PASS' else 0.0)
    if stack_vals: components.append(('IP stacks',sum(stack_vals)/len(stack_vals),0.10))
    site_vals=[100.0 if x['https']['ok'] else 0.0 for x in result['sites']]
    components.append(('Important sites',sum(site_vals)/len(site_vals),0.25))
    p4=result['ping']['ipv4']; latency_score=_score_lower_better(_safe_float(p4.get('rtt')),20,250) or 0.0; loss_score=max(0.0,100.0-float(p4.get('loss',100))); jitter_score=_score_lower_better(_safe_float(p4.get('jitter')),5,80) or 0.0
    components.append(('Latency/loss/jitter',(0.45*latency_score+0.35*loss_score+0.20*jitter_score),0.15))
    down=_safe_float(result['speed'].get('download_mbps')); up=_safe_float(result['speed'].get('upload_mbps'))
    ds=_score_higher_better(down,1,150); us=_score_higher_better(up,1,50); speed_vals=[x for x in (ds,us) if x is not None]
    if speed_vals: components.append(('Bandwidth',sum(speed_vals)/len(speed_vals),0.20))
    weight=sum(w for _,_,w in components)
    result['score']=sum(v*w for _,v,w in components)/max(0.001,weight)
    result['components']=components
    return result


def render_diag(result):
    print('\n'+'='*92)
    print(f"OVERALL INTERNET SCORE: {result['score']:.1f}/100")
    print('='*92)
    if RICH_OK and console is not None:
        t=Table(title='Protocol health')
        for col in ('Protocol','Success','Loss','Median RTT','Status'): t.add_column(col)
        for p in ('TCP','UDP','HTTP','HTTPS'):
            d=result['protocols'][p]
            r='N/A' if d['rtt'] is None else f"{d['rtt']:.1f} ms"
            t.add_row(p,f"{d['success']}/{d['total']}",f"{d['loss']:.1f}%",r,'PASS' if d['ok'] else 'FAIL')
        console.print(t)
        t2=Table(title='IP / latency')
        for col in ('Test','IPv4','IPv6','RTT','Loss','Jitter'): t2.add_column(col)
        p4=result['ping']['ipv4']; p6=result['ping']['ipv6']; s4=result['stacks'].get('ipv4',{}); s6=result['stacks'].get('ipv6',{})
        t2.add_row('Ping', 'PASS' if p4['ok'] else 'FAIL','PASS' if p6['ok'] else 'FAIL', f"{p4['rtt']:.1f} ms" if p4.get('rtt') else 'N/A', f"{p4.get('loss',100):.1f}%", f"{p4['jitter']:.1f} ms" if p4.get('jitter') is not None else 'N/A')
        t2.add_row('IPv4/IPv6 stack',s4.get('state','N/A'),s6.get('state','N/A'),f"{s4.get('rtt'):.1f} ms" if s4.get('rtt') else 'N/A','—','—')
        console.print(t2)
        t3=Table(title='Important sites')
        for col in ('Service','HTTPS','HTTP','IPv4','IPv6','HTTPS RTT'): t3.add_column(col)
        for x in result['sites']:
            t3.add_row(x['name'],'PASS' if x['https']['ok'] else 'FAIL','PASS' if x['http']['ok'] else 'FAIL',x['ipv4']['state'],x['ipv6']['state'],f"{x['https']['rtt']:.0f} ms" if x['https'].get('rtt') else 'N/A')
        console.print(t3)
        t4=Table(title='Speed / score components')
        for c in ('Metric','Result','Weight'): t4.add_column(c)
        t4.add_row('Download',f"{result['speed'].get('download_mbps',0):.2f} Mbps" if result['speed'].get('download_mbps') else 'N/A','')
        t4.add_row('Upload',f"{result['speed'].get('upload_mbps',0):.2f} Mbps" if result['speed'].get('upload_mbps') else 'N/A','')
        for name,val,w in result.get('components',[]): t4.add_row(name,f"{val:.1f}/100",f"{w*100:.0f}%")
        console.print(t4)
    else:
        print(f"{'PROTOCOL':<10} {'SUCCESS':<10} {'LOSS':<9} {'RTT':<12} STATUS")
        for p in ('TCP','UDP','HTTP','HTTPS'):
            d=result['protocols'][p]
            rtt = f"{d['rtt']:.1f} ms" if d.get('rtt') is not None else 'N/A'
            print(f"{p:<10} {d['success']}/{d['total']:<8} {d['loss']:>6.1f}%  {rtt:<12} {'PASS' if d['ok'] else 'FAIL'}")
        print(f"IPv4 ping: {result['ping']['ipv4']}\nIPv6 ping: {result['ping']['ipv6']}")
        print(f"Download: {result['speed'].get('download_mbps')} Mbps | Upload: {result['speed'].get('upload_mbps')} Mbps")
        for x in result['sites']: print(f"{x['name']:<18} HTTPS={x['https']['ok']} HTTP={x['http']['ok']} IPv4={x['ipv4']['state']} IPv6={x['ipv6']['state']}")


def diag_menu(state):
    ui_clear(); ui_header(state,'DIAG')
    try:
        result=run_full_diagnostics(state)
        render_diag(result)
        state.cfg['last_diag']=result
        state.save()
    except KeyboardInterrupt:
        print('\n[!] Diagnostic run stopped.')
    except Exception as e:
        print(f'\n[!] Diagnostic error: {e}')
    ui_pause()


def settings_menu(state):
    while True:
        ui_clear(); ui_header(state,"SETTINGS")
        cfg=_connect_state(state)
        share='ON  → 0.0.0.0:1819' if cfg.get('lan_share_proxy') else 'OFF → 127.0.0.1:1819'
        ips=get_local_ips()
        ui_choice([
            ("1","Speed test — ping / jitter / download / upload"),
            ("2","Scan settings"),
            ("3",f"Share LAN proxy: {share}"),
            ("4","Ping providers — every 30s for Xray configs"),
            ("5","Show device IP addresses"),
            ("6","SNI Spoof auto-scan settings"),
            ("7","Clear scan cache"),
            ("0","Back"),
        ],"Settings")
        c=input("\nSelect › ").strip()
        try:
            if c=="1":
                ui_clear(); ui_header(state,"SPEED TEST")
                result=run_speed_test(); state.cfg["last_speedtest"]=result; state.save(); ui_pause()
            elif c=="2":
                print("\nCurrent scan settings:")
                for k in ("workers","max_in_flight","handshake_timeout","probe_count","rate","cooldown"):
                    print(f"  {k:<18} {state.cfg.get(k)}")
                print("\nEnter a value or press Enter to keep it.")
                for k in ("workers","max_in_flight","handshake_timeout","probe_count","rate"):
                    raw=input(f"{k} [{state.cfg.get(k)}]: ").strip()
                    if raw: state.cfg[k]=float(raw) if k in ("handshake_timeout","rate") else int(raw)
                state.save(); print("\nSaved."); ui_pause()
            elif c=="3":
                new=not bool(cfg.get('lan_share_proxy'))
                cfg['lan_share_proxy']=new; state.save()
                print(f"\nLAN sharing {'ENABLED' if new else 'DISABLED'}.")
                if new:
                    print('Proxy bind: 0.0.0.0:1819')
                    print('WARNING: this exposes an unauthenticated SOCKS proxy to your LAN.')
                    print('Only enable it on a trusted network and firewall the port from untrusted interfaces.')
                else: print('Proxy bind: 127.0.0.1:1819')
                ui_pause()
            elif c=="4":
                ui_clear(); ui_header(state,'XRAY PING PROVIDERS')
                providers=_ping_provider_hosts(state)
                print('Current providers (Xray live ping runs every 30 seconds):')
                for i,pv in enumerate(providers,1): print(f"  {i}. {pv['name']} → {pv['host']}:{pv['port']}")
                print('\nEnter comma-separated providers as Name=host:port')
                print('Example: CF=1.1.1.1:443,Google=8.8.8.8:443,Quad9=9.9.9.9:443')
                raw=input('New providers › ').strip()
                if raw:
                    vals=[]
                    for item in raw.split(','):
                        item=item.strip()
                        if not item: continue
                        if '=' in item: name,addr=item.split('=',1)
                        else: name,addr=item,item
                        host,port=_parse_host_port(addr,443)
                        if not host: continue
                        vals.append({'name':name.strip() or host,'host':host,'port':int(port or 443)})
                    if vals:
                        state.cfg['xray_ping_providers']=vals
                        state.save()
                print('Saved.')
                ui_pause()
            elif c=="5":
                ui_clear(); ui_header(state,'DEVICE IP')
                ips=get_local_ips()
                if ips:
                    for i,ip in enumerate(ips,1): print(f"  {i:02d}. {ip}")
                else: print('  No non-loopback address detected.')
                print(f"\nConfigured proxy bind: {proxy_bind(state)}")
                ui_pause()
            elif c=="6":
                ui_clear(); ui_header(state,'SNI SPOOF SETTINGS')
                print(f"IP limit          : {cfg.get('sni_spoof_auto_ip_limit',512)}")
                print(f"SNI limit         : {cfg.get('sni_spoof_sni_limit',64)}")
                print(f"Max pairs         : {cfg.get('sni_spoof_max_candidates',2048)}")
                print(f"Batch size        : {cfg.get('sni_spoof_batch_size',64)}")
                print(f"Probe timeout     : {cfg.get('sni_spoof_timeout',2.5)}s")
                print('Enter new values, or press Enter to keep the current value.')
                for key,kind in (("sni_spoof_auto_ip_limit",int),("sni_spoof_sni_limit",int),("sni_spoof_max_candidates",int),("sni_spoof_batch_size",int),("sni_spoof_timeout",float)):
                    raw=input(f"{key} [{cfg.get(key)}] › ").strip()
                    if raw: cfg[key]=kind(raw)
                cfg['sni_spoof_auto_ip_limit']=max(1,int(cfg['sni_spoof_auto_ip_limit']))
                cfg['sni_spoof_sni_limit']=max(1,int(cfg['sni_spoof_sni_limit']))
                cfg['sni_spoof_max_candidates']=max(1,int(cfg['sni_spoof_max_candidates']))
                cfg['sni_spoof_batch_size']=max(8,min(128,int(cfg['sni_spoof_batch_size'])))
                cfg['sni_spoof_timeout']=max(0.5,float(cfg['sni_spoof_timeout']))
                state.save(); print('Saved.'); ui_pause()
            elif c=="7":
                state.cache={}; state.save(); print("\nCache cleared."); ui_pause()
            elif c=="0": return
        except KeyboardInterrupt:
            print("\nStopped."); ui_pause()
        except Exception as e:
            print(f"\nError: {e}"); ui_pause()


def remove_menu(state):
    ui_clear(); ui_header(state,"REMOVE")
    ui_choice([("1","Clear cache"),("2","Remove the 'spider' command"),("0","Back")],"Remove")
    c=input("\nSelect › ").strip()
    if c=="1":
        state.cache={}; state.save(); print("Cache removed.")
    elif c=="2":
        confirm=input("Type REMOVE to remove ~/.local/bin/spider: ").strip()
        if confirm=="REMOVE":
            try: (Path.home()/".local/bin/spider").unlink()
            except FileNotFoundError: pass
            print("The spider command was removed. Project files were kept.")
        else: print("Cancelled.")
    ui_pause()

def contact_menu(state):
    ui_clear(); ui_header(state,"CONTACT")
    if RICH_OK:
        console.print(Panel("GitHub\nhttps://github.com/amirh00sain/SpiderPanel\n\nTelegram\nhttps://t.me/amirsp1ider", title="Contact Me", border_style="magenta"))
    else:
        print("\nGitHub  : https://github.com/amirh00sain/SpiderPanel")
        print("Telegram: https://t.me/amirsp1ider")
    ui_pause()

def advanced_menu(state):
    while True:
        ui_clear(); ui_header(state,"ADVANCED")
        ui_choice([
            ("1","Railway — paste config → scan healthy IPs → ranked configs"),
            ("2","Cloudflare — paste config → scan healthy IPs → ranked configs"),
            ("3","Fastly — paste config → scan healthy IPs → ranked configs"),
            ("4","Amazon CloudFront — paste config → scan healthy IPs → ranked configs"),
            ("5","DPI — add fingerprint + cybersuit + finalmask to config"),
            ("0","Back")],"Advanced")
        c=input("\nSelect › ").strip()
        try:
            if c=="1":
                base=read_config_text("Railway config")
                if not base: continue
                generated=advanced_config_scan(state,"RAILWAY",base)
                ui_pause("Press Enter to return...")
            elif c=="2":
                base=read_config_text("Cloudflare config")
                if not base: continue
                generated=advanced_config_scan(state,"CLOUDFLARE",base)
                ui_pause("Press Enter to return...")
            elif c=="3":
                base=read_config_text("Fastly config")
                if not base: continue
                generated=advanced_config_scan(state,"FASTLY",base)
                ui_pause("Press Enter to return...")
            elif c=="4":
                base=read_config_text("Amazon CloudFront config")
                if not base: continue
                generated=advanced_config_scan(state,"AMAZON",base)
                ui_pause("Press Enter to return...")
            elif c=="5":
                base=read_config_text("DPI config / URI")
                if not base: continue
                result=build_dpi_config(base)
                out=HOME/"dpi.txt"; out.write_text(result+"\n", encoding="utf-8"); os.chmod(out,0o600)
                if RICH_OK: console.print(Panel(result,title=f"DPI Output → {out}",border_style="green"))
                else: print(result); print(f"Saved: {out}")
                ui_pause()
            elif c=="0": return
        except KeyboardInterrupt:
            print("\n[!] Operation stopped."); ui_pause()
        except Exception as e:
            print(f"\nError: {e}"); ui_pause()


def menu():
    state=State()
    while True:
        ui_clear()
        # Fastfetch is a permanent part of the main UI: always render it first,
        # above the Spider header and main menu. It is not a settings/menu item.
        if not run_fastfetch():
            print_fallback_logo()
        print()
        ui_header(state)
        ui_choice([
            ("1","CDN"),
            ("2","Advanced"),
            ("3","Connect"),
            ("4","Diag"),
            ("5","Settings"),
            ("6","Remove"),
            ("7","Contact Me"),
            ("0","Exit")],"Main Menu")
        c=input("\nSelect › ").strip()
        try:
            if c=="1": cdn_menu(state)
            elif c=="2": advanced_menu(state)
            elif c=="3": connect_menu(state)
            elif c=="4": diag_menu(state)
            elif c=="5": settings_menu(state)
            elif c=="6": remove_menu(state)
            elif c=="7": contact_menu(state)
            elif c=="0":
                stop_background_process('aether'); stop_background_process('xray'); stop_background_process('sni-spoof-proxy')
                ui_clear(); print("Goodbye."); return
        except KeyboardInterrupt:
            print("\nInterrupted."); ui_pause()
        except Exception as e:
            print(f"\nError: {e}"); ui_pause()


def cf_menu(state):
    while True:
        ui_clear(); ui_header(state,"CLOUDFLARE")
        ui_choice([
            ("1","Scan cf_subnets.txt — TCP 443"),
            ("2","Custom CIDRs — TCP ports"),
            ("0","Back")],"Cloudflare")
        sel=input("\nSelect › ").strip()
        if sel=="0": return
        if sel not in ("1","2"): continue
        if sel=="1":
            cidrs=load_cidrs(DEFAULT_CF_FILE)
            ports=[443]
            candidate_limit=int(state.cfg.get("cf_max_candidates",20000))
        else:
            try:
                cidrs=[ipaddress.ip_network(x.strip()) for x in input("CIDRs (comma separated) › ").split(",") if x.strip()]
                if not cidrs: raise ValueError("No CIDRs supplied")
            except ValueError as e:
                print(f"Invalid CIDR: {e}"); ui_pause(); continue
            ui_choice([("1","443"),("2","80"),("3","8080"),("4","8443"),("5","443,80,8080,8443"),("0","Back")],"TCP Ports")
            ps=input("\nSelect › ").strip()
            port_map={"1":[443],"2":[80],"3":[8080],"4":[8443],"5":[443,80,8080,8443]}
            if ps=="0": continue
            if ps not in port_map: continue
            ports=port_map[ps]
            candidate_limit=int(state.cfg.get("cf_max_candidates",20000))
        ui_choice([("1","Ordered"),("2","Random"),("0","Back")],"Scan Order")
        order_sel=input("\nSelect › ").strip()
        if order_sel=="0": continue
        if order_sel not in ("1","2"): continue
        order="ordered" if order_sel=="1" else "random"
        ui_clear(); ui_header(state,"CLOUDFLARE SCAN")
        print("Only verified endpoints are shown live.")
        print("Press Q or Ctrl+C to stop.\n")
        stop=StopController().start()
        try:
            results=scan_cidrs_connectivity(state,cidrs,ports,order=order,limit=candidate_limit,stop=stop)
        finally:
            try: stop.close()
            except Exception: pass
        ui_result_table(results,"Cloudflare — reachable endpoints")
        ui_pause()



def scan_cdn_provider(state, provider, title, cidrs, *, ports=(443,), limit=None, order="ordered"):
    """Scan a CDN/provider IPv4 snapshot using the same quality scoring pipeline."""
    ui_clear(); ui_header(state, f"{title.upper()} SCAN")
    print("Only verified endpoints are shown live.")
    print(f"Target: {title}  |  TCP ports: {', '.join(map(str,ports))}")
    print("Quality: packet loss + ping + jitter + throughput (when measurable) + reliability + service.")
    print("Press Q or Ctrl+C to stop.\n")
    stop=StopController().start()
    try:
        results=scan_range(
            cidrs, "tcp", state, list(ports), order,
            int(limit if limit is not None else state.cfg.get("cdn_max_candidates",20000)),
            stop=stop,
        )
    finally:
        try: stop.close()
        except Exception: pass
    ui_result_table(results, f"{title} — reachable endpoints")
    ui_pause()


def fastly_menu(state):
    while True:
        ui_clear(); ui_header(state,"FASTLY")
        ui_choice([
            ("1","Scan Fastly IPv4 ranges — TCP 443"),
            ("2","Refresh Fastly + Amazon CloudFront ranges"),
            ("0","Back"),
        ],"Fastly")
        c=input("\nSelect › ").strip()
        if c=="0": return
        try:
            if c=="2":
                info=refresh_cdn_ranges()
                for name,count,path in info: print(f"✓ {name}: {count} CIDRs → {path}")
                ui_pause(); continue
            if c!="1": continue
            ui_choice([("1","Ordered"),("2","Random"),("0","Back")],"Scan Order")
            o=input("\nSelect › ").strip()
            if o=="0": continue
            if o not in ("1","2"): continue
            cidrs=cdn_provider_cidrs("FASTLY")
            scan_cdn_provider(state,"FASTLY","Fastly",cidrs,ports=(443,),order="ordered" if o=="1" else "random")
        except KeyboardInterrupt:
            print("\nInterrupted."); ui_pause()
        except Exception as e:
            print(f"\nError: {e}"); ui_pause()


def amazon_menu(state):
    while True:
        ui_clear(); ui_header(state,"AMAZON CLOUDFRONT")
        ui_choice([
            ("1","Scan Amazon CloudFront — Global + Regional Edge — TCP 443"),
            ("2","Refresh Amazon CloudFront ranges"),
            ("0","Back"),
        ],"Amazon CloudFront")
        c=input("\nSelect › ").strip()
        if c=="0": return
        try:
            if c=="2":
                info=refresh_cdn_ranges()
                for name,count,path in info: print(f"✓ {name}: {count} CIDRs → {path}")
                ui_pause(); continue
            if c!="1": continue
            ui_choice([("1","Ordered"),("2","Random"),("0","Back")],"Scan Order")
            o=input("\nSelect › ").strip()
            if o=="0": continue
            if o not in ("1","2"): continue
            cidrs=cdn_provider_cidrs("AMAZON")
            scan_cdn_provider(state,"AMAZON","Amazon CloudFront",cidrs,ports=(443,),order="ordered" if o=="1" else "random")
        except KeyboardInterrupt:
            print("\nInterrupted."); ui_pause()
        except Exception as e:
            print(f"\nError: {e}"); ui_pause()


def cdn_menu(state):
    while True:
        ui_clear(); ui_header(state,"CDN")
        ui_choice([
            ("1","Railway"),
            ("2","Cloudflare"),
            ("3","Fastly"),
            ("4","Amazon CloudFront"),
            ("5","Refresh Fastly + Amazon CloudFront IP ranges"),
            ("0","Back"),
        ],"CDN Providers")
        c=input("\nSelect › ").strip()
        try:
            if c=="1": railway_menu(state)
            elif c=="2": cf_menu(state)
            elif c=="3": fastly_menu(state)
            elif c=="4": amazon_menu(state)
            elif c=="5":
                info=refresh_cdn_ranges()
                print()
                for name,count,path in info: print(f"✓ {name}: {count} CIDRs → {path}")
                ui_pause()
            elif c=="0": return
        except KeyboardInterrupt:
            print("\nInterrupted."); ui_pause()
        except Exception as e:
            print(f"\nError: {e}"); ui_pause()


def railway_menu(state):
    while True:
        ui_clear(); ui_header(state,"RAILWAY")
        ui_choice([
            ("1","TCP — 66.33.22.220–66.33.22.250"),
            ("2","HTTPS — 69.46.46.0/24"),
            ("0","Back")],"Railway")
        c=input("\nSelect › ").strip()
        if c=="0": return
        if c not in ("1","2"): continue
        ui_choice([("1","Ordered"),("2","Random"),("0","Back")],"Scan Order")
        o=input("\nSelect › ").strip()
        if o=="0": continue
        if o not in ("1","2"): continue
        order="ordered" if o=="1" else "random"
        # Railway endpoint scans are intentionally fixed to TCP/TLS port 443.
        ps=[443]
        state.cfg["https_port"]=443
        ui_clear(); ui_header(state,"RAILWAY SCAN")
        print("Only verified endpoints are shown live.")
        print("Railway TCP/HTTPS scan port: 443")
        print("Press Q or Ctrl+C to stop.\n")
        if c=="1": r=scan_range(RAILWAY_TCP_CIDRS,"tcp",state,ps,order,0)
        else: r=scan_range(RAILWAY_HTTPS,"https",state,None,order,0)
        ui_result_table(r,"Railway — reachable endpoints")
        ui_pause()

def cli():
    ap=argparse.ArgumentParser(prog="spider")
    sp=ap.add_subparsers(dest="cmd")
    sp.add_parser("menu")
    sp.add_parser("fastfetch")
    sp.add_parser("diag")
    sp.add_parser("connect")
    sp.add_parser("sni-spoof")
    p=sp.add_parser("scan-tcp"); p.add_argument("--cidr",default=""); p.add_argument("--ports",default="443",help="Railway scan is fixed to 443"); p.add_argument("--order",choices=["ordered","random"],default="ordered")
    p=sp.add_parser("scan-https"); p.add_argument("--cidr",default="69.46.46.0/24"); p.add_argument("--port",type=int,default=443,help="Railway HTTPS scan is fixed to 443"); p.add_argument("--order",choices=["ordered","random"],default="ordered")
    a=ap.parse_args(); state=State()
    if a.cmd in (None,"menu"): menu(); return
    if a.cmd=="fastfetch":
        ui_clear()
        if not run_fastfetch():
            print_fallback_logo()
            print("\nfastfetch is not installed; showing the bundled dot logo instead.")
        return
    elif a.cmd=="diag":
        diag_menu(state)
    elif a.cmd=="connect":
        connect_menu(state)
    elif a.cmd=="sni-spoof":
        sni_spoof_menu(state)
    elif a.cmd=="scan-tcp":
        nets = [ipaddress.ip_network(a.cidr)] if a.cidr else list(RAILWAY_TCP_CIDRS)
        r=scan_range(nets,"tcp",state,[443],a.order); print(json.dumps(r,indent=2))
    elif a.cmd=="scan-https":
        state.cfg["https_port"]=443; r=scan_range(ipaddress.ip_network(a.cidr),"https",state,None,a.order); print(json.dumps(r,indent=2))

if __name__=="__main__": cli()
