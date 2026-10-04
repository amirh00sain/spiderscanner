#!/usr/bin/env python3
"""
spider: Termux/Linux TCP/HTTPS endpoint scanner.

Scope:
- Cloudflare TCP/HTTPS connectivity checks.
- Railway TCP/HTTPS connectivity checks.
- Advanced config replacement and DPI helpers.
- Multi-metric quality scoring: packet loss, latency, jitter, speed, reliability, and service validation.
"""
from __future__ import annotations
import argparse, ipaddress, json, os, random, re, select, signal, socket, ssl, statistics, struct, subprocess, sys, time, copy, shutil
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
RAW_CF_FILE_URL = "https://raw.githubusercontent.com/amirh00sain/spiderscanner/main/data/cf_subnets.txt"
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
    "score_weights": {"loss": 30.0, "latency": 20.0, "jitter": 15.0, "speed": 15.0, "reliability": 10.0, "service": 10.0},
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
    vals={
        'loss':_higher_is_better(100.0-float(row.get('packet_loss',100.0)),0,100),
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


def add_packet_loss(results,probe_fn,state,*,limit=None,speed_probe=None):
    """Measure repeated latency, packet loss, jitter, reliability and optional throughput."""
    if not results: return results
    attempts=max(3,int(state.cfg.get('probe_count',5)))
    visible=max(1,int(limit if limit is not None else state.cfg.get('quality_probe_limit',25)))
    ranked=sorted(results,key=lambda x:(-x.get('score',0),x.get('rtt_ms',999999)))
    timeout=float(state.cfg.get('advanced_timeout',1.0))
    for row in ranked[:visible]:
        ip=row.get('ip'); port=int(row.get('port',443)); ok_count=0; rtts=[]
        for _ in range(attempts):
            try: ok,rtt=probe_fn(ip,port,timeout)
            except Exception: ok,rtt=False,None
            if ok:
                ok_count+=1
                if rtt is not None: rtts.append(float(rtt))
        if not rtts and row.get('rtt_ms') is not None: rtts=[float(row['rtt_ms'])]
        row['attempts']=attempts; row['success_count']=ok_count
        row['packet_loss']=round(100.0*(attempts-ok_count)/attempts,2)
        if rtts:
            row['rtt_ms']=round(statistics.median(rtts),2)
            row['median_rtt_ms']=row['rtt_ms']
            row['min_rtt_ms']=round(min(rtts),2)
            row['jitter_ms']=round(_jitter_from_samples(rtts),2)
        row['reliability_score']=round(100.0*ok_count/attempts,2)
        if speed_probe is not None and ok_count:
            try: speed=speed_probe(ip,port,max(3.0,timeout*3.0))
            except Exception: speed=None
            if speed is not None and speed>0: row['speed_mbps']=round(float(speed),3)
        _score_result(row,state.cfg)
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
        try: stop.close()
        except Exception: pass
    ranked=sorted(results,key=lambda x:x.get("rtt_ms",999999))
    speed_probe=https_transfer_probe if any(int(r.get("port",0))==443 for r in ranked) else None
    return add_packet_loss(ranked,fn,state,speed_probe=speed_probe)

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
    if kind.upper()=="RAILWAY":
        cidrs=list(RAILWAY_TCP_CIDRS)
        title="Railway"
    elif kind.upper()=="CLOUDFLARE":
        cidrs=load_cidrs(DEFAULT_CF_FILE)
        title="Cloudflare"
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
    out_dir=HOME/("advanced-railway" if kind.upper()=="RAILWAY" else "advanced-cloudflare")
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
    rows=results[:limit]
    if RICH_OK:
        t=Table(title=title,show_lines=False)
        for col in ('#','IP','Port','Ping','Jitter','Loss','Speed','Score'):
            t.add_column(col,justify='right' if col!='IP' else 'left')
        for i,r in enumerate(rows,1):
            def fmt(k,suffix=''):
                v=r.get(k,'—'); return f'{v:.1f}{suffix}' if isinstance(v,(int,float)) else str(v)
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
    for i,r in enumerate(results,1):
        ip=r["ip"] if isinstance(r,dict) else r.ip
        conf=replace_server_in_config(base_config,ip)
        safe_ip=ip.replace(':','_')
        path=out_dir/f"{title.lower()}-{i:03d}-{safe_ip}.conf"
        path.write_text(conf,encoding="utf-8")
        generated.append((i,r,path,conf))

    if not generated:
        print("\nNo healthy configs generated.",flush=True)
        return []

    all_path=out_dir/(title.lower()+"-all.txt")
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


def settings_menu(state):
    while True:
        ui_clear(); ui_header(state,"SETTINGS")
        ui_choice([
            ("1","Speed test — ping / jitter / download / upload"),
            ("2","Scan settings"),
            ("3","Clear scan cache"),
            ("0","Back"),
        ],"Settings")
        c=input("\nSelect › ").strip()
        try:
            if c=="1":
                ui_clear(); ui_header(state,"SPEED TEST")
                result=run_speed_test(); state.cfg["last_speedtest"]=result; state.save(); ui_pause()
            elif c=="2":
                cfg=state.cfg
                print("\nCurrent scan settings:")
                for k in ("workers","max_in_flight","handshake_timeout","probe_count","rate","cooldown"):
                    print(f"  {k:<18} {cfg.get(k)}")
                print("\nEnter a value or press Enter to keep it.")
                for k in ("workers","max_in_flight","handshake_timeout","probe_count","rate"):
                    raw=input(f"{k} [{cfg.get(k)}]: ").strip()
                    if raw:
                        cfg[k]=float(raw) if k in ("handshake_timeout","rate") else int(raw)
                state.save(); print("\nSaved."); ui_pause()
            elif c=="3":
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
            ("3","DPI — add fingerprint + cybersuit + finalmask to config"),
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
            ("1","Cloudflare"),
            ("2","Railway"),
            ("3","Advanced"),
            ("4","Settings"),
            ("5","Remove"),
            ("6","Contact Me"),
            ("0","Exit")],"Main Menu")
        c=input("\nSelect › ").strip()
        try:
            if c=="1": cf_menu(state)
            elif c=="2": railway_menu(state)
            elif c=="3": advanced_menu(state)
            elif c=="4": settings_menu(state)
            elif c=="5": remove_menu(state)
            elif c=="6": contact_menu(state)
            elif c=="0":
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
    elif a.cmd=="scan-tcp":
        nets = [ipaddress.ip_network(a.cidr)] if a.cidr else list(RAILWAY_TCP_CIDRS)
        r=scan_range(nets,"tcp",state,[443],a.order); print(json.dumps(r,indent=2))
    elif a.cmd=="scan-https":
        state.cfg["https_port"]=443; r=scan_range(ipaddress.ip_network(a.cidr),"https",state,None,a.order); print(json.dumps(r,indent=2))

if __name__=="__main__": cli()
