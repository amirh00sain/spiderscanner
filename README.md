# 🕷️ Spider Network Scanner

<p align="center"><img src="svg/hero.svg" alt="Spider Network Scanner" width="100%"></p>

A fast terminal UI for Cloudflare and Railway endpoint checks, Advanced config replacement, DPI config URI generation, and multi-metric endpoint quality scoring.

Version: **1**

### Quality scoring

Spider now ranks verified endpoints with a measured quality score based on packet loss (30%), latency/ping (20%), jitter (15%), real HTTPS throughput when measurable (15%), probe reliability (10%), and service/dataplane validation (10%). Metrics that are not measurable for a protocol are excluded and their weight is redistributed instead of being treated as zero. HTTPS endpoints can receive a real download-throughput measurement.

---

## 🚀 Installation

<p align="center"><img src="svg/install.svg" alt="Install Spider" width="100%"></p>

Or run the command directly:

```bash
curl -fsSL https://raw.githubusercontent.com/amirh00sain/spiderscanner/main/install.sh | bash
```

Then open Spider:

```bash
spider
```

The installer installs Spider under `~/.local/share/spider` and creates the `spider` command in `~/.local/bin`.

---

## ✦ Briefly

Spider provides a structured terminal UI with live, stoppable scans for Cloudflare and Railway, Advanced Railway/Cloudflare config replacement, DPI config URI generation, and a built-in Speed Test. Fastfetch with the `amirh00sain` dot-matrix logo is shown at the top of the main menu.

---

## 📢 Contact

**GitHub**  
https://github.com/amirh00sain/SpiderPanel

**Telegram**  
https://t.me/amirsp1ider

---

<p align="center"><img src="svg/logo.svg" alt="amirh00sain" width="520"></p>

<p align="center">Made by <b>amirh00sain</b></p>
