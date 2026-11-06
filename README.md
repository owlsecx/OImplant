# 🦉 OImplant

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Attack%20/%20Offensive-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OImplant** — Implant config builder/analyzer — sleep, kill-date, channels, IOCs ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OImplant — Implant config builder/analyzer — sleep, kill-date, channels, IOCs. Implant config builder/analyzer (benign simulated configs). Generate/parse benign simulated implant configs (sleep, kill-date, channels), decode strings, extract IOCs.

---

## ✨ Features

- Build and analyze implant configuration profiles
- Model sleep, kill-date and channel settings
- Extract and review IOC-oriented fields
- Safe purple-team planning without live malware
- Compare configs and highlight risky defaults
- Export operator-ready configuration summaries

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OImplant OImplant.go
./OImplant --help
./OImplant --build --format json
./OImplant --input config.json --analyze
./OImplant --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
