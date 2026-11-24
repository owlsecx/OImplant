# 🦉 OImplant

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Attack%20/%20Offensive-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square"/>
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

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

**GNU General Public License v3.0** — © 2026 Owlsec LLC

This tool is free software: its full source code is published in this repository and you may study, modify and redistribute it under the GPL-3.0.

> Other OwlSec tools are separate, independent programs under their own terms; many remain proprietary.
