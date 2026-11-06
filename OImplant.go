// OImplant — Implant config builder/analyzer (benign simulated configs).
// Author: khaled.s.haddad   Website: owlsec.org   Language: Go (stdlib only)
// Generate/parse benign simulated implant configs (sleep, kill-date, channels),
// decode strings, extract IOCs. For authorized lab and detection engineering.
// AUTHORIZED TESTING ONLY. MITRE ATT&CK TA0011 / related.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
	DR  = "\033[96m" // legacy frame alias → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func line(w int)       { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", B, R) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

const BANNER = `
 ██████╗ ██╗███╗   ███╗██████╗ ██╗      █████╗ ███╗   ██╗████████╗
██╔═══██╗██║████╗ ████║██╔══██╗██║     ██╔══██╗████╗  ██║╚══██╔══╝
██║   ██║██║██╔████╔██║██████╔╝██║     ███████║██╔██╗ ██║   ██║   
██║   ██║██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══██║██║╚██╗██║   ██║   
╚██████╔╝██║██║ ╚═╝ ██║██║     ███████╗██║  ██║██║ ╚████║   ██║   
 ╚═════╝ ╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   
`

const APPNAME = "OImplant"
const SUITE = "Owl Offensive Suite"
const TAGLINE = "Implant config builder/analyzer — sleep, kill-date, channels, IOCs"
const SUBLINE = "Sleep · Jitter · Kill-date · Working-hours · Channels · IOCs (benign, offline)"
const VERSION = "2.2.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"
const PRIMARY_MITRE = "TA0011"

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW) + col("   ·   MITRE "+PRIMARY_MITRE, DIM))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}
func menu(title string, items []string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Printf("  %s  %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(it, W))
	}
	fmt.Println()
	fmt.Println("  " + col("[H]", YLW+B) + "  " + col("Help & Usage", W) + col("  — how to use, options, CLI flags & examples", DIM))
	fmt.Println("  " + col("[0]", R+B) + "  " + col("Exit", W))
	fmt.Println()
	rule()
	return prompt("Select option")
}
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ====================================================================
//  DOMAIN MODEL
// ====================================================================

// CatalogEntry is a single technique / binary / mechanism / channel
// record in this tool's knowledge base. It is the unit that powers
// the catalog browser, the marker scanner, the planner and exports.
type CatalogEntry struct {
	ID        string
	Name      string
	Category  string
	Platform  string
	Tactic    string
	Technique string
	Severity  string
	Summary   string
	Detail    string
	Commands  []string
	Markers   []string
	Detection []string
	Refs      []string
	Tags      []string
}

// Finding is a single observation produced by scanning an input, by a
// planner, or by a configuration audit. Findings carry MITRE mapping,
// severity and evidence and feed every export format.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"`
	Score     int      `json:"score"`
	Tactic    string   `json:"tactic"`
	Technique string   `json:"technique"`
	File      string   `json:"file,omitempty"`
	Line      int      `json:"line,omitempty"`
	Evidence  string   `json:"evidence,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Detection string   `json:"detection,omitempty"`
	Refs      []string `json:"refs,omitempty"`
	Fprint    string   `json:"fingerprint"`
}

// Report bundles a full analysis run for export and grading.
type Report struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	Tagline    string    `json:"tagline"`
	Generated  string    `json:"generated"`
	Target     string    `json:"target,omitempty"`
	Mode       string    `json:"mode"`
	Findings   []Finding `json:"findings"`
	Grade      string    `json:"grade"`
	Score      int       `json:"score"`
	Summary    string    `json:"summary"`
	MitrePrime string    `json:"mitrePrimary"`
}

// severity ordering / weights
var sevRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
var sevWeight = map[string]int{"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}

func sevColor(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return R + B
	case "high":
		return R
	case "medium":
		return YLW
	case "low":
		return GRN
	default:
		return GY
	}
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])[:16]
}

// ====================================================================
//  CATALOG (tool-specific knowledge base)
// ====================================================================

var catalog = []CatalogEntry{
	{
		ID: "IMP-SLEEP", Name: "Sleep / beacon interval", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071", Severity: "low",
		Summary:   "Implant sleep interval between callbacks.",
		Detail:    "Implant sleep interval between callbacks. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Sleep / beacon interval", "# MITRE T1071"},
		Markers:   []string{"sleep\\s*=\\s*\\d+", "beacon.?interval", "callback_interval"},
		Detection: []string{"Hunt markers of Sleep / beacon interval", "Map to T1071", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-JITTER", Name: "Jitter percent", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071", Severity: "low",
		Summary:   "Randomization of sleep.",
		Detail:    "Randomization of sleep. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Jitter percent", "# MITRE T1071"},
		Markers:   []string{"jitter\\s*=\\s*\\d+", "jitter_percent"},
		Detection: []string{"Hunt markers of Jitter percent", "Map to T1071", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-KILLDATE", Name: "Kill date", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1489", Severity: "medium",
		Summary:   "Self-disable after date.",
		Detail:    "Self-disable after date. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Kill date", "# MITRE T1489"},
		Markers:   []string{"kill.?date", "killdate\\s*="},
		Detection: []string{"Hunt markers of Kill date", "Map to T1489", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1489"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-WORKINGHOURS", Name: "Working hours guard", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1497", Severity: "low",
		Summary:   "Only run during business hours.",
		Detail:    "Only run during business hours. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Working hours guard", "# MITRE T1497"},
		Markers:   []string{"working.?hours", "business.?hours"},
		Detection: []string{"Hunt markers of Working hours guard", "Map to T1497", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1497"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-USERAGENT", Name: "Callback User-Agent", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071.001", Severity: "low",
		Summary:   "HTTP User-Agent string.",
		Detail:    "HTTP User-Agent string. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Callback User-Agent", "# MITRE T1071.001"},
		Markers:   []string{"user.?agent\\s*=", "UserAgent"},
		Detection: []string{"Hunt markers of Callback User-Agent", "Map to T1071.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071.001"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-HOSTS", Name: "Callback host list", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1008", Severity: "medium",
		Summary:   "Comma-separated callback hosts.",
		Detail:    "Comma-separated callback hosts. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Callback host list", "# MITRE T1008"},
		Markers:   []string{"callback.?hosts?\\s*=", "c2.?hosts?\\s*="},
		Detection: []string{"Hunt markers of Callback host list", "Map to T1008", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1008"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-PORT", Name: "Callback port", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071", Severity: "low",
		Summary:   "C2 port.",
		Detail:    "C2 port. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Callback port", "# MITRE T1071"},
		Markers:   []string{"callback.?port\\s*=", "c2.?port\\s*="},
		Detection: []string{"Hunt markers of Callback port", "Map to T1071", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-PROTOCOL", Name: "Transport protocol", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071", Severity: "medium",
		Summary:   "http/https/dns/smb/mtls.",
		Detail:    "http/https/dns/smb/mtls. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Transport protocol", "# MITRE T1071"},
		Markers:   []string{"protocol\\s*=\\s*(https?|dns|smb|mtls)", "transport\\s*="},
		Detection: []string{"Hunt markers of Transport protocol", "Map to T1071", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-PSK", Name: "Pre-shared key / PSK", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1573", Severity: "high",
		Summary:   "Symmetric key material in config.",
		Detail:    "Symmetric key material in config. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Pre-shared key / PSK", "# MITRE T1573"},
		Markers:   []string{"psk\\s*=", "shared.?key\\s*=", "aes.?key\\s*="},
		Detection: []string{"Hunt markers of Pre-shared key / PSK", "Map to T1573", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1573"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-PUBKEY", Name: "Public key pin", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1573", Severity: "medium",
		Summary:   "Pinned server pubkey.",
		Detail:    "Pinned server pubkey. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Public key pin", "# MITRE T1573"},
		Markers:   []string{"public.?key\\s*=", "server.?key\\s*=", "spki"},
		Detection: []string{"Hunt markers of Public key pin", "Map to T1573", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1573"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-PROXY", Name: "Proxy settings", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1090", Severity: "medium",
		Summary:   "Explicit proxy host:port.",
		Detail:    "Explicit proxy host:port. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Proxy settings", "# MITRE T1090"},
		Markers:   []string{"proxy\\s*=", "proxy.?host", "HTTPS_PROXY"},
		Detection: []string{"Hunt markers of Proxy settings", "Map to T1090", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1090"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-SPAWNTO", Name: "Spawnto / injection target", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0005", Technique: "T1055", Severity: "medium",
		Summary:   "Process used for injection.",
		Detail:    "Process used for injection. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Spawnto / injection target", "# MITRE T1055"},
		Markers:   []string{"spawnto\\s*=", "inject.?into"},
		Detection: []string{"Hunt markers of Spawnto / injection target", "Map to T1055", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1055"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-PIPENAME", Name: "Named pipe name", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0011", Technique: "T1090", Severity: "medium",
		Summary:   "SMB/pipe beacon name.",
		Detail:    "SMB/pipe beacon name. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Named pipe name", "# MITRE T1090"},
		Markers:   []string{"pipe.?name\\s*=", "named.?pipe\\s*="},
		Detection: []string{"Hunt markers of Named pipe name", "Map to T1090", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1090"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-URI", Name: "Callback URI path", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071.001", Severity: "low",
		Summary:   "HTTP path for beacon.",
		Detail:    "HTTP path for beacon. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Callback URI path", "# MITRE T1071.001"},
		Markers:   []string{"uri\\s*=\\s*\\\"?/", "callback.?path\\s*="},
		Detection: []string{"Hunt markers of Callback URI path", "Map to T1071.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071.001"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-HEADERS", Name: "Custom headers", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071.001", Severity: "low",
		Summary:   "Extra HTTP headers.",
		Detail:    "Extra HTTP headers. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Custom headers", "# MITRE T1071.001"},
		Markers:   []string{"headers?\\s*=", "custom.?header"},
		Detection: []string{"Hunt markers of Custom headers", "Map to T1071.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071.001"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-ENCODE", Name: "Encoding layer", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1132", Severity: "medium",
		Summary:   "base64/netbios/mask encoding.",
		Detail:    "base64/netbios/mask encoding. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Encoding layer", "# MITRE T1132"},
		Markers:   []string{"encoding\\s*=\\s*(base64|netbios|mask)", "encoder\\s*="},
		Detection: []string{"Hunt markers of Encoding layer", "Map to T1132", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1132"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-OBFUS", Name: "Obfuscation flag", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1027", Severity: "medium",
		Summary:   "Strings obfuscated in implant.",
		Detail:    "Strings obfuscated in implant. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Obfuscation flag", "# MITRE T1027"},
		Markers:   []string{"obfuscat", "string.?encrypt"},
		Detection: []string{"Hunt markers of Obfuscation flag", "Map to T1027", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1027"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-ANTIDEBUG", Name: "Anti-debug checks", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1622", Severity: "medium",
		Summary:   "IsDebuggerPresent / timing checks.",
		Detail:    "IsDebuggerPresent / timing checks. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Anti-debug checks", "# MITRE T1622"},
		Markers:   []string{"anti.?debug", "IsDebuggerPresent", "CheckRemoteDebugger"},
		Detection: []string{"Hunt markers of Anti-debug checks", "Map to T1622", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1622"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-ANTIVM", Name: "Anti-VM checks", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1497.001", Severity: "medium",
		Summary:   "CPUID / MAC OUI / driver checks.",
		Detail:    "CPUID / MAC OUI / driver checks. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Anti-VM checks", "# MITRE T1497.001"},
		Markers:   []string{"anti.?vm", "anti.?sandbox", "VMware|VirtualBox|VBox"},
		Detection: []string{"Hunt markers of Anti-VM checks", "Map to T1497.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1497.001"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-PERSIST", Name: "Persistence mode", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0003", Technique: "T1547", Severity: "high",
		Summary:   "Implant persists via service/runkey/task.",
		Detail:    "Implant persists via service/runkey/task. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Persistence mode", "# MITRE T1547"},
		Markers:   []string{"persist(ence)?\\s*=", "install.?method"},
		Detection: []string{"Hunt markers of Persistence mode", "Map to T1547", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1547"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-PRIV", Name: "Requested privileges", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0004", Technique: "T1134", Severity: "medium",
		Summary:   "SeDebug etc requested at start.",
		Detail:    "SeDebug etc requested at start. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Requested privileges", "# MITRE T1134"},
		Markers:   []string{"require.?priv", "SeDebugPrivilege"},
		Detection: []string{"Hunt markers of Requested privileges", "Map to T1134", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1134"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-MUTANT", Name: "Mutex / named event", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0005", Technique: "T1070", Severity: "low",
		Summary:   "Single-instance mutex name.",
		Detail:    "Single-instance mutex name. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Mutex / named event", "# MITRE T1070"},
		Markers:   []string{"mutex\\s*=", "mutant\\s*=", "named.?event"},
		Detection: []string{"Hunt markers of Mutex / named event", "Map to T1070", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1070"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-DLL", Name: "Export / reflective DLL", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0005", Technique: "T1620", Severity: "medium",
		Summary:   "Reflective DLL load markers.",
		Detail:    "Reflective DLL load markers. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Export / reflective DLL", "# MITRE T1620"},
		Markers:   []string{"reflective.?dll", "DllMain", "ReflectiveLoader"},
		Detection: []string{"Hunt markers of Export / reflective DLL", "Map to T1620", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1620"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-SHELLCODE", Name: "Shellcode blob markers", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1055", Severity: "high",
		Summary:   "Embedded shellcode hex/base64 blobs.",
		Detail:    "Embedded shellcode hex/base64 blobs. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Shellcode blob markers", "# MITRE T1055"},
		Markers:   []string{"shellcode", "\\\\x90\\\\x90\\\\x90", "buf\\s*=\\s*\\\""},
		Detection: []string{"Hunt markers of Shellcode blob markers", "Map to T1055", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1055"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-STAGE", Name: "Stager URL", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1105", Severity: "high",
		Summary:   "URL of second-stage payload.",
		Detail:    "URL of second-stage payload. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Stager URL", "# MITRE T1105"},
		Markers:   []string{"stager.?url\\s*=", "stage.?url\\s*=", "payload.?url"},
		Detection: []string{"Hunt markers of Stager URL", "Map to T1105", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1105"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-USER", Name: "Run-as user guard", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1497", Severity: "low",
		Summary:   "Only run if certain user logged in.",
		Detail:    "Only run if certain user logged in. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Run-as user guard", "# MITRE T1497"},
		Markers:   []string{"required.?user\\s*=", "run.?as\\s*="},
		Detection: []string{"Hunt markers of Run-as user guard", "Map to T1497", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1497"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-DOMAIN", Name: "Domain join guard", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1497", Severity: "low",
		Summary:   "Only run on domain-joined hosts.",
		Detail:    "Only run on domain-joined hosts. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Domain join guard", "# MITRE T1497"},
		Markers:   []string{"require.?domain", "domain.?joined"},
		Detection: []string{"Hunt markers of Domain join guard", "Map to T1497", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1497"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-PROCESS", Name: "Parent process guard", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1497", Severity: "low",
		Summary:   "Only run under expected parent.",
		Detail:    "Only run under expected parent. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Parent process guard", "# MITRE T1497"},
		Markers:   []string{"required.?parent", "parent.?process"},
		Detection: []string{"Hunt markers of Parent process guard", "Map to T1497", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1497"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-IOC-IP", Name: "Hardcoded C2 IP IOC", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071", Severity: "high",
		Summary:   "Literal IPv4 C2 address in config.",
		Detail:    "Literal IPv4 C2 address in config. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Hardcoded C2 IP IOC", "# MITRE T1071"},
		Markers:   []string{"\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b"},
		Detection: []string{"Hunt markers of Hardcoded C2 IP IOC", "Map to T1071", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-IOC-DOMAIN", Name: "Hardcoded C2 domain IOC", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071", Severity: "high",
		Summary:   "Literal C2 domain.",
		Detail:    "Literal C2 domain. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Hardcoded C2 domain IOC", "# MITRE T1071"},
		Markers:   []string{"c2\\.[a-z0-9.-]+\\.[a-z]{2,}", "beacon\\.[a-z0-9.-]+"},
		Detection: []string{"Hunt markers of Hardcoded C2 domain IOC", "Map to T1071", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-IOC-HASH", Name: "Payload hash reference", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1070", Severity: "low",
		Summary:   "SHA256 of expected stage.",
		Detail:    "SHA256 of expected stage. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Payload hash reference", "# MITRE T1070"},
		Markers:   []string{"sha256\\s*=\\s*[a-fA-F0-9]{64}", "payload.?hash"},
		Detection: []string{"Hunt markers of Payload hash reference", "Map to T1070", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1070"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-CHANNEL-DNS", Name: "DNS channel enabled", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071.004", Severity: "high",
		Summary:   "DNS transport selected.",
		Detail:    "DNS transport selected. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# DNS channel enabled", "# MITRE T1071.004"},
		Markers:   []string{"channel\\s*=\\s*dns", "dns.?enabled\\s*=\\s*true"},
		Detection: []string{"Hunt markers of DNS channel enabled", "Map to T1071.004", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071.004"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-CHANNEL-HTTP", Name: "HTTP channel enabled", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071.001", Severity: "medium",
		Summary:   "HTTP transport selected.",
		Detail:    "HTTP transport selected. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# HTTP channel enabled", "# MITRE T1071.001"},
		Markers:   []string{"channel\\s*=\\s*https?", "http.?enabled"},
		Detection: []string{"Hunt markers of HTTP channel enabled", "Map to T1071.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071.001"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-CHANNEL-SMB", Name: "SMB channel enabled", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0011", Technique: "T1071", Severity: "medium",
		Summary:   "SMB transport selected.",
		Detail:    "SMB transport selected. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# SMB channel enabled", "# MITRE T1071"},
		Markers:   []string{"channel\\s*=\\s*smb", "smb.?enabled"},
		Detection: []string{"Hunt markers of SMB channel enabled", "Map to T1071", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-WATCHDOG", Name: "Watchdog / restart loop", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0003", Technique: "T1547", Severity: "medium",
		Summary:   "Watchdog restarts implant on crash.",
		Detail:    "Watchdog restarts implant on crash. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Watchdog / restart loop", "# MITRE T1547"},
		Markers:   []string{"watchdog", "respawn", "keepalive.?loop"},
		Detection: []string{"Hunt markers of Watchdog / restart loop", "Map to T1547", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1547"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-CONFIG-B64", Name: "Base64-encoded config blob", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1027", Severity: "medium",
		Summary:   "Entire config stored as base64.",
		Detail:    "Entire config stored as base64. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Base64-encoded config blob", "# MITRE T1027"},
		Markers:   []string{"config\\s*=\\s*[A-Za-z0-9+/=]{40,}"},
		Detection: []string{"Hunt markers of Base64-encoded config blob", "Map to T1027", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1027"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-CONFIG-XOR", Name: "XOR-encoded config", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1027.007", Severity: "medium",
		Summary:   "Config XOR'd with a key.",
		Detail:    "Config XOR'd with a key. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# XOR-encoded config", "# MITRE T1027.007"},
		Markers:   []string{"xor.?key\\s*=", "config.?xor"},
		Detection: []string{"Hunt markers of XOR-encoded config", "Map to T1027.007", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1027.007"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-STACK", Name: "Call-stack spoof flag", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0005", Technique: "T1055", Severity: "medium",
		Summary:   "Spoof call stacks for API calls.",
		Detail:    "Spoof call stacks for API calls. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Call-stack spoof flag", "# MITRE T1055"},
		Markers:   []string{"stack.?spoof", "call.?stack.?spoof"},
		Detection: []string{"Hunt markers of Call-stack spoof flag", "Map to T1055", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1055"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-INDIRECT", Name: "Indirect syscalls flag", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0005", Technique: "T1106", Severity: "high",
		Summary:   "Use indirect syscalls.",
		Detail:    "Use indirect syscalls. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Indirect syscalls flag", "# MITRE T1106"},
		Markers:   []string{"indirect.?syscall", "halo.?gate", "hell.?gate"},
		Detection: []string{"Hunt markers of Indirect syscalls flag", "Map to T1106", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1106"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-ETW", Name: "ETW bypass flag", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0005", Technique: "T1562.006", Severity: "high",
		Summary:   "Patch/disable ETW on start.",
		Detail:    "Patch/disable ETW on start. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# ETW bypass flag", "# MITRE T1562.006"},
		Markers:   []string{"etw.?bypass", "disable.?etw", "patch.?etw"},
		Detection: []string{"Hunt markers of ETW bypass flag", "Map to T1562.006", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1562.006"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-AMSI", Name: "AMSI bypass flag", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0005", Technique: "T1562.001", Severity: "high",
		Summary:   "AMSI bypass on start.",
		Detail:    "AMSI bypass on start. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# AMSI bypass flag", "# MITRE T1562.001"},
		Markers:   []string{"amsi.?bypass", "disable.?amsi", "patch.?amsi"},
		Detection: []string{"Hunt markers of AMSI bypass flag", "Map to T1562.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1562.001"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-SLEEP-ENCRYPT", Name: "Sleep obfuscation / encrypt", Category: "ImplantConfig", Platform: "windows",
		Tactic: "TA0005", Technique: "T1027", Severity: "medium",
		Summary:   "Encrypt implant memory during sleep.",
		Detail:    "Encrypt implant memory during sleep. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Sleep obfuscation / encrypt", "# MITRE T1027"},
		Markers:   []string{"sleep.?encrypt", "sleep.?obf", "ekko|foliage|zilean"},
		Detection: []string{"Hunt markers of Sleep obfuscation / encrypt", "Map to T1027", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1027"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-MODULE", Name: "Loaded module list", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0005", Technique: "T1129", Severity: "low",
		Summary:   "Configured post-ex modules.",
		Detail:    "Configured post-ex modules. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Loaded module list", "# MITRE T1129"},
		Markers:   []string{"modules?\\s*=", "postex.?module"},
		Detection: []string{"Hunt markers of Loaded module list", "Map to T1129", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1129"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-OPERATOR", Name: "Operator / campaign tag", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071", Severity: "info",
		Summary:   "Campaign or operator identifier.",
		Detail:    "Campaign or operator identifier. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Operator / campaign tag", "# MITRE T1071"},
		Markers:   []string{"operator\\s*=", "campaign\\s*=", "project\\s*="},
		Detection: []string{"Hunt markers of Operator / campaign tag", "Map to T1071", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071"},
		Tags:      []string{"implant", "config"},
	},
	{
		ID: "IMP-VERSION", Name: "Implant version string", Category: "ImplantConfig", Platform: "cross",
		Tactic: "TA0011", Technique: "T1071", Severity: "info",
		Summary:   "Version marker for IOC clustering.",
		Detail:    "Version marker for IOC clustering. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Implant version string", "# MITRE T1071"},
		Markers:   []string{"implant.?version\\s*=", "agent.?version\\s*="},
		Detection: []string{"Hunt markers of Implant version string", "Map to T1071", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1071"},
		Tags:      []string{"implant", "config"},
	},
}

// catalogByID returns the entry with the given id, or ok=false.
func catalogByID(id string) (CatalogEntry, bool) {
	for _, e := range catalog {
		if strings.EqualFold(e.ID, id) {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// categories returns the sorted distinct category set in the catalog.
func categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range catalog {
		if e.Category != "" && !seen[e.Category] {
			seen[e.Category] = true
			out = append(out, e.Category)
		}
	}
	sort.Strings(out)
	return out
}

// platforms returns the sorted distinct platform set in the catalog.
func platforms() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range catalog {
		if e.Platform != "" && !seen[e.Platform] {
			seen[e.Platform] = true
			out = append(out, e.Platform)
		}
	}
	sort.Strings(out)
	return out
}

// tactics returns the sorted distinct MITRE tactic set.
func tactics() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range catalog {
		if e.Tactic != "" && !seen[e.Tactic] {
			seen[e.Tactic] = true
			out = append(out, e.Tactic)
		}
	}
	sort.Strings(out)
	return out
}

// searchCatalog matches a free-text query against most text fields.
func searchCatalog(q string) []CatalogEntry {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	terms := strings.Fields(q)
	var out []CatalogEntry
	for _, e := range catalog {
		hay := strings.ToLower(strings.Join([]string{e.ID, e.Name, e.Category, e.Platform, e.Tactic, e.Technique, e.Summary, e.Detail, strings.Join(e.Commands, " "), strings.Join(e.Tags, " ")}, " "))
		all := true
		for _, t := range terms {
			if !strings.Contains(hay, t) {
				all = false
				break
			}
		}
		if all {
			out = append(out, e)
		}
	}
	return out
}

// filterByCategory returns catalog entries in a category (case-insensitive).
func filterByCategory(cat string) []CatalogEntry {
	var out []CatalogEntry
	for _, e := range catalog {
		if strings.EqualFold(e.Category, cat) {
			out = append(out, e)
		}
	}
	return out
}

// filterByPlatform returns catalog entries for a platform.
func filterByPlatform(p string) []CatalogEntry {
	var out []CatalogEntry
	for _, e := range catalog {
		if strings.EqualFold(e.Platform, p) || strings.EqualFold(e.Platform, "any") || strings.EqualFold(e.Platform, "cross") {
			out = append(out, e)
		}
	}
	return out
}

// severityCounts tallies findings by severity.
func severityCounts(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[strings.ToLower(f.Severity)]++
	}
	return m
}

// ====================================================================
//  GRADING ENGINE
// ====================================================================

// gradeFor converts an accumulated risk score into an A+..F grade.
func gradeFor(score int) string {
	switch {
	case score <= 0:
		return "A+"
	case score < 10:
		return "A"
	case score < 25:
		return "B"
	case score < 50:
		return "C"
	case score < 90:
		return "D"
	case score < 150:
		return "E"
	default:
		return "F"
	}
}

// scoreFindings sums weighted severities into a single risk score.
func scoreFindings(fs []Finding) int {
	total := 0
	for _, f := range fs {
		w := sevWeight[strings.ToLower(f.Severity)]
		if w == 0 {
			w = 3
		}
		total += w
	}
	return total
}

// gradeExplain returns a short human explanation of a grade.
func gradeExplain(g string) string {
	switch g {
	case "A+":
		return "No material exposure observed in this analysis."
	case "A":
		return "Minimal exposure; only low-impact items present."
	case "B":
		return "Minor exposure; review flagged items at leisure."
	case "C":
		return "Moderate exposure; remediation recommended."
	case "D":
		return "Significant exposure; prioritise remediation."
	case "E":
		return "Severe exposure; urgent remediation required."
	default:
		return "Critical exposure; treat as actively exploitable."
	}
}

// ====================================================================
//  MARKER SCANNER
// ====================================================================

// compiledMarker pairs a catalog entry with a compiled regex marker.
type compiledMarker struct {
	entry CatalogEntry
	re    *regexp.Regexp
	raw   string
}

// buildMarkers compiles every marker in the catalog once. Markers that
// fail to compile as regex are matched as literal substrings instead.
func buildMarkers() []compiledMarker {
	var out []compiledMarker
	for _, e := range catalog {
		for _, m := range e.Markers {
			re, err := regexp.Compile("(?i)" + m)
			if err != nil {
				re = nil
			}
			out = append(out, compiledMarker{entry: e, re: re, raw: m})
		}
	}
	return out
}

// scanReader reads a stream line by line and matches catalog markers,
// producing one finding per (entry, line) hit. Deduplicated per entry/line.
func scanReader(name string, r io.Reader) []Finding {
	markers := buildMarkers()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	var findings []Finding
	seen := map[string]bool{}
	lineNo := 0
	for sc.Scan() {
		lineNo++
		text := sc.Text()
		low := strings.ToLower(text)
		for _, cm := range markers {
			hit := false
			if cm.re != nil {
				hit = cm.re.MatchString(text)
			} else {
				hit = strings.Contains(low, strings.ToLower(cm.raw))
			}
			if !hit {
				continue
			}
			key := cm.entry.ID + "#" + strconv.Itoa(lineNo)
			if seen[key] {
				continue
			}
			seen[key] = true
			ev := strings.TrimSpace(text)
			if len(ev) > 200 {
				ev = ev[:200] + "…"
			}
			findings = append(findings, Finding{
				RuleID:    cm.entry.ID,
				Title:     cm.entry.Name,
				Severity:  cm.entry.Severity,
				Score:     sevWeight[strings.ToLower(cm.entry.Severity)],
				Tactic:    cm.entry.Tactic,
				Technique: cm.entry.Technique,
				File:      name,
				Line:      lineNo,
				Evidence:  ev,
				Detail:    cm.entry.Summary,
				Detection: strings.Join(cm.entry.Detection, "; "),
				Refs:      cm.entry.Refs,
				Fprint:    fingerprint(cm.entry.ID, name, strconv.Itoa(lineNo)),
			})
		}
	}
	sortFindings(findings)
	return findings
}

// scanFile opens a file and scans it.
func scanFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return scanReader(filepath.Base(path), f), nil
}

// sortFindings orders findings by severity (desc) then file/line.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := sevRank[strings.ToLower(fs[i].Severity)], sevRank[strings.ToLower(fs[j].Severity)]
		if ri != rj {
			return ri > rj
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

// ====================================================================
//  SHANNON ENTROPY (used by several analyzers)
// ====================================================================

// shannonEntropy returns bits/byte entropy of a buffer (0..8).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// entropyGrade labels an entropy value.
func entropyGrade(h float64) string {
	switch {
	case h >= 7.5:
		return "very-high (packed/encrypted)"
	case h >= 6.5:
		return "high (compressed/encoded)"
	case h >= 5.0:
		return "moderate"
	case h >= 3.0:
		return "low"
	default:
		return "very-low (plain/structured)"
	}
}

// ====================================================================
//  COMMON DECODERS (deobfuscation helpers reused by tools)
// ====================================================================

// tryBase64 decodes a base64 token if it looks like one.
func tryBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 8 || len(s)%4 != 0 {
		// try standard anyway with padding tolerance
	}
	for _, dec := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := dec.DecodeString(s); err == nil && len(b) > 0 && isMostlyPrintable(b) {
			return string(b), true
		}
	}
	return "", false
}

// tryBase64UTF16 decodes PowerShell -EncodedCommand (UTF-16LE base64).
func tryBase64UTF16(s string) (string, bool) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) < 2 {
		return "", false
	}
	// strip UTF-16LE: take every other byte
	var out []byte
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] == 0 {
			out = append(out, b[i])
		}
	}
	if len(out) > 0 && isMostlyPrintable(out) {
		return string(out), true
	}
	return "", false
}

// isMostlyPrintable reports whether a buffer is mostly printable ASCII.
func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.85
}

// hexDecodeStr decodes a hex string if valid.
func hexDecodeStr(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s) == 0 || len(s)%2 != 0 {
		return "", false
	}
	b, err := hex.DecodeString(s)
	if err != nil || !isMostlyPrintable(b) {
		return "", false
	}
	return string(b), true
}

// rot13 applies the classic ROT13 substitution.
func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

// xorBytes XORs a buffer with a repeating key (lab decode helper).
func xorBytes(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// ====================================================================
//  REPORT BUILD + GRADING
// ====================================================================

func buildReport(mode, target string, fs []Finding) Report {
	sortFindings(fs)
	score := scoreFindings(fs)
	g := gradeFor(score)
	sc := severityCounts(fs)
	summary := fmt.Sprintf("%d finding(s): %d critical, %d high, %d medium, %d low, %d info.",
		len(fs), sc["critical"], sc["high"], sc["medium"], sc["low"], sc["info"])
	return Report{
		Tool:       APPNAME,
		Version:    VERSION,
		Tagline:    TAGLINE,
		Generated:  time.Now().Format(time.RFC3339),
		Target:     target,
		Mode:       mode,
		Findings:   fs,
		Grade:      g,
		Score:      score,
		Summary:    summary,
		MitrePrime: PRIMARY_MITRE,
	}
}

// ====================================================================
//  EXPORT ENGINE  (txt / md / json / csv / sarif)
// ====================================================================

func exportTXT(r Report) string {
	var b strings.Builder
	b.WriteString("OWL " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString("Version " + r.Version + "   Generated " + r.Generated + "\n")
	b.WriteString("Author khaled.s.haddad   owlsec.org\n")
	b.WriteString(strings.Repeat("=", 72) + "\n")
	if r.Target != "" {
		b.WriteString("Target : " + r.Target + "\n")
	}
	b.WriteString("Mode   : " + r.Mode + "\n")
	b.WriteString("Primary MITRE : " + r.MitrePrime + "\n")
	b.WriteString("Grade  : " + r.Grade + " (score " + strconv.Itoa(r.Score) + ") — " + gradeExplain(r.Grade) + "\n")
	b.WriteString("Summary: " + r.Summary + "\n")
	b.WriteString(strings.Repeat("-", 72) + "\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%d] %s  (%s)\n", i+1, f.Title, strings.ToUpper(f.Severity)))
		b.WriteString("    Rule      : " + f.RuleID + "\n")
		b.WriteString("    MITRE     : " + f.Technique + "  " + f.Tactic + "\n")
		if f.File != "" {
			b.WriteString(fmt.Sprintf("    Location  : %s:%d\n", f.File, f.Line))
		}
		if f.Evidence != "" {
			b.WriteString("    Evidence  : " + f.Evidence + "\n")
		}
		if f.Detail != "" {
			b.WriteString("    Detail    : " + f.Detail + "\n")
		}
		if f.Detection != "" {
			b.WriteString("    Detection : " + f.Detection + "\n")
		}
		if len(f.Refs) > 0 {
			b.WriteString("    Refs      : " + strings.Join(f.Refs, ", ") + "\n")
		}
		b.WriteString("    Fingerprint: " + f.Fprint + "\n\n")
	}
	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
	}
	return b.String()
}

func exportMD(r Report) string {
	var b strings.Builder
	b.WriteString("# OWL " + r.Tool + "\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString("| Version | " + r.Version + " |\n")
	b.WriteString("| Generated | " + r.Generated + " |\n")
	if r.Target != "" {
		b.WriteString("| Target | " + r.Target + " |\n")
	}
	b.WriteString("| Mode | " + r.Mode + " |\n")
	b.WriteString("| Primary MITRE | " + r.MitrePrime + " |\n")
	b.WriteString("| Grade | **" + r.Grade + "** (score " + strconv.Itoa(r.Score) + ") |\n")
	b.WriteString("| Summary | " + r.Summary + " |\n\n")
	b.WriteString("## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("_No findings._\n")
		return b.String()
	}
	b.WriteString("| # | Severity | Title | MITRE | Location | Evidence |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for i, f := range r.Findings {
		loc := ""
		if f.File != "" {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		ev := strings.ReplaceAll(f.Evidence, "|", "\\|")
		if len(ev) > 60 {
			ev = ev[:60] + "…"
		}
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %s |\n", i+1, strings.ToUpper(f.Severity), f.Title, f.Technique, loc, ev))
	}
	b.WriteString("\n### Detail\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("#### %d. %s (%s)\n\n", i+1, f.Title, strings.ToUpper(f.Severity)))
		b.WriteString("- Rule: `" + f.RuleID + "`\n")
		b.WriteString("- MITRE: " + f.Technique + " / " + f.Tactic + "\n")
		if f.Detail != "" {
			b.WriteString("- Detail: " + f.Detail + "\n")
		}
		if f.Detection != "" {
			b.WriteString("- Detection: " + f.Detection + "\n")
		}
		if len(f.Refs) > 0 {
			b.WriteString("- Refs: " + strings.Join(f.Refs, ", ") + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportJSON(r Report) string {
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func exportCSV(r Report) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"index", "severity", "score", "ruleId", "title", "tactic", "technique", "file", "line", "evidence", "detection", "fingerprint"})
	for i, f := range r.Findings {
		w.Write([]string{
			strconv.Itoa(i + 1), f.Severity, strconv.Itoa(f.Score), f.RuleID, f.Title,
			f.Tactic, f.Technique, f.File, strconv.Itoa(f.Line), f.Evidence, f.Detection, f.Fprint,
		})
	}
	w.Flush()
	return buf.String()
}

// SARIF 2.1.0 structures (minimal, valid)
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  sarifText         `json:"fullDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   sarifText         `json:"message"`
	Locations []sarifLocation   `json:"locations,omitempty"`
	Fprints   map[string]string `json:"fingerprints,omitempty"`
	Props     map[string]string `json:"properties,omitempty"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func exportSARIF(r Report) string {
	ruleSet := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := ruleSet[f.RuleID]; !ok {
			ruleSet[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Detail},
				HelpURI:          "https://owlsec.org/" + strings.ToLower(APPNAME),
				Properties:       map[string]string{"tactic": f.Tactic, "technique": f.Technique, "severity": f.Severity},
			}
		}
		res := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title + ": " + f.Detail},
			Fprints: map[string]string{"owl/v1": f.Fprint},
			Props:   map[string]string{"severity": f.Severity, "technique": f.Technique},
		}
		if f.File != "" {
			reg := &sarifRegion{StartLine: f.Line}
			if f.Line <= 0 {
				reg = nil
			}
			res.Locations = []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File}, Region: reg}}}
		}
		results = append(results, res)
	}
	var rules []sarifRule
	for _, v := range ruleSet {
		rules = append(rules, v)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "OWL-" + APPNAME,
				Version:        VERSION,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	buf, _ := json.MarshalIndent(log, "", "  ")
	return string(buf)
}

// renderReport selects a format.
func renderReport(r Report, format string) string {
	switch strings.ToLower(format) {
	case "md", "markdown":
		return exportMD(r)
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

// writeOut writes rendered output to a file or stdout.
func writeOut(content, path string) error {
	if path == "" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// ====================================================================
//  HOW TO USE SCREEN  (mandatory — menu item + --howto flag)
// ====================================================================

type HowtoSection struct {
	Title string
	Lines []string
}

var howtoSections = []HowtoSection{
	{Title: "LEGAL & ETHICAL WARNING", Lines: []string{
		"OImplant is for AUTHORIZED security testing, detection engineering and education ONLY.",
		"Use it exclusively on systems, files and logs you own or are explicitly permitted",
		"in writing to assess. Unauthorized use of the techniques catalogued here may be a crime.",
		"This tool is an OFFLINE analyzer / planner / catalog: it does NOT launch live attacks",
		"against third-party systems. You are solely responsible for staying in scope.",
	}},
	{Title: "HOW TO USE", Lines: []string{
		"1. Browse the catalog for techniques, markers, detection and MITRE mapping.",
		"2. Collect authorized offline inputs (configs, logs, captures, dumps).",
		"3. Run: OImplant --scan input.txt --format sarif --output out.sarif",
		"4. Use 'Parse implant config' for the tool-specific analyzer.",
		"5. Use 'MITRE technique index' to pivot by technique.",
		"6. Export findings as txt|md|json|csv|sarif; generate Sigma via --sigma.",
	}},
	{Title: "MENU OPTIONS", Lines: []string{
		"[1]  Catalog browser   — list/search/filter and view full entry cards.",
		"[2]  Scan input file   — regex marker scan into graded findings.",
		"[3]  Run planner       — tool-specific planner / graph / builder.",
		"[4]  Catalog statistics — severity/category/platform breakdown.",
		"[5]  Export            — dump catalog/last report in any of 5 formats.",
		"[6]  Run demo          — synthetic self-contained demonstration.",
		"[7]  ATT&CK coverage matrix — tactic/technique coverage view.",
		"[8]  Detection rules (Sigma) — generate Sigma-style rules.",
		"[9]  Parse implant config — decode a benign config into fields + IOCs.",
		"[10] MITRE technique index — pivot by technique ID.",
		"[H]  Help & Usage      — this screen.",
		"[0]  Exit.  CLI mirrors: --howto, --demo, --scan, --search, --plan, --sigma.",
	}},
	{Title: "REQUIREMENTS", Lines: []string{
		"- Offline analyzer/planner; Go stdlib only; no live attacks.",
		"- Authorized testing only; written permission required.",
		"- Inputs are text configs, logs, or synthetic lab samples.",
	}},
	{Title: "v1.1 CLI WORKFLOW", Lines: []string{
		"--score FILE   rate how detectable a sample config is (0..100 + grade),",
		"               a hunting/triage aid — louder configs score higher.",
		"--yara         export YARA-like text-detection rules from the marker",
		"               catalog, for sweeping sample artifacts on disk.",
		"--diff OLD.json  compare a scanned config to a previous report (+new/-gone).",
	}},
	{Title: "FEATURE / PROTOCOL NOTES", Lines: []string{
		"Parses implant-style key=value configs and promotes sensitive keys to findings.",
		"Decodes base64 'config' blobs and re-scans them.",
		"Benign/simulated configs only — no live implant generation against third parties.",
	}},
}

// showHowto renders the HOW TO USE screen.
func showHowto() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  HOW TO USE — "+APPNAME, CY+B))
	line(64)
	for _, s := range howtoSections {
		fmt.Println()
		fmt.Println("  " + col("▸ "+s.Title, CY+B))
		for _, ln := range s.Lines {
			if ln == "" {
				fmt.Println()
				continue
			}
			fmt.Println("    " + col(ln, W))
		}
	}
	line(64)
	fmt.Println("  " + col("Primary MITRE mapping: ", DIM) + col(PRIMARY_MITRE, CY))
	fmt.Println("  " + col("Authorized testing only — see LEGAL & ETHICAL WARNING above.", GY))
}

// howtoText returns the HOW TO USE content as plain text (for --howto).
func howtoText() string {
	var b strings.Builder
	b.WriteString("OWL " + APPNAME + " — HOW TO USE\n")
	b.WriteString(TAGLINE + "\n")
	b.WriteString(strings.Repeat("=", 72) + "\n")
	for _, s := range howtoSections {
		b.WriteString("\n## " + s.Title + "\n")
		for _, ln := range s.Lines {
			b.WriteString("  " + ln + "\n")
		}
	}
	b.WriteString("\nPrimary MITRE mapping: " + PRIMARY_MITRE + "\n")
	return b.String()
}

// ====================================================================
//  CATALOG BROWSER (shared interactive + CLI views)
// ====================================================================

// printCatalogTable prints a compact table of entries.
func printCatalogTable(entries []CatalogEntry) {
	if len(entries) == 0 {
		warnMsg("No catalog entries match.")
		return
	}
	rows := [][]string{}
	for _, e := range entries {
		rows = append(rows, []string{e.ID, trunc(e.Name, 34), e.Platform, strings.ToUpper(e.Severity), e.Technique})
	}
	table([]string{"ID", "NAME", "PLATFORM", "SEV", "MITRE"}, rows)
	fmt.Println()
	info(fmt.Sprintf("%d entr%s.", len(entries), plural(len(entries))))
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// showEntry prints a full catalog entry card.
func showEntry(e CatalogEntry) {
	fmt.Println()
	fmt.Println("  " + col("╭─ "+e.ID+" — "+e.Name, CY+B))
	fmt.Println("  " + col("│ Category : ", DR) + col(e.Category, W))
	fmt.Println("  " + col("│ Platform : ", DR) + col(e.Platform, W))
	fmt.Println("  " + col("│ Severity : ", DR) + col(strings.ToUpper(e.Severity), sevColor(e.Severity)))
	fmt.Println("  " + col("│ Tactic   : ", DR) + col(e.Tactic, W))
	fmt.Println("  " + col("│ Technique: ", DR) + col(e.Technique, W))
	fmt.Println("  " + col("╰─", DR))
	fmt.Println("  " + col("Summary: ", CY+B) + col(e.Summary, W))
	if e.Detail != "" {
		fmt.Println()
		for _, ln := range wrap(e.Detail, 78) {
			fmt.Println("    " + col(ln, GY))
		}
	}
	if len(e.Commands) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Example / reference commands:", CY+B))
		for _, c := range e.Commands {
			fmt.Println("    " + col("$ ", DR) + col(c, W))
		}
	}
	if len(e.Markers) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Scan markers (regex):", CY+B))
		for _, m := range e.Markers {
			fmt.Println("    " + col(m, YLW))
		}
	}
	if len(e.Detection) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Detection guidance:", CY+B))
		for _, d := range e.Detection {
			fmt.Println("    " + col("• "+d, W))
		}
	}
	if len(e.Refs) > 0 {
		fmt.Println()
		fmt.Println("  " + col("References: ", DIM) + col(strings.Join(e.Refs, "  "), GY))
	}
}

// wrap wraps text to a width.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	var cur string
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// ====================================================================
//  GENERIC PLANNER (catalog -> prioritized action plan)
// ====================================================================

// genericPlan ranks catalog entries into a prioritized, MITRE-tagged plan.
func genericPlan() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  PRIORITIZED PLAN (catalog-ranked)", CY+B))
	line(64)
	entries := append([]CatalogEntry{}, catalog...)
	sort.SliceStable(entries, func(i, j int) bool {
		return sevRank[strings.ToLower(entries[i].Severity)] > sevRank[strings.ToLower(entries[j].Severity)]
	})
	rows := [][]string{}
	for i, e := range entries {
		if i >= 25 {
			break
		}
		rows = append(rows, []string{strconv.Itoa(i + 1), e.ID, trunc(e.Name, 30), strings.ToUpper(e.Severity), e.Technique})
	}
	table([]string{"#", "ID", "STEP", "SEV", "MITRE"}, rows)
}

// genericDemo runs a synthetic self-contained scan over an embedded sample.
func genericDemo() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  DEMO — synthetic self-contained run", CY+B))
	line(64)
	sample := demoSample()
	fs := scanReader("demo-sample.txt", strings.NewReader(sample))
	rep := buildReport("demo", "demo-sample.txt", fs)
	printFindings(rep)
}

// printFindings prints a report's findings + grade to the TUI.
func printFindings(rep Report) {
	if len(rep.Findings) == 0 {
		okMsg("No findings in this run.")
	} else {
		rows := [][]string{}
		for i, f := range rep.Findings {
			rows = append(rows, []string{strconv.Itoa(i + 1), strings.ToUpper(f.Severity), trunc(f.Title, 32), f.Technique, fmt.Sprintf("%s:%d", f.File, f.Line)})
		}
		table([]string{"#", "SEV", "FINDING", "MITRE", "LOC"}, rows)
	}
	fmt.Println()
	gradeLineOut(rep)
}

func gradeLineOut(rep Report) {
	fmt.Println("  " + col("Grade : ", CY+B) + col(rep.Grade, sevColorForGrade(rep.Grade)+B) + col("  score "+strconv.Itoa(rep.Score), GY))
	fmt.Println("  " + col(gradeExplain(rep.Grade), GY))
	fmt.Println("  " + col(rep.Summary, W))
}

func sevColorForGrade(g string) string {
	switch g {
	case "A+", "A":
		return GRN
	case "B", "C":
		return YLW
	default:
		return R
	}
}

// ====================================================================
//  IOC EXTRACTOR + TIMELINE + FINDING MERGE UTILITIES
// ====================================================================

// extractIOCs pulls IPv4, URLs, emails, and Windows paths from text.
func extractIOCs(text string) (ips, urls, emails, paths []string) {
	ipRe := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	urlRe := regexp.MustCompile(`https?://[^\s"'<>]{4,}`)
	emRe := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	pathRe := regexp.MustCompile(`(?i)(?:[A-Za-z]:\\|\\\\|/var/|/tmp/|/etc/|/home/|/usr/)[^\s"'<>]{2,}`)
	seen := map[string]bool{}
	add := func(list *[]string, v string) {
		if seen[v] {
			return
		}
		seen[v] = true
		*list = append(*list, v)
	}
	for _, m := range ipRe.FindAllString(text, 50) {
		add(&ips, m)
	}
	for _, m := range urlRe.FindAllString(text, 50) {
		add(&urls, trunc(m, 160))
	}
	for _, m := range emRe.FindAllString(text, 50) {
		add(&emails, m)
	}
	for _, m := range pathRe.FindAllString(text, 50) {
		add(&paths, trunc(m, 120))
	}
	return
}

// iocsToFindings converts extracted IOCs into Finding records.
func iocsToFindings(src string, ips, urls, emails, paths []string) []Finding {
	var fs []Finding
	for _, v := range ips {
		fs = append(fs, Finding{RuleID: "IOC-IP", Title: "IPv4 address", Severity: "info",
			Score: 1, Tactic: "Discovery", Technique: "T1016", File: src, Evidence: v,
			Detail: "Extracted IPv4 indicator.", Fprint: fingerprint("ip", v)})
	}
	for _, v := range urls {
		fs = append(fs, Finding{RuleID: "IOC-URL", Title: "URL", Severity: "info",
			Score: 1, Tactic: "Command and Control", Technique: "T1071", File: src, Evidence: v,
			Detail: "Extracted URL indicator.", Fprint: fingerprint("url", v)})
	}
	for _, v := range emails {
		fs = append(fs, Finding{RuleID: "IOC-EMAIL", Title: "Email address", Severity: "info",
			Score: 1, Tactic: "Initial Access", Technique: "T1566", File: src, Evidence: v,
			Detail: "Extracted email indicator.", Fprint: fingerprint("em", v)})
	}
	for _, v := range paths {
		fs = append(fs, Finding{RuleID: "IOC-PATH", Title: "Filesystem path", Severity: "info",
			Score: 1, Tactic: "Discovery", Technique: "T1083", File: src, Evidence: v,
			Detail: "Extracted path indicator.", Fprint: fingerprint("path", v)})
	}
	return fs
}

// mergeFindings concatenates and de-duplicates findings by fingerprint.
func mergeFindings(sets ...[]Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, set := range sets {
		for _, f := range set {
			key := f.Fprint
			if key == "" {
				key = fingerprint(f.RuleID, f.Title, f.Evidence, strconv.Itoa(f.Line))
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out
}

// timelineEvent is a simple ordered event for planner/report timelines.
type timelineEvent struct {
	TS     string
	Phase  string
	Title  string
	Detail string
}

// buildTimeline renders a phase-ordered timeline from findings' tactics.
func buildTimeline(fs []Finding) []timelineEvent {
	phaseOf := map[string]string{
		"Initial Access": "1-Initial", "Execution": "2-Execution",
		"Persistence": "3-Persist", "Privilege Escalation": "4-PrivEsc",
		"Defense Evasion": "5-Evasion", "Credential Access": "6-Creds",
		"Discovery": "7-Discover", "Lateral Movement": "8-Lateral",
		"Collection": "9-Collect", "Command and Control": "A-C2",
		"Exfiltration": "B-Exfil", "Impact": "C-Impact",
	}
	var evs []timelineEvent
	for i, f := range fs {
		phase := phaseOf[f.Tactic]
		if phase == "" {
			phase = "Z-Other"
		}
		evs = append(evs, timelineEvent{
			TS: fmt.Sprintf("T+%03d", i+1), Phase: phase,
			Title: f.Title, Detail: trunc(f.Detail, 80),
		})
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Phase < evs[j].Phase })
	return evs
}

// printTimeline displays a timeline table in the TUI.
func printTimeline(evs []timelineEvent) {
	if len(evs) == 0 {
		warnMsg("No timeline events.")
		return
	}
	rows := [][]string{}
	for _, e := range evs {
		rows = append(rows, []string{e.TS, e.Phase, trunc(e.Title, 36), trunc(e.Detail, 40)})
	}
	table([]string{"TS", "PHASE", "EVENT", "DETAIL"}, rows)
}

// findingSummaryLine returns a one-line summary of a findings slice.
func findingSummaryLine(fs []Finding) string {
	sc := severityCounts(fs)
	return fmt.Sprintf("%d findings (crit=%d high=%d med=%d low=%d info=%d) grade=%s",
		len(fs), sc["critical"], sc["high"], sc["medium"], sc["low"], sc["info"],
		gradeFor(scoreFindings(fs)))
}

// writeFindingsBundle exports a report in all 5 formats under a directory prefix.
func writeFindingsBundle(rep Report, prefix string) error {
	formats := []string{"txt", "md", "json", "csv", "sarif"}
	for _, f := range formats {
		path := prefix + "." + f
		if f == "sarif" {
			path = prefix + ".sarif.json"
		}
		if err := os.WriteFile(path, []byte(renderReport(rep, f)), 0644); err != nil {
			return err
		}
		okMsg("Wrote " + path)
	}
	return nil
}

// countMarkers returns total compiled markers across the catalog.
func countMarkers() int {
	n := 0
	for _, e := range catalog {
		n += len(e.Markers)
	}
	return n
}

// topSeverity returns the highest severity present in a findings slice.
func topSeverity(fs []Finding) string {
	top := "info"
	for _, f := range fs {
		if sevRank[strings.ToLower(f.Severity)] > sevRank[top] {
			top = strings.ToLower(f.Severity)
		}
	}
	return top
}

// filterFindingsBySev returns findings at or above a minimum severity.
func filterFindingsBySev(fs []Finding, min string) []Finding {
	minR := sevRank[strings.ToLower(min)]
	var out []Finding
	for _, f := range fs {
		if sevRank[strings.ToLower(f.Severity)] >= minR {
			out = append(out, f)
		}
	}
	return out
}

// groupFindingsByTechnique groups findings by MITRE technique ID.
func groupFindingsByTechnique(fs []Finding) map[string][]Finding {
	m := map[string][]Finding{}
	for _, f := range fs {
		k := f.Technique
		if k == "" {
			k = "(none)"
		}
		m[k] = append(m[k], f)
	}
	return m
}

// ====================================================================
//  ATT&CK COVERAGE MATRIX
// ====================================================================

// attackCoverage prints a tactic x technique coverage matrix derived from
// the catalog, useful for detection-engineering gap analysis.
func attackCoverage() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  ATT&CK COVERAGE MATRIX", CY+B))
	line(64)
	byTactic := map[string][]string{}
	techSeverity := map[string]string{}
	for _, e := range catalog {
		tac := e.Tactic
		if tac == "" {
			tac = "(unmapped)"
		}
		byTactic[tac] = append(byTactic[tac], e.Technique)
		if sevRank[strings.ToLower(e.Severity)] > sevRank[strings.ToLower(techSeverity[e.Technique])] {
			techSeverity[e.Technique] = e.Severity
		}
	}
	var tacs []string
	for k := range byTactic {
		tacs = append(tacs, k)
	}
	sort.Strings(tacs)
	rows := [][]string{}
	for _, tac := range tacs {
		uniq := uniqueSorted(byTactic[tac])
		rows = append(rows, []string{trunc(tac, 34), strconv.Itoa(len(byTactic[tac])), strconv.Itoa(len(uniq)), trunc(strings.Join(uniq, ","), 40)})
	}
	table([]string{"TACTIC", "ENTRIES", "TECHNIQUES", "IDS"}, rows)
	fmt.Println()
	info(fmt.Sprintf("%d distinct techniques across %d tactics.", len(techSeverity), len(tacs)))
}

// uniqueSorted returns a deduplicated, sorted copy of a string slice.
func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// attackCoverageText returns the coverage matrix as plain text (CLI).
func attackCoverageText() string {
	byTactic := map[string]int{}
	byTech := map[string]bool{}
	for _, e := range catalog {
		tac := e.Tactic
		if tac == "" {
			tac = "(unmapped)"
		}
		byTactic[tac]++
		byTech[e.Technique] = true
	}
	var b strings.Builder
	b.WriteString(APPNAME + " ATT&CK coverage: " + strconv.Itoa(len(byTech)) + " techniques\n")
	var tacs []string
	for k := range byTactic {
		tacs = append(tacs, k)
	}
	sort.Strings(tacs)
	for _, tac := range tacs {
		b.WriteString(fmt.Sprintf("  %-40s %d\n", tac, byTactic[tac]))
	}
	return b.String()
}

// ====================================================================
//  SIGMA-STYLE DETECTION RULE GENERATOR
// ====================================================================

// yamlEscape quotes a string for a simple inline YAML scalar.
func yamlEscape(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, ":#{}[],&*?|<>=!%@") || strings.Contains(s, "\\") || strings.Contains(s, "\"") || strings.Contains(s, "'") {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return s
}

// generateSigma turns catalog entries into Sigma-like detection rules.
// The output is a best-effort Sigma skeleton for blue-team use; markers
// become CommandLine regex conditions. It is a generator, not a validator.
func generateSigma() string {
	var b strings.Builder
	for _, e := range catalog {
		if len(e.Markers) == 0 {
			continue
		}
		b.WriteString("title: " + yamlEscape(APPNAME+" - "+e.Name) + "\n")
		b.WriteString("id: " + fingerprint("sigma", APPNAME, e.ID) + "\n")
		b.WriteString("status: experimental\n")
		b.WriteString("description: " + yamlEscape(e.Summary) + "\n")
		b.WriteString("references:\n")
		for _, r := range e.Refs {
			b.WriteString("  - " + yamlEscape(r) + "\n")
		}
		b.WriteString("author: khaled.s.haddad (owlsec.org)\n")
		b.WriteString("tags:\n")
		b.WriteString("  - attack." + strings.ToLower(strings.ReplaceAll(firstToken(e.Tactic), " ", "_")) + "\n")
		if e.Technique != "" {
			b.WriteString("  - attack." + strings.ToLower(strings.ReplaceAll(e.Technique, ".", "_")) + "\n")
		}
		b.WriteString("logsource:\n")
		b.WriteString("  category: process_creation\n")
		b.WriteString("  product: " + yamlEscape(e.Platform) + "\n")
		b.WriteString("detection:\n")
		b.WriteString("  selection:\n")
		b.WriteString("    CommandLine|re:\n")
		for _, m := range e.Markers {
			b.WriteString("      - " + yamlEscape(m) + "\n")
		}
		b.WriteString("  condition: selection\n")
		b.WriteString("level: " + sigmaLevel(e.Severity) + "\n")
		b.WriteString("---\n")
	}
	return b.String()
}

// firstToken returns the first whitespace/slash-delimited token.
func firstToken(s string) string {
	s = strings.TrimSpace(s)
	for i, r := range s {
		if r == ' ' || r == '/' {
			return s[:i]
		}
	}
	if s == "" {
		return "execution"
	}
	return s
}

func sigmaLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "informational"
	}
}

// menuSigma shows generated Sigma rules and offers to export them.
func menuSigma() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  DETECTION RULES (SIGMA-STYLE)", CY+B))
	line(64)
	rules := generateSigma()
	count := strings.Count(rules, "---\n")
	info(fmt.Sprintf("Generated %d Sigma-style rule(s) from the catalog markers.", count))
	preview := rules
	if len(preview) > 1400 {
		preview = preview[:1400] + "\n... (truncated preview) ..."
	}
	fmt.Println(col(preview, GY))
	fmt.Println()
	if out := prompt("export to file? (path or blank)"); out != "" {
		if err := os.WriteFile(out, []byte(rules), 0644); err != nil {
			errMsg(err.Error())
		} else {
			okMsg("Wrote Sigma rules to " + out)
		}
	}
	pause()
}

// ====================================================================
//  TOOL-SPECIFIC EXTRA ENGINE
// ====================================================================

// parseKeyValueLines parses "key=value" / "key: value" style config lines.
func parseKeyValueLines(text string) map[string]string {
	out := map[string]string{}
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "//") || strings.HasPrefix(ln, ";") {
			continue
		}
		sep := "="
		if i := strings.Index(ln, ":"); i > 0 && (strings.Index(ln, "=") < 0 || i < strings.Index(ln, "=")) {
			sep = ":"
		}
		parts := strings.SplitN(ln, sep, 2)
		if len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}

// scoreConfigMap grades a set of config key=value pairs against expected hardening.
type configRule struct {
	Key      string
	BadVals  []string
	GoodVals []string
	Sev      string
	Title    string
	Tech     string
	Detail   string
}

func auditConfigMap(src string, cfg map[string]string, rules []configRule) []Finding {
	var fs []Finding
	for _, r := range rules {
		v, ok := cfg[r.Key]
		if !ok {
			continue
		}
		low := strings.ToLower(v)
		bad := false
		for _, b := range r.BadVals {
			if strings.Contains(low, strings.ToLower(b)) {
				bad = true
				break
			}
		}
		if !bad && len(r.GoodVals) > 0 {
			good := false
			for _, g := range r.GoodVals {
				if strings.EqualFold(v, g) {
					good = true
					break
				}
			}
			if !good {
				bad = true
			}
		}
		if !bad {
			continue
		}
		fs = append(fs, Finding{
			RuleID: "CFG-" + r.Key, Title: r.Title, Severity: r.Sev,
			Score: sevWeight[strings.ToLower(r.Sev)], Tactic: "Defense Evasion",
			Technique: r.Tech, File: src, Evidence: r.Key + "=" + v,
			Detail: r.Detail, Fprint: fingerprint(r.Key, v),
		})
	}
	return fs
}

// parseImplantConfig extracts implant config keys and emits IOC findings.
func parseImplantConfig(path string) (Report, error) {
	fs, err := scanFile(path)
	if err != nil {
		return Report{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	cfg := parseKeyValueLines(string(b))
	// Promote interesting keys to findings
	interesting := map[string]string{
		"psk": "critical", "shared_key": "critical", "aes_key": "critical",
		"callback_hosts": "high", "c2_hosts": "high", "stager_url": "high",
		"amsi_bypass": "high", "etw_bypass": "high", "killdate": "medium",
		"persist": "high", "persistence": "high", "protocol": "medium",
	}
	for k, v := range cfg {
		sev := interesting[strings.ToLower(k)]
		if sev == "" {
			continue
		}
		fs = append(fs, Finding{RuleID: "IMP-KEY-" + k, Title: "Implant config key: " + k,
			Severity: sev, Score: sevWeight[sev], Tactic: "Command and Control", Technique: "T1071",
			File: filepath.Base(path), Evidence: k + "=" + trunc(v, 80),
			Detail: "Sensitive implant configuration value.", Fprint: fingerprint(k, v)})
	}
	// Decode base64 config if present
	if v, ok := cfg["config"]; ok {
		if d, ok2 := tryBase64(v); ok2 {
			fs = append(fs, scanReader(filepath.Base(path)+"#config-b64", strings.NewReader(d))...)
		}
	}
	return buildReport("implant-config", path, fs), nil
}
func menuScanSpecial() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  PARSE IMPLANT CONFIG", CY+B))
	line(64)
	p := prompt("path to implant config / decoded strings")
	if p == "" {
		warnMsg("No path.")
		pause()
		return
	}
	rep, err := parseImplantConfig(p)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	printFindings(rep)
	if f := prompt("export format (blank=skip)"); f != "" {
		out := prompt("output file (blank=stdout)")
		writeOut(renderReport(rep, f), out)
		okMsg("Exported.")
	}
	pause()
}

func menuShowMitre() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  MITRE TECHNIQUE INDEX", CY+B))
	line(64)
	by := map[string][]CatalogEntry{}
	for _, e := range catalog {
		by[e.Technique] = append(by[e.Technique], e)
	}
	var keys []string
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := [][]string{}
	for _, k := range keys {
		rows = append(rows, []string{k, strconv.Itoa(len(by[k])), trunc(by[k][0].Name, 40), by[k][0].Severity})
	}
	table([]string{"TECHNIQUE", "N", "EXAMPLE", "SEV"}, rows)
	pause()
}
func init() {
	planReportFn = func() Report {
		entries := append([]CatalogEntry{}, catalog...)
		sort.SliceStable(entries, func(i, j int) bool {
			return sevRank[strings.ToLower(entries[i].Severity)] > sevRank[strings.ToLower(entries[j].Severity)]
		})
		return buildReport("plan", "catalog", entriesToFindings(entries))
	}
}

// ====================================================================
//  DEMO SAMPLE + PLAN REPORT (hooks; tools may override planReportFn)
// ====================================================================

func demoSample() string {
	return "# synthetic OImplant sample (authorized lab)\nsleep = 60000\njitter = 20\nkilldate = 2027-06-01\nprotocol = https\ncallback_hosts = 198.51.100.10,c2.lab.example\npsk = 5f4dcc3b5aa765d61d8327deb882cf99\namsi_bypass = true\netw_bypass = true\npersist = runkey\nspawnto = C:\\\\Windows\\\\System32\\\\rundll32.exe\nstager_url = https://198.51.100.10/stage\nuser_agent = Mozilla/5.0 (Windows NT 10.0)\nmutex = Global\\\\MsUpdateSvc\nconfig = c2xlZXA9MzAwMDA=\n"
}

// planReportFn lets a tool supply a custom planner report for CLI --plan.
var planReportFn = defaultPlanReport

// planReport returns the planner report for the CLI --plan path.
func planReport() Report { return planReportFn() }

// defaultPlanReport ranks the catalog by severity into a plan report.
func defaultPlanReport() Report {
	entries := append([]CatalogEntry{}, catalog...)
	sort.SliceStable(entries, func(i, j int) bool {
		return sevRank[strings.ToLower(entries[i].Severity)] > sevRank[strings.ToLower(entries[j].Severity)]
	})
	return buildReport("plan", "catalog", entriesToFindings(entries))
}

// ====================================================================
//  DEMO SAMPLE + runDemo/runPlan dispatch
// ====================================================================

func runDemo() {
	genericDemo()
}

func runPlan() {
	genericPlan()
}

// ====================================================================
//  INTERACTIVE TUI
// ====================================================================

func interactiveBrowse() {
	for {
		sel := menu("CATALOG BROWSER", []string{"List all", "Search", "By category", "By platform", "Show entry by ID", "Back"})
		switch sel {
		case "1":
			clear()
			banner()
			printCatalogTable(catalog)
			pause()
		case "2":
			q := prompt("query")
			clear()
			banner()
			printCatalogTable(searchCatalog(q))
			pause()
		case "3":
			cats := categories()
			fmt.Println()
			for i, c := range cats {
				fmt.Printf("   %s %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(c, W))
			}
			idx := prompt("category #")
			if n, err := strconv.Atoi(idx); err == nil && n >= 1 && n <= len(cats) {
				clear()
				banner()
				printCatalogTable(filterByCategory(cats[n-1]))
				pause()
			}
		case "4":
			ps := platforms()
			fmt.Println()
			for i, p := range ps {
				fmt.Printf("   %s %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(p, W))
			}
			idx := prompt("platform #")
			if n, err := strconv.Atoi(idx); err == nil && n >= 1 && n <= len(ps) {
				clear()
				banner()
				printCatalogTable(filterByPlatform(ps[n-1]))
				pause()
			}
		case "5":
			id := prompt("entry ID")
			if e, ok := catalogByID(id); ok {
				clear()
				banner()
				showEntry(e)
			} else {
				errMsg("No entry with ID " + id)
			}
			pause()
		case "6", "0", "00", "":
			return
		}
	}
}

func interactiveScan() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  SCAN INPUT FOR CATALOG MARKERS", CY+B))
	line(64)
	p := prompt("path to file")
	if p == "" {
		warnMsg("No path given.")
		pause()
		return
	}
	fs, err := scanFile(p)
	if err != nil {
		errMsg("Open failed: " + err.Error())
		pause()
		return
	}
	rep := buildReport("scan", p, fs)
	fmt.Println()
	printFindings(rep)
	fmt.Println()
	if yn := prompt("export? (format or blank)"); yn != "" {
		out := prompt("output file (blank=stdout)")
		writeOut(renderReport(rep, yn), out)
		okMsg("Exported.")
	}
	pause()
}

func interactiveStats() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  CATALOG STATISTICS", CY+B))
	line(64)
	bySev := map[string]int{}
	byCat := map[string]int{}
	byPlat := map[string]int{}
	markerCount := 0
	for _, e := range catalog {
		bySev[strings.ToLower(e.Severity)]++
		byCat[e.Category]++
		byPlat[e.Platform]++
		markerCount += len(e.Markers)
	}
	info(fmt.Sprintf("Catalog entries : %d", len(catalog)))
	info(fmt.Sprintf("Scan markers    : %d", markerCount))
	info(fmt.Sprintf("Categories      : %d", len(byCat)))
	info(fmt.Sprintf("Platforms       : %d", len(byPlat)))
	fmt.Println()
	fmt.Println("  " + col("By severity:", CY+B))
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if bySev[s] > 0 {
			bar := strings.Repeat("█", bySev[s])
			fmt.Printf("    %-9s %s %d\n", s, col(bar, sevColor(s)), bySev[s])
		}
	}
	fmt.Println()
	fmt.Println("  " + col("By category:", CY+B))
	var cs []string
	for c := range byCat {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	for _, c := range cs {
		fmt.Printf("    %-28s %d\n", c, byCat[c])
	}
}

func interactiveExport() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  EXPORT CATALOG / LAST REPORT", CY+B))
	line(64)
	rep := buildReport("catalog-dump", "catalog", catalogAsFindings())
	f := prompt("format txt|md|json|csv|sarif")
	if f == "" {
		f = "txt"
	}
	out := prompt("output file (blank=stdout)")
	if err := writeOut(renderReport(rep, f), out); err != nil {
		errMsg(err.Error())
	} else {
		okMsg("Export complete.")
	}
	pause()
}

// catalogAsFindings turns the catalog into findings for a reference dump.
func catalogAsFindings() []Finding {
	var fs []Finding
	for _, e := range catalog {
		fs = append(fs, Finding{
			RuleID:    e.ID,
			Title:     e.Name,
			Severity:  e.Severity,
			Score:     sevWeight[strings.ToLower(e.Severity)],
			Tactic:    e.Tactic,
			Technique: e.Technique,
			Detail:    e.Summary,
			Detection: strings.Join(e.Detection, "; "),
			Refs:      e.Refs,
			Fprint:    fingerprint(e.ID),
		})
	}
	return fs
}

func mainMenu() {
	for {
		items := []string{"Catalog browser", "Scan input file", "Run planner", "Catalog statistics", "Export", "Run demo", "ATT&CK coverage matrix", "Detection rules (Sigma)"}
		items = append(items, []string{"Parse implant config", "MITRE technique index"}...)
		sel := menu("MAIN MENU — "+APPNAME, items)
		switch strings.ToLower(sel) {
		case "1":
			interactiveBrowse()
		case "2":
			interactiveScan()
		case "3":
			runPlan()
			pause()
		case "4":
			interactiveStats()
			pause()
		case "5":
			interactiveExport()
		case "6":
			runDemo()
			pause()
		case "7":
			attackCoverage()
			pause()
		case "8":
			menuSigma()
		case "9":
			menuScanSpecial()
		case "10":
			menuShowMitre()
		case "h", "help", "?":
			showHowto()
			pause()
		case "0", "00", "q", "exit", "":
			clear()
			okMsg("Goodbye. Stay authorized.")
			return
		}
	}
}

// ====================================================================
//  CLI
// ====================================================================

func usage() {
	banner()
	fmt.Println("  " + col("USAGE", CY+B) + col("  "+APPNAME+" [flags]", W))
	fmt.Println()
	fmt.Println("  Run with no flags for the interactive TUI.")
	fmt.Println()
	fmt.Println("  " + col("FLAGS", CY+B))
	flags := [][]string{
		{"-h, --help", "Show this help"},
		{"--version", "Print version and exit"},
		{"--howto", "Print the HOW TO USE screen (legal, steps, navigation)"},
		{"--demo", "Run a synthetic, self-contained demonstration"},
		{"--list", "List the full technique/binary catalog"},
		{"--search Q", "Search the catalog for Q"},
		{"--category C", "Filter catalog by category"},
		{"--platform P", "Filter catalog by platform"},
		{"--id ID", "Show a single catalog entry by ID"},
		{"--scan FILE", "Scan FILE for catalog markers -> findings"},
		{"--input FILE", "Alias for --scan"},
		{"--plan", "Run the tool's planner / graph / builder"},
		{"--sigma", "Generate Sigma-style detection rules from the catalog"},
		{"--coverage", "Print an ATT&CK tactic coverage matrix"},
		{"--stats", "Print catalog statistics"},
		{"--format F", "Output format: txt|md|json|csv|sarif (default txt)"},
		{"--output FILE", "Write output to FILE instead of stdout"},
		{"--score FILE", "Rate a sample config's detectability (hunting aid)"},
		{"--yara", "Export detection (YARA-like) rules from the marker catalog"},
		{"--diff OLD.json", "Diff a scanned config against a previous JSON report"},
		{"--no-color", "Disable ANSI colors"},
	}
	for _, f := range flags {
		fmt.Printf("    %s  %s\n", col(pad(f[0], 16), W), col(f[1], GY))
	}
	fmt.Println()
	fmt.Println("  " + col("EXAMPLES", CY+B))
	fmt.Println("    " + col(APPNAME+" --scan sample.conf --format sarif --output out.sarif", GY))
	fmt.Println("    " + col(APPNAME+" --score sample.conf        # detectability grade", GY))
	fmt.Println("    " + col(APPNAME+" --yara --output rules.yar  # hunting rules", GY))
	fmt.Println("    " + col(APPNAME+" --scan sample.conf --diff last.json", GY))
	fmt.Println()
	fmt.Println("  " + col("Primary MITRE: ", DIM) + col(PRIMARY_MITRE, CY) + col("   Authorized testing only.", GY))
}

func main() {
	var (
		fHelp    = flag.Bool("help", false, "")
		fH       = flag.Bool("h", false, "")
		fVersion = flag.Bool("version", false, "")
		fHowto   = flag.Bool("howto", false, "")
		fDemo    = flag.Bool("demo", false, "")
		fList    = flag.Bool("list", false, "")
		fStats   = flag.Bool("stats", false, "")
		fPlan    = flag.Bool("plan", false, "")
		fSigma   = flag.Bool("sigma", false, "")
		fCover   = flag.Bool("coverage", false, "")
		fSearch  = flag.String("search", "", "")
		fCat     = flag.String("category", "", "")
		fPlat    = flag.String("platform", "", "")
		fID      = flag.String("id", "", "")
		fScan    = flag.String("scan", "", "")
		fInput   = flag.String("input", "", "")
		fFormat  = flag.String("format", "txt", "")
		fOutput  = flag.String("output", "", "")
		fNoColor = flag.Bool("no-color", false, "")
		fSelf    = flag.Bool("selftest", false, "")
		fScore   = flag.String("score", "", "")
		fYara    = flag.Bool("yara", false, "")
		fDiff    = flag.String("diff", "", "")
	)
	flag.Usage = usage
	flag.Parse()

	if *fNoColor {
		noColor = true
	}

	switch {
	case *fHelp || *fH:
		usage()
		return
	case *fVersion:
		fmt.Printf("%s %s — %s\n", APPNAME, VERSION, TAGLINE)
		fmt.Println("Author khaled.s.haddad | owlsec.org | Primary MITRE " + PRIMARY_MITRE)
		return
	case *fHowto:
		if noColor {
			fmt.Print(howtoText())
		} else {
			showHowto()
			fmt.Println()
		}
		return
	case *fDemo:
		runDemo()
		fmt.Println()
		return
	case *fSelf:
		os.Exit(runSelfTest())
	}

	scanTarget := *fScan
	if scanTarget == "" {
		scanTarget = *fInput
	}

	// CLI data operations that honor --format/--output
	if *fList {
		rep := buildReport("catalog", "catalog", catalogAsFindings())
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fStats {
		printCatalogStatsText()
		return
	}
	if *fSearch != "" {
		entries := searchCatalog(*fSearch)
		rep := buildReport("search:"+*fSearch, "catalog", entriesToFindings(entries))
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fCat != "" {
		entries := filterByCategory(*fCat)
		rep := buildReport("category:"+*fCat, "catalog", entriesToFindings(entries))
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fPlat != "" {
		entries := filterByPlatform(*fPlat)
		rep := buildReport("platform:"+*fPlat, "catalog", entriesToFindings(entries))
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fID != "" {
		if e, ok := catalogByID(*fID); ok {
			rep := buildReport("entry:"+*fID, "catalog", entriesToFindings([]CatalogEntry{e}))
			writeOut(renderReport(rep, *fFormat), *fOutput)
		} else {
			fmt.Fprintln(os.Stderr, "no entry with ID "+*fID)
			os.Exit(1)
		}
		return
	}
	if *fYara {
		writeOut(generateYara(), *fOutput)
		return
	}
	if *fScore != "" {
		b, err := os.ReadFile(*fScore)
		if err != nil {
			fmt.Fprintln(os.Stderr, "score error: "+err.Error())
			os.Exit(2)
		}
		sc, grade, notes := profileScore(parseKeyValueLines(string(b)))
		fmt.Printf("detectability score: %d/100  grade %s\n", sc, grade)
		for _, n := range notes {
			fmt.Println("  - " + n)
		}
		return
	}
	if scanTarget != "" {
		fs, err := scanFile(scanTarget)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan error: "+err.Error())
			os.Exit(1)
		}
		if *fDiff != "" {
			old, err := loadReport(*fDiff)
			if err != nil {
				fmt.Fprintln(os.Stderr, "diff error: "+err.Error())
				os.Exit(2)
			}
			added, resolved := diffFindings(old.Findings, fs)
			fmt.Printf("# config diff vs %s\n", *fDiff)
			for _, f := range added {
				fmt.Printf("+ [%s] %s (%s)\n", strings.ToUpper(f.Severity), f.Title, f.Technique)
			}
			for _, f := range resolved {
				fmt.Printf("- [%s] %s (%s)\n", strings.ToUpper(f.Severity), f.Title, f.Technique)
			}
			fmt.Printf("# %d new, %d resolved\n", len(added), len(resolved))
			if len(added) > 0 {
				os.Exit(1)
			}
			return
		}
		rep := buildReport("scan", scanTarget, fs)
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fSigma {
		writeOut(generateSigma(), *fOutput)
		return
	}
	if *fCover {
		writeOut(attackCoverageText(), *fOutput)
		return
	}
	if *fPlan {
		rep := planReport()
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}

	// No flags -> interactive UI
	if noColor && !isatty() {
		// Non-interactive without flags: print help so piping is useful.
		usage()
		return
	}
	mainMenu()
}

// entriesToFindings converts catalog entries into findings for export.
func entriesToFindings(entries []CatalogEntry) []Finding {
	var fs []Finding
	for _, e := range entries {
		fs = append(fs, Finding{
			RuleID: e.ID, Title: e.Name, Severity: e.Severity,
			Score: sevWeight[strings.ToLower(e.Severity)], Tactic: e.Tactic,
			Technique: e.Technique, Detail: e.Summary,
			Detection: strings.Join(e.Detection, "; "), Refs: e.Refs,
			Fprint: fingerprint(e.ID),
		})
	}
	return fs
}

// printCatalogStatsText prints catalog stats as plain text (CLI).
func printCatalogStatsText() {
	bySev := map[string]int{}
	byCat := map[string]int{}
	markers := 0
	for _, e := range catalog {
		bySev[strings.ToLower(e.Severity)]++
		byCat[e.Category]++
		markers += len(e.Markers)
	}
	fmt.Printf("%s catalog: %d entries, %d markers, %d categories\n", APPNAME, len(catalog), markers, len(byCat))
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if bySev[s] > 0 {
			fmt.Printf("  %-9s %d\n", s, bySev[s])
		}
	}
	var cs []string
	for c := range byCat {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	for _, c := range cs {
		fmt.Printf("  [cat] %-28s %d\n", c, byCat[c])
	}
}

// ====================================================================
//  SELF-TEST — verifies the catalog, scanner, search and exporters.
// ====================================================================

func runSelfTest() int {
	banner()
	fmt.Println("  " + col("⬡  Self-Test — "+APPNAME+" engine", B+CY))
	rule()
	fmt.Println()
	pass, fail := 0, 0
	check := func(name string, cond bool) {
		if cond {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col(name, W))
		}
	}

	check("catalog is non-empty", len(catalog) > 0)
	idset := map[string]bool{}
	fieldsOK, dup := true, false
	for _, e := range catalog {
		if e.ID == "" || e.Name == "" || e.Category == "" || e.Technique == "" {
			fieldsOK = false
		}
		if idset[e.ID] {
			dup = true
		}
		idset[e.ID] = true
	}
	check("every entry has ID/Name/Category/Technique", fieldsOK)
	check("catalog IDs are unique", !dup)

	check("fingerprint is deterministic", fingerprint("a", "b") == fingerprint("a", "b"))
	check("fingerprint differs on input", fingerprint("a", "b") != fingerprint("a", "c"))
	check("fingerprint is 16 hex chars", len(fingerprint("x")) == 16)

	check("sevWeight ordered crit>high>med>low>info",
		sevWeight["critical"] > sevWeight["high"] &&
			sevWeight["high"] > sevWeight["medium"] &&
			sevWeight["medium"] > sevWeight["low"] &&
			sevWeight["low"] > sevWeight["info"])

	check("searchCatalog(\"\") = nil", searchCatalog("") == nil)
	check("searchCatalog(\"sleep\") finds entries", len(searchCatalog("sleep")) > 0)
	check("searchCatalog(\"zzzznomatch\") = empty", len(searchCatalog("zzzznomatch")) == 0)
	check("filterByCategory(ImplantConfig) non-empty", len(filterByCategory("ImplantConfig")) > 0)

	// scanner: feed a synthetic implant config carrying known markers.
	sample := "sleep = 60\njitter_percent = 25\nkilldate=2025-12-31\nuser_agent: Mozilla/5.0\nnothing here\n"
	fs := scanReader("beacon.conf", strings.NewReader(sample))
	check("scanReader detects config markers", len(fs) >= 2)
	gotSleep, gotKill := false, false
	for _, f := range fs {
		if strings.Contains(f.RuleID, "SLEEP") {
			gotSleep = true
		}
		if strings.Contains(f.RuleID, "KILLDATE") {
			gotKill = true
		}
	}
	check("scanner flags the sleep interval", gotSleep)
	check("scanner flags the kill date", gotKill)

	rep := buildReport("selftest", "beacon.conf", fs)
	for _, fmtName := range []string{"txt", "md", "json", "csv", "sarif"} {
		out := renderReport(rep, fmtName)
		check("renderReport("+fmtName+") produces output", len(strings.TrimSpace(out)) > 0)
	}
	var js interface{}
	check("JSON export is valid JSON", json.Unmarshal([]byte(renderReport(rep, "json")), &js) == nil)
	var sarif map[string]interface{}
	check("SARIF export is valid JSON", json.Unmarshal([]byte(renderReport(rep, "sarif")), &sarif) == nil)

	check("generateSigma produces rules", len(strings.TrimSpace(generateSigma())) > 0)
	check("attackCoverageText produces a matrix", len(strings.TrimSpace(attackCoverageText())) > 0)

	check("stripANSI removes colour", stripANSI(col("hi", CY)) == "hi")
	check("visw counts runes", visw("abc") == 3)

	// v1.1: profile scoring.
	loud := map[string]string{"sleep": "2", "protocol": "http"}
	quiet := map[string]string{"sleep": "600", "jitter": "40", "killdate": "2025-01-01", "working_hours": "9-17", "protocol": "https"}
	sLoud, gLoud, nLoud := profileScore(loud)
	sQuiet, _, _ := profileScore(quiet)
	check("profileScore rates a loud config higher", sLoud > sQuiet)
	check("profileScore gives a worse grade to loud config", gLoud == "F" || gLoud == "D")
	check("profileScore lists contributing factors", len(nLoud) > 0)
	check("atoiLoose parses '60s' → 60", func() bool { n, ok := atoiLoose("60s"); return ok && n == 60 }())

	// v1.1: config diff.
	a := []Finding{{Fprint: "x"}, {Fprint: "y"}}
	b := []Finding{{Fprint: "y"}, {Fprint: "z"}}
	add, res := diffFindings(a, b)
	check("diffFindings finds 1 new / 1 resolved", len(add) == 1 && len(res) == 1)

	// v1.1: YARA-like export.
	y := generateYara()
	check("generateYara emits rule blocks", strings.Contains(y, "rule ") && strings.Contains(y, "condition:"))

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d FAILED", pass, fail))
	return 1
}

// ====================================================================
//  v1.1 — profile scoring, config diff, detection-rule (YARA-like) export
// ====================================================================

func atoiLoose(s string) (int, bool) {
	s = strings.TrimSpace(s)
	d := ""
	for _, r := range s {
		if r >= '0' && r <= '9' {
			d += string(r)
		} else if d != "" {
			break
		}
	}
	if d == "" {
		return 0, false
	}
	n, _ := strconv.Atoi(d)
	return n, true
}

func cfgGet(cfg map[string]string, keys ...string) (string, bool) {
	for k, v := range cfg {
		for _, want := range keys {
			if strings.EqualFold(k, want) {
				return v, true
			}
		}
	}
	return "", false
}

// profileScore rates how DETECTABLE a sample config is for defenders/hunters.
// Higher = noisier on the wire and easier to catch. Pure heuristic over fields.
func profileScore(cfg map[string]string) (int, string, []string) {
	score := 0
	var notes []string
	if v, ok := cfgGet(cfg, "sleep", "beacon_interval", "callback_interval"); ok {
		if n, ok2 := atoiLoose(v); ok2 {
			switch {
			case n < 5:
				score += 40
				notes = append(notes, fmt.Sprintf("very short interval %ds — loud (+40)", n))
			case n < 60:
				score += 20
				notes = append(notes, fmt.Sprintf("short interval %ds (+20)", n))
			default:
				notes = append(notes, fmt.Sprintf("interval %ds — quieter", n))
			}
		}
	}
	if v, ok := cfgGet(cfg, "jitter", "jitter_percent"); ok {
		if n, ok2 := atoiLoose(v); ok2 && n < 20 {
			score += 20
			notes = append(notes, fmt.Sprintf("low jitter %d%% — regular pattern (+20)", n))
		} else {
			notes = append(notes, "jitter present — less regular")
		}
	} else {
		score += 15
		notes = append(notes, "no jitter — fixed cadence (+15)")
	}
	if _, ok := cfgGet(cfg, "killdate", "kill_date"); !ok {
		score += 10
		notes = append(notes, "no kill-date — long-lived (+10)")
	}
	if _, ok := cfgGet(cfg, "working_hours", "business_hours"); !ok {
		score += 10
		notes = append(notes, "no working-hours guard — active off-hours (+10)")
	}
	if v, ok := cfgGet(cfg, "protocol", "transport"); ok && !strings.Contains(strings.ToLower(v), "https") {
		score += 15
		notes = append(notes, "non-HTTPS transport — easier to inspect (+15)")
	}
	if score > 100 {
		score = 100
	}
	grade := "A"
	switch {
	case score >= 70:
		grade = "F"
	case score >= 50:
		grade = "D"
	case score >= 30:
		grade = "C"
	case score >= 15:
		grade = "B"
	}
	return score, grade, notes
}

// diffFindings compares two finding sets by fingerprint.
func diffFindings(oldF, newF []Finding) (added, resolved []Finding) {
	oldSet := map[string]bool{}
	for _, f := range oldF {
		oldSet[f.Fprint] = true
	}
	newSet := map[string]bool{}
	for _, f := range newF {
		newSet[f.Fprint] = true
		if !oldSet[f.Fprint] {
			added = append(added, f)
		}
	}
	for _, f := range oldF {
		if !newSet[f.Fprint] {
			resolved = append(resolved, f)
		}
	}
	return
}

func loadReport(path string) (Report, error) {
	var r Report
	raw, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(raw, &r)
	return r, err
}

// generateYara emits simple text-detection rules from the catalog markers,
// for defenders to hunt sample artifacts on disk.
func generateYara() string {
	var b strings.Builder
	b.WriteString("/* " + APPNAME + " " + VERSION + " — detection rules from marker catalog */\n\n")
	for _, e := range catalog {
		if len(e.Markers) == 0 {
			continue
		}
		rule := "rule " + strings.ReplaceAll(strings.ReplaceAll(e.ID, "-", "_"), " ", "_") + " {\n"
		rule += "  meta:\n"
		rule += "    description = " + strconv.Quote(e.Name) + "\n"
		rule += "    mitre = " + strconv.Quote(e.Technique) + "\n"
		rule += "    severity = " + strconv.Quote(e.Severity) + "\n"
		rule += "  strings:\n"
		for i, m := range e.Markers {
			rule += fmt.Sprintf("    $m%d = /%s/ nocase\n", i, m)
		}
		rule += "  condition:\n    any of them\n}\n\n"
		b.WriteString(rule)
	}
	return b.String()
}
