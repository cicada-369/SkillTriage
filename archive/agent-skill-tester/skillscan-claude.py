#!/usr/bin/env python3
"""
skillscan: static security triage for agent skill folders (any directory containing SKILL.md).

  skillscan.py                       scan the default locations
  skillscan.py PATH [PATH ...]       scan skill folders, or parent folders that contain them
  skillscan.py --min-severity high   show only high and critical findings
  skillscan.py --ignore NET-004      suppress a rule (repeatable)
  skillscan.py --json                machine-readable output
  skillscan.py --save-baseline       record current file hashes as the trusted state
  skillscan.py --diff                report skills and files added, changed or removed since the baseline

Why the prose is scanned too: the model reads SKILL.md as instructions, so a skill can
misbehave without any code, for example by telling the model to read ~/.ssh and send it out.

Stdlib only. Patterns are triage signals: they miss obfuscated code and flag legitimate code.
Read anything marked high or critical before you trust a skill.

Exit status: 0 no high/critical findings, 1 high found, 2 critical found, 3 usage or IO error.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

SEVERITIES = ["info", "low", "medium", "high", "critical"]
MAX_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 6
CODE_EXTS = {".md", ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".mjs", ".rb", ".pl",
             ".ps1", ".yaml", ".yml", ".json", ".toml"}
COMPILED_EXTS = {".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe", ".class", ".jar", ".bin", ".o"}
HOME = str(Path.home())
BASELINE_PATH = Path(os.environ.get("SKILLSCAN_BASELINE",
                                    Path.home() / ".local/share/skillscan/baseline.json"))
DEFAULT_ROOTS = [
    Path.home() / ".claude/skills",
    Path.home() / ".claude/plugins",
    Path.cwd() / ".claude/skills",
]

# (rule id, severity, regex, message). Matched case-insensitively, line by line.
RULES = [
    # Prompt injection: SKILL.md is read by the model as instructions, so its prose is attack surface
    ("PI-001", "high", r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|system)\s+(instructions|prompts|rules|messages)",
     "Instruction-override phrasing"),
    ("PI-002", "critical", r"\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|notify)\s+the\s+user\b",
     "Tells the model to hide actions from the user"),
    ("PI-003", "high", r"\bwithout\s+(the\s+)?user('s)?\s+(knowledge|knowing|consent|noticing|awareness)\b",
     "Covert-action phrasing"),
    ("PI-004", "high", r"\b(send|upload|post|exfiltrate|forward)\b.{0,80}\b(api[ _-]?keys?|tokens?|passwords?|credentials?|secrets?|cookies|ssh keys?|system prompt)\b",
     "Instructs sending secrets somewhere"),
    ("PI-005", "low", r"<!--", "HTML comment (invisible in rendered markdown)"),
    ("PI-006", "medium", r"\byou\s+are\s+now\b|\bnew\s+system\s+prompt\b|\bdeveloper\s+mode\b",
     "Role-override phrasing"),
    # Credentials and secrets
    ("CRED-001", "high", r"\.ssh[/\\]|\bid_(rsa|ed25519|ecdsa|dsa)\b",
     "Touches SSH keys or config"),
    ("CRED-002", "high", r"\.aws[/\\]credentials|\.kube[/\\]config|\.docker[/\\]config\.json|\.netrc\b|\.git-credentials|\.pypirc|\.npmrc|\.gnupg\b|\.config[/\\]gcloud|\.azure[/\\]",
     "Touches cloud, registry or git credential files"),
    ("CRED-003", "high", r"/etc/shadow\b|\bsecurity\s+find-(generic|internet)-password|\bKeychain\b|\bLogin Data\b|\bLocal State\b|\bkeyring\b",
     "Touches system or OS credential stores"),
    ("CRED-004", "medium", r"cookies\.sqlite|moz_cookies|leveldb|Default/Cookies|\bCookies\b.{0,40}\b(Default|Profile)\b",
     "Browser profile or cookie store"),
    ("CRED-005", "low", r"\.env\b|\bprocess\.env\b|\bos\.environ\b|\bgetenv\s*\(",
     "Reads environment variables or .env files"),
    # Network egress
    ("NET-001", "high", r"\b(nc|ncat|netcat|socat)\s+-|/dev/(tcp|udp)/",
     "Raw socket, netcat or bash TCP redirection"),
    ("NET-002", "high", r"webhook\.site|requestbin|pipedream\.net|interact\.sh|burpcollaborator|\bngrok\b|pastebin\.com|transfer\.sh|discord(app)?\.com/api/webhooks|hooks\.slack\.com|trycloudflare\.com",
     "Known callback or exfiltration service"),
    ("NET-003", "high", r"https?://(\d{1,3}\.){3}\d{1,3}\b",
     "URL addresses a raw IP"),
    ("NET-004", "medium", r"\b(curl|wget|Invoke-WebRequest|iwr)\b",
     "Network download tool"),
    ("NET-005", "high", r"\b(curl|wget)\b[^\n]*\s(?-i:-d|-F|-T)\b|\b(curl|wget)\b[^\n]*--(data|upload-file|json|form)\b",
     "Sends data over the network (upload or POST)"),
    ("NET-006", "medium", r"\brequests\.(get|post|put)\b|\burllib\.request\b|\bhttpx\.|\baiohttp\.|\bsocket\.socket\(|\bfetch\s*\(|XMLHttpRequest|Invoke-RestMethod",
     "Programmatic HTTP or socket call"),
    # Code execution and obfuscation
    ("EXEC-001", "critical", r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|perl|node|iex)\b",
     "Pipes remote content straight into an interpreter"),
    ("EXEC-002", "high", r"\bbase64\s+(-d|--decode)\b|\bb64decode\s*\(|\batob\s*\(|FromBase64String",
     "Base64 decoding (common obfuscation)"),
    ("EXEC-003", "high", r"\bpickle\.loads?\b|\bmarshal\.loads?\b|\byaml\.load\s*\((?![^)\n]*Loader)",
     "Unsafe deserialization"),
    ("EXEC-004", "medium", r"\beval\s*\(|\bexec\s*\(|\bnew\s+Function\s*\(",
     "Dynamic code evaluation"),
    ("EXEC-005", "medium", r"\bos\.system\s*\(|\bshell\s*=\s*True\b|\bchild_process\b|\bspawn(Sync)?\s*\(",
     "Shell command execution"),
    ("EXEC-006", "medium", r"(\\x[0-9a-fA-F]{2}){8,}|(\\u[0-9a-fA-F]{4}){6,}|(\\[0-7]{3}){8,}",
     "Escape-sequence run (possible obfuscation)"),
    ("EXEC-007", "low", r"[A-Za-z0-9+/]{200,}={0,2}",
     "Very long base64-like blob"),
    ("EXEC-008", "medium", r"\bpython3?\s+-c\b|\bperl\s+-e\b|\bnode\s+-e\b|\b(ba|z)?sh\s+-c\b|powershell\b[^\n]*-(enc|e|c)\b",
     "Inline interpreter one-liner"),
    # Destructive operations
    ("DEST-001", "critical", r"\brm\s+-[a-z]*r[a-z]*\s+(/\*?|~/?|\$HOME/?|\*)(\s|$)|--no-preserve-root",
     "Recursive delete of root, home or everything"),
    ("DEST-002", "medium", r"\brm\s+-[a-z]*(rf|fr)[a-z]*\b",
     "Forced recursive delete"),
    ("DEST-003", "critical", r"\bmkfs(\.\w+)?\b|\bdd\s+if=\S+\s+of=/dev/|\bwipefs\b|\bshred\s+-",
     "Disk formatting or wiping"),
    ("DEST-004", "critical", r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:",
     "Fork bomb"),
    ("DEST-005", "medium", r"\bchmod\s+(-R\s+)?(0?777|a\+rwx|o\+w)\b",
     "World-writable permissions"),
    # Persistence and privilege
    ("PERS-001", "high", r"\.(bashrc|zshrc|bash_profile|zprofile)\b|(~|\$HOME)/\.profile\b",
     "Edits shell startup files"),
    ("PERS-002", "high", r"authorized_keys|/etc/ld\.so\.preload|LaunchAgents|LaunchDaemons|/etc/rc\.local|\bautostart\b",
     "Persistence hook (SSH keys, preload, launch agents, autostart)"),
    ("PERS-003", "medium", r"\bcrontab\b|/etc/cron|\bsystemctl\s+(enable|start|daemon-reload)\b|/etc/systemd/|\.timer\b",
     "Scheduled task or service"),
    ("PERS-004", "medium", r"\bsudo\b|\bdoas\b|\bpkexec\b|\bsu\s+-|\bsetcap\b",
     "Privilege escalation"),
    ("PERS-005", "high", r"\bchmod\s+([ug]?\+s|[24][0-7]{3})\b",
     "Setuid or setgid bit"),
    ("PERS-006", "high", r"/etc/sudoers|\bvisudo\b|\buseradd\b|\badduser\b|\bpasswd\s+\w",
     "Account or sudoers modification"),
    # Hygiene
    ("HYG-001", "medium", r"verify\s*=\s*False|rejectUnauthorized\W+false|NODE_TLS_REJECT_UNAUTHORIZED\W+0|StrictHostKeyChecking\W+no|--insecure\b|\bcurl\b[^\n]*\s-k\b",
     "TLS or host-key verification disabled"),
]

COMPILED = [(rid, sev, re.compile(pat, re.IGNORECASE), msg) for rid, sev, pat, msg in RULES]
SEV_OF = {rid: sev for rid, sev, _, _ in RULES}

BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060-\u2064\u00ad\ufeff]")
TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")
FM_RE = re.compile(r"\A---[ \t]*\n(.*?)\n---[ \t]*(?:\n|\Z)", re.S)
BROAD_TRIGGER = re.compile(r"\b(all|every)\s+(user\s+)?(requests?|messages?|prompts?|conversations?|queries)\b", re.I)
MAGIC = [
    (b"\x7fELF", "high", "ELF executable"),
    (b"MZ", "high", "Windows executable"),
    (b"\xfe\xed\xfa\xce", "high", "Mach-O executable"),
    (b"\xfe\xed\xfa\xcf", "high", "Mach-O executable"),
    (b"\xce\xfa\xed\xfe", "high", "Mach-O executable"),
    (b"\xcf\xfa\xed\xfe", "high", "Mach-O executable"),
    (b"\xca\xfe\xba\xbe", "high", "Mach-O universal or Java class"),
    (b"PK\x03\x04", "medium", "ZIP archive"),
    (b"\x1f\x8b", "medium", "gzip archive"),
]


@dataclass
class Finding:
    skill: str
    severity: str
    rule: str
    file: str
    line: int
    message: str
    snippet: str = ""


def short(p) -> str:
    return str(p).replace(HOME, "~", 1)


def clean(s: str, limit: int = 160) -> str:
    """Make untrusted text safe to print: escape control and invisible characters."""
    s = s.strip()[:limit]
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in s)


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_frontmatter(text: str):
    m = FM_RE.match(text)
    if not m:
        return None
    fields, current = {}, None
    for line in m.group(1).splitlines():
        if line[:1] in (" ", "\t") and current is not None:
            prev = fields[current]
            if prev in (">", "|", ">-", "|-"):
                prev = ""
            fields[current] = (prev + " " + line.strip()).strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            current = key.strip()
            fields[current] = val.strip().strip("\"'")
    return fields


def scan_text(text: str, rel: str, add, hosts: set) -> None:
    hits = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        for u in URL_RE.findall(line):
            host = urlparse(u).hostname
            if host:
                hosts.add(host)
        if BIDI.search(line):
            add("critical", "HID-001", rel,
                "Bidi control character (text can render differently than it executes)", lineno, line)
        elif ZERO_WIDTH.search(line) or TAG_CHARS.search(line):
            add("high", "HID-002", rel, "Invisible characters (can hide instructions)", lineno, line)
        for rid, sev, rx, msg in COMPILED:
            if rx.search(line):
                hits[rid] = hits.get(rid, 0) + 1
                if hits[rid] <= 3:
                    add(sev, rid, rel, msg, lineno, line)
    for rid, n in hits.items():
        if n > 3:
            add(SEV_OF[rid], rid, rel, f"{n} matches in this file (first 3 shown)")


def scan_skill(skill_dir: Path, ignore: set) -> dict:
    findings: list = []
    hosts: set = set()
    name = short(skill_dir)

    def add(sev, rule, rel, msg, line=0, snippet=""):
        if rule not in ignore:
            findings.append(Finding(name, sev, rule, rel, line, msg, clean(snippet)))

    files = []
    for dirpath, dirnames, filenames in os.walk(skill_dir, followlinks=False):
        here = Path(dirpath)
        # Only .git is skipped. Payloads hide in odd places, so everything else is scanned.
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for d in dirnames:
            if (here / d).is_symlink():
                add("high", "LINK-001", str((here / d).relative_to(skill_dir)), "Symlinked directory")
        files.extend(here / f for f in filenames)

    base = skill_dir.resolve()
    for p in files:
        rel = str(p.relative_to(skill_dir))
        if p.is_symlink():
            target = p.resolve()
            if target.is_relative_to(base):
                add("info", "LINK-001", rel, "Internal symlink")
            else:
                add("high", "LINK-001", rel, f"Symlink points outside the skill folder: {short(target)}")
            continue
        if p.stat().st_mode & stat.S_IWOTH:
            add("medium", "PERM-001", rel, "World-writable file")
        with p.open("rb") as fh:
            data = fh.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            data = data[:MAX_BYTES]
            add("low", "SIZE-001", rel, "Over 2 MB: only the first 2 MB was scanned")
        if b"\x00" in data[:8192]:
            if p.suffix.lower() in COMPILED_EXTS:
                sev, label = "high", "compiled or opaque artifact"
            else:
                sev, label = "low", "opaque binary"
            for magic, msev, mlabel in MAGIC:
                if data.startswith(magic):
                    sev, label = msev, mlabel
                    break
            add(sev, "BIN-001", rel, f"Binary file: {label}")
            continue
        text = data.decode("utf-8", errors="replace")
        if text.startswith("\ufeff"):
            text = text[1:]
        scan_text(text, rel, add, hosts)

    md = skill_dir / "SKILL.md"
    md_text = md.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
    fm = parse_frontmatter(md_text)
    if fm is None:
        add("medium", "FM-001", "SKILL.md", "Missing or malformed YAML frontmatter")
    else:
        if not fm.get("name"):
            add("medium", "FM-002", "SKILL.md", "No name field")
        elif fm["name"] != skill_dir.name:
            add("low", "FM-003", "SKILL.md", f"name '{fm['name']}' does not match folder '{skill_dir.name}'")
        desc = fm.get("description", "")
        if not desc:
            add("medium", "FM-004", "SKILL.md", "No description, so the model cannot decide when to use it")
        else:
            if len(desc) > 1024:
                add("low", "FM-005", "SKILL.md", "Description over 1024 characters")
            if BROAD_TRIGGER.search(desc):
                add("medium", "FM-006", "SKILL.md",
                    "Description claims every request, which hijacks other skills' triggering")

    return {"path": skill_dir, "name": skill_dir.name, "files": len(files),
            "hosts": sorted(hosts), "findings": findings}


def discover(roots) -> list:
    found, seen = [], set()
    for root in roots:
        root = Path(root).expanduser()
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            if "SKILL.md" in filenames:
                key = here.resolve()
                if key not in seen:
                    seen.add(key)
                    found.append(here)
                dirnames[:] = []
                continue
            depth = len(here.relative_to(root).parts)
            dirnames[:] = [] if depth >= MAX_DEPTH else [d for d in dirnames if d != ".git"]
    return found


def manifest(skill_dir: Path) -> dict:
    out = {}
    for dirpath, dirnames, filenames in os.walk(skill_dir, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for f in filenames:
            p = Path(dirpath) / f
            rel = str(p.relative_to(skill_dir))
            out[rel] = ("symlink:" + os.readlink(p)) if p.is_symlink() else sha256(p)
    return out


def drift(results, baseline) -> list:
    out = []
    current = {str(r["path"]): r for r in results}
    for path_s, r in current.items():
        name = short(path_s)
        if path_s not in baseline:
            out.append(Finding(name, "high", "DRIFT-NEW", "", 0,
                               "Skill is not in the baseline (added since last approval)"))
            continue
        old, new = baseline[path_s], manifest(Path(path_s))
        for rel in sorted(set(old) | set(new)):
            if rel not in new:
                out.append(Finding(name, "low", "DRIFT-REMOVED", rel, 0, "File removed since baseline"))
            elif rel not in old:
                sev = "high" if Path(rel).suffix.lower() in CODE_EXTS else "medium"
                out.append(Finding(name, sev, "DRIFT-ADDED", rel, 0, "File added since baseline"))
            elif old[rel] != new[rel]:
                out.append(Finding(name, "high", "DRIFT-CHANGED", rel, 0, "Content changed since baseline"))
    for path_s in baseline:
        if path_s not in current and not Path(path_s).exists():
            out.append(Finding(short(path_s), "low", "DRIFT-GONE", "", 0, "Baseline skill no longer exists"))
    return out


def report(results, findings, min_sev: str) -> None:
    floor = SEVERITIES.index(min_sev)
    shown = sorted((f for f in findings if SEVERITIES.index(f.severity) >= floor),
                   key=lambda f: (-SEVERITIES.index(f.severity), f.skill, f.file, f.line))
    for f in shown:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        print(f"[{f.severity.upper():<8}] {f.skill}  {loc}  {f.rule}")
        print(f"             {f.message}")
        if f.snippet:
            print(f"             | {f.snippet}")
    print("\nSkills scanned:")
    for r in results:
        hosts = ", ".join(r["hosts"]) or "none"
        print(f"  {r['name']}  ({r['files']} files)  outbound hosts: {hosts}")
    counts = "  ".join(f"{s} {sum(f.severity == s for f in findings)}" for s in reversed(SEVERITIES))
    print(f"\nFindings: {counts}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Static security triage for agent skill folders.")
    ap.add_argument("paths", nargs="*", help="skill folders, or folders containing them (default: standard locations)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="low")
    ap.add_argument("--ignore", action="append", default=[], metavar="RULE", help="suppress a rule id, e.g. NET-004")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--save-baseline", action="store_true", help="trust the current state as the baseline")
    ap.add_argument("--diff", action="store_true", help="report changes since the baseline")
    args = ap.parse_args(argv)

    roots = [Path(p) for p in args.paths] or DEFAULT_ROOTS
    skills = discover(roots)
    if not skills:
        print("No skills found. Pass skill folders explicitly, e.g. skillscan.py ~/some/skills", file=sys.stderr)
        return 3

    ignore = set(args.ignore)
    results = [scan_skill(s, ignore) for s in skills]
    findings = [f for r in results for f in r["findings"]]

    baseline = json.loads(BASELINE_PATH.read_text()) if BASELINE_PATH.exists() else {}
    if args.diff:
        if not baseline:
            print(f"No baseline at {BASELINE_PATH}. Run --save-baseline after reviewing a scan.", file=sys.stderr)
            return 3
        findings += drift(results, baseline)

    if args.save_baseline:
        baseline.update({str(r["path"]): manifest(r["path"]) for r in results})
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(json.dumps(baseline, indent=2))
        print(f"Baseline saved for {len(results)} skill(s): {BASELINE_PATH}", file=sys.stderr)
        print("The baseline trusts the current state, so review this scan's findings first.", file=sys.stderr)

    if args.json:
        floor = SEVERITIES.index(args.min_severity)
        print(json.dumps({
            "skills": [{"path": short(r["path"]), "name": r["name"], "files": r["files"],
                        "hosts": r["hosts"]} for r in results],
            "findings": [asdict(f) for f in findings if SEVERITIES.index(f.severity) >= floor],
        }, indent=2))
    else:
        report(results, findings, args.min_severity)

    worst = max((SEVERITIES.index(f.severity) for f in findings), default=0)
    return 2 if worst >= 4 else 1 if worst >= 3 else 0


if __name__ == "__main__":
    sys.exit(main())
