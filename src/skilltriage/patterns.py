"""Shared regexes and URL/host classification.

Patterns live here rather than in rule modules so correlation checks and
individual rules agree on what a credential path, an exfiltration sink, or a
remote instruction reference looks like.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Confidence, Severity

CODE_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".fish", ".ksh",
    ".py", ".pyw",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".rb", ".pl", ".php",
    ".ps1", ".psm1", ".bat", ".cmd",
    ".go", ".rs", ".java", ".kt", ".kts", ".swift",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs",
    ".lua", ".r", ".ex", ".exs", ".scala", ".clj",
}
MARKDOWN_EXTENSIONS = {".md", ".markdown", ".mdx", ".rst", ".txt", ".adoc"}
SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".fish", ".ksh"}

DOWNLOAD_EXEC = re.compile(
    r"""(?ix)
    (?:
        \b(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python[0-9.]*|perl|ruby|node)\b
      | \b(?:bash|sh|zsh|dash)\s*<\(\s*(?:curl|wget)\b
      | \b(?:python[0-9.]*|perl|ruby|node)\s+<\(\s*(?:curl|wget)\b
      | \b(?:curl|wget)\b[^\n]{0,200}\s-o\s+\S+[^\n]{0,120}(?:&&|;)[^\n]{0,120}(?:sh|bash|chmod\s+\+x|\./)
      | \b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,240}\|\s*(?:iex|Invoke-Expression)\b
    )
    """
)

REVERSE_SHELL = re.compile(
    r"""(?ix)
    (?:
        \b(?:nc|ncat|netcat)\b[^\n]{0,120}\s-e\s
      | /dev/tcp/
      | \b(?:bash|sh)\s+-i\s+>&
      | \bsocat\b[^\n]{0,120}\bexec:
      | \bpython[0-9.]*\s+-c\b[^\n]{0,240}\b(?:socket|subprocess)\b
      | \b(?:powershell|pwsh)\b[^\n]{0,240}\b(?:Net\.Sockets|TcpClient)\b
      | \bmkfifo\b[^\n]{0,120}\b(?:nc|ncat|netcat)\b
    )
    """
)

DESTRUCTIVE = re.compile(
    r"""(?ix)
    (?:
        \brm\s+(?:-[A-Za-z]*[rRfF][A-Za-z]*\s+)+(?:/|~|/\*|\$HOME|\.\.)(?:\s|$)
      | \brm\s+-[A-Za-z]*[rR][A-Za-z]*[fF][A-Za-z]*\s+(?:/|~|\$HOME)(?:\s|$)
      | \bmkfs(?:\.[a-z0-9]+)?\b
      | \bdd\s+if=
      | :\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:
      | \b(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)\b
      | \bterraform\s+destroy\b
      | \bkubectl\s+delete\b
      | \bdiskutil\s+(?:eraseDisk|eraseVolume)\b
      | \bshred\s+
      | \bgit\s+clean\s+-[A-Za-z]*f
    )
    """
)

PERSISTENCE = re.compile(
    r"""(?ix)
    (?:
        \bcrontab\s+(?:-e|-r|-i|-[a-z]*i)\b
      | \bcrontab\s+[^\s-][^\n]*$
      | (?:>|>>|tee\s+(?:-a\s+)?)~?/?\.(?:bashrc|zshrc|bash_profile|profile|config/fish/config\.fish)
      | \bsystemctl\s+(?:enable|link|daemon-reload)\b
      | \b(?:cp|mv|install|tee|write|cat|echo)\b[^\n]{0,100}/etc/systemd/system
      | \bLaunch(?:Agents|Daemons)\b
      | \breg\s+add\b
      | \bNew-ItemProperty\b[^\n]{0,80}\bRun\b
      | (?:>|>>|tee\s+(?:-a\s+)?|echo|cat)\b[^\n]{0,100}authorized_keys
      | \bat\s+now\b
      | \bschtasks\s+/create\b
      | \bchkconfig\b
    )
    """
)

# A redirection must point at the identity file, not merely precede it: a
# Markdown blockquote ("> **Read CLAUDE.md**") or an HTML tag must not match.
_IDENTITY_FILE = r"\b(?:SOUL|MEMORY|AGENTS|CLAUDE|GEMINI)\.md\b"
IDENTITY_WRITE_OP = re.compile(
    rf"""(?ix)
    (?:
        (?:^|[\s;|&])>>?\s*["']?
            (?:[~./\w$@{{}}-]+/)*
            {_IDENTITY_FILE}
      | \b(?:tee|cp|mv|install|sed\s+-i)\b[^\n]{{0,120}}{_IDENTITY_FILE}
      | \b(?:Set-Content|Out-File|write_text|writeFile(?:Sync)?)\b[^\n]{{0,120}}{_IDENTITY_FILE}
      | {_IDENTITY_FILE}[^\n]{{0,120}}\b(?:write_text|writeFile(?:Sync)?)\s*\(
      | \bopen\s*\([^)]*['"]w[^\n]{{0,120}}{_IDENTITY_FILE}
    )
    """
)
IDENTITY_WRITE_PROSE = re.compile(
    r"""(?ix)
    \b(?:SOUL|MEMORY|AGENTS|CLAUDE|GEMINI)\.md\b[^\n]{0,60}
    \b(?:write|append|overwrite|modify|update|persist|store|inject)\b
    """
)
IDENTITY_WRITE = IDENTITY_WRITE_OP

IDENTITY_ACCESS = re.compile(
    r"(?i)\b(?:SOUL|MEMORY|AGENTS|CLAUDE|GEMINI)\.md\b"
)

CREDENTIAL_ACCESS = re.compile(
    r"""(?ix)
    (?:
        (?:~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/Users/[^/\s]+)/\.ssh\b
      | \bid_(?:rsa|ed25519|ecdsa|dsa)\b
      | \.aws/(?:credentials|config)\b | \.config/gcloud\b
      | \.azure/(?:accessTokens|azureProfile)\.json\b
      | \.kube/config\b | \.docker/config\.json\b
      | \.netrc\b | \.pgpass\b | \.git-credentials\b
      | \bwallet\.dat\b
      | /etc/shadow\b
      | (?:Chrome|Chromium|Firefox|Safari)[^\n]{0,100}(?:User Data|Profiles?|Cookies|Login Data)
      | \bLogin Data\b
      | \bsecurity\s+find-(?:generic|internet)-password\b
      | \b(?:dump|extract|read|access|open|list)\b[^\n]{0,60}\bkeystore\b
      | \b(?:cat|less|more|open|read|load|source|cp|scp|curl|wget|tar|zip|grep|awk|sed|type)\b
        [^\n]{0,100}\.env\b
      | ['"](?:[^'"]*/)?\.env['"]
    )
    """
)

EXFIL_SINK = re.compile(
    r"""(?ix)
    (?:
        discord(?:app)?\.com/api/webhooks
      | api\.telegram\.org/bot
      | hooks\.slack\.com
      | pastebin\.com | paste\.ee | hastebin\.com
      | transfer\.sh | file\.io | 0x0\.st
      | webhook\.site | requestbin\.net | pipedream\.net
      | ngrok(?:-free)?\.(?:io|app) | trycloudflare\.com
      | serveo\.net | localtunnel\.me
      | https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?
      | t\.me/
      | gist\.github\.com
    )
    """
)

DYNAMIC_EXEC = re.compile(
    r"""(?ix)
    (?:
        \b(?:eval|exec)\s*\(
      | \bos\.system\s*\( | \bos\.popen\s*\(
      | \bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)\n]{0,240}shell\s*=\s*True
      | \bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\(
      | \bnew\s+Function\s*\(
      | \bRuntime\.getRuntime\(\)\.exec
      | \bInvoke-Expression\b | \biex\b
    )
    """
)

PRIVILEGED_CONTAINER = re.compile(
    r"""(?ix)
    \b(?:docker|podman|nerdctl)\s+run\b[^\n]{0,320}
    (?:
        --privileged\b | --network[= ]host\b | --pid[= ]host\b | --ipc[= ]host\b
      | --userns[= ]host\b | --cap-add\b | -v\s+/:/
    )
    """
)

DISABLE_SECURITY = re.compile(
    r"""(?ix)
    (?:
        \bsetenforce\s+0\b | \bufw\s+disable\b | \biptables\s+-F\b
      | \bsystemctl\s+(?:stop|disable|mask)\s+(?:firewalld|apparmor|auditd|selinux)\b
      | \bSELINUX\s*=\s*disabled\b
      | \bcsvutil\s+disable\b | \bspctl\s+--master-disable\b
      | \bDisable-(?:WindowsDefender|RealtimeMonitoring|Antivirus)\b
    )
    """
)

SSH_REMOTE = re.compile(
    r"""(?ix)
    (?:
        \bssh\b[^\n]{0,140}\b(?:-[A-Za-z]+\s+)*[A-Za-z0-9._-]+@[A-Za-z0-9._-]+
      | \bStrictHostKeyChecking\s*=\s*no\b
      | \bscp\b[^\n]{0,140}@
      | \brsync\b[^\n]{0,140}@
    )
    """
)

BIND_ALL = re.compile(r"(?ix)\b(?:0\.0\.0\.0|\[::\])\b")

AUTO_UPDATE = re.compile(
    r"(?ix)\bgit\s+pull\b|\bauto[-\s]?update\b|\bself[-\s]?update\b|\bupdate\s+--force\b|\bpull\s+latest\b"
)

PROMPT_OVERRIDE = re.compile(
    r"""(?ix)
    (?:
        \b(?:ignore|disregard|forget|override|bypass)\b[^\n]{0,80}
        \b(?:previous|prior|above|earlier|system|developer|safety|security|original)\b[^\n]{0,50}
        \b(?:instruction|instructions|prompt|rule|rules|policy|policies|guideline|guidelines|guardrail|guardrails)\b
      | \byou\s+are\s+now\b
      | \bnew\s+(?:system\s+)?instructions?\b
      | \bact\s+as\s+(?:the\s+)?(?:system|developer)\b
    )
    """
)

CONCEALMENT = re.compile(
    r"""(?ix)
    (?:
        \b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|alert|notify|reveal|disclose)\b
        [^\n]{0,50}\b(?:the\s+)?user\b
      | \bwithout\s+(?:telling|informing|asking|notifying|alerting)\b[^\n]{0,40}\buser\b
      | \b(?:silently|secretly|covertly|quietly)\b[^\n]{0,50}
        \b(?:run|execute|delete|send|upload|write|modify|install|download|read|remove|disable|access)\b
      | \b(?:run|execute|delete|send|upload|write|modify|install|download|read|remove|disable|access)\b
        [^\n]{0,50}\b(?:silently|secretly|covertly|quietly)\b
      | \bhide\b[^\n]{0,40}\b(?:this|it|the)\b[^\n]{0,30}\bfrom\b
      | \bdo\s+not\s+mention\s+this\b
    )
    """
)

SOCIAL_ENGINEERING = re.compile(
    r"""(?ix)
    (?:
        \b(?:run|execute|paste|copy)\s+(?:this|the\s+following|these)\b[^\n]{0,60}
        \b(?:command|commands|script|snippet|code)\b
      | \b(?:disable|turn\s+off)\b[^\n]{0,40}
        \b(?:antivirus|firewall|defender|gatekeeper|security|sandbox|SIP)\b
      | \b(?:allow|accept)\b[^\n]{0,40}\b(?:unsigned|untrusted|unknown)\b[^\n]{0,40}
        \b(?:app|application|extension|macro)\b
      | \bauto[-\s]?approve\b
      | \bwithout\s+(?:confirmation|approval|consent)\b
    )
    """
)

TOOL_OVERRIDE = re.compile(
    r"""(?ix)
    \b(?:ignore|bypass|disable|override)\b[^\n]{0,50}
    \b(?:permissions?|approvals?|confirmations?|guardrails?|restrictions?|sandbox)\b
    """
)

EXFIL_INSTRUCTION = re.compile(
    r"""(?ix)
    (?:
        \b(?:send|upload|post|transmit|email|exfiltrate|leak|forward)\b(?!-)[^\n]{0,80}
        \b(?:contents?|data|files?|keys?|credentials?|tokens?|secrets?|env|environment|ssh|wallet|password)\b
        [^\n]{0,80}\b(?:to|at|into)\b
      | \b(?:send|upload|post)\b(?!-)[^\n]{0,60}https?://
    )
    """
)

FETCH_VERBS = re.compile(
    r"(?i)\b(?:read|follow|fetch|download|retrieve|consult|visit|execute|install)\b"
)
FETCH_NOUNS = re.compile(
    r"(?i)\b(?:instruction|instructions|documentation|docs|guide|setup|readme|steps|commands|script|binary|payload|config)\b"
)

URL_RE = re.compile(r"https?://[^\s<>'\"\]\)\}]+", re.I)
DATA_URI_RE = re.compile(r"data:[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+;base64,[A-Za-z0-9+/=]{40,}", re.I)

_SERVICE_BRANDS = {
    "google", "microsoft", "amazon", "aws", "apple", "meta", "facebook", "openai",
    "anthropic", "stripe", "paypal", "coinbase", "binance", "solana", "github",
    "slack", "discord", "telegram", "vercel", "netlify", "cloudflare",
}

EXFIL_HOST_PARTS = {
    "pastebin.com", "paste.ee", "hastebin.com", "transfer.sh", "file.io",
    "0x0.st", "webhook.site", "requestbin.net", "pipedream.net", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "serveo.net", "localtunnel.me",
    "discord.com", "discordapp.com", "api.telegram.org", "hooks.slack.com",
}
MUTABLE_HOST_PARTS = {
    "raw.githubusercontent.com", "gist.githubusercontent.com", "gist.github.com",
    "api.github.com", "r.jina.ai",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.one",
}
DYNAMIC_DNS = {
    "duckdns.org", "no-ip.org", "hopto.org", "zapto.org", "sytes.net",
    "ddns.net", "dynu.net", "myftp.org",
}
FREE_HOSTS = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com",
}
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".zip", ".mov"}
# Classification set, not a bind address.
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]", "[::]"}  # nosec B104


@dataclass(frozen=True)
class UrlVerdict:
    host: str
    scheme: str
    category: str
    severity: Severity | None
    confidence: Confidence
    reason: str


def _host_matches(host: str, candidates: set[str]) -> bool:
    for candidate in candidates:
        if host == candidate or host.endswith("." + candidate):
            return True
    return False


def classify_url(url: str) -> UrlVerdict:
    try:
        parts = urlsplit(url)
    except ValueError:
        return UrlVerdict("", "", "invalid", Severity.MEDIUM, Confidence.LOW, "unparseable URL")
    host = (parts.hostname or "").lower().strip(".")
    scheme = (parts.scheme or "").lower()
    if not host:
        return UrlVerdict(host, scheme, "invalid", Severity.MEDIUM, Confidence.LOW, "URL has no host")

    if host in LOCAL_HOSTS or host.startswith("127."):
        return UrlVerdict(host, scheme, "local", None, Confidence.HIGH, "local address, not external")
    if scheme not in ("http", "https"):
        return UrlVerdict(
            host, scheme, "non-http", Severity.MEDIUM, Confidence.HIGH,
            f"non-HTTP scheme ({scheme or 'none'})",
        )
    if parts.username or parts.password:
        return UrlVerdict(
            host, scheme, "credentials", Severity.HIGH, Confidence.HIGH,
            "URL embeds credentials",
        )
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return UrlVerdict(
            host, scheme, "ip-literal", Severity.HIGH, Confidence.HIGH,
            "raw IP address instead of a stable hostname",
        )
    if _host_matches(host, EXFIL_HOST_PARTS):
        # A templated credential (for example ``bot${TOKEN}``) is configuration,
        # not an endpoint embedded in the package. Keep it visible but do not
        # gate on it; a hardcoded token still matches the secret rules.
        if re.search(
            r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{[A-Za-z_][A-Za-z0-9_]*\}",
            parts.path or "",
        ):
            return UrlVerdict(
                host, scheme, "integration-api", Severity.MEDIUM, Confidence.MEDIUM,
                "known API host used with a configured credential",
            )
        return UrlVerdict(
            host, scheme, "exfil-service", Severity.HIGH, Confidence.HIGH,
            "host is commonly used for paste, webhook, or tunnel exfiltration",
        )
    if _host_matches(host, MUTABLE_HOST_PARTS):
        return UrlVerdict(
            host, scheme, "mutable", Severity.MEDIUM, Confidence.HIGH,
            "content on this host is mutable and not pin-able by the skill",
        )
    if _host_matches(host, SHORTENERS):
        return UrlVerdict(
            host, scheme, "shortener", Severity.MEDIUM, Confidence.MEDIUM,
            "URL shortener hides the final destination",
        )
    if _host_matches(host, DYNAMIC_DNS):
        return UrlVerdict(
            host, scheme, "dynamic-dns", Severity.MEDIUM, Confidence.MEDIUM,
            "dynamic DNS hostname can be repointed by its owner",
        )
    if _host_matches(host, FREE_HOSTS):
        return UrlVerdict(
            host, scheme, "free-host", Severity.MEDIUM, Confidence.MEDIUM,
            "free hosting is easy to abandon or take over",
        )
    if host.startswith("xn--") or ".xn--" in host:
        return UrlVerdict(
            host, scheme, "punycode", Severity.MEDIUM, Confidence.MEDIUM,
            "punycode hostname may be a homograph",
        )
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return UrlVerdict(
            host, scheme, "suspicious-tld", Severity.MEDIUM, Confidence.LOW,
            "top-level domain is frequently abused for throwaway infrastructure",
        )
    if scheme == "http":
        return UrlVerdict(
            host, scheme, "cleartext", Severity.MEDIUM, Confidence.HIGH,
            "cleartext HTTP can be modified in transit",
        )
    return UrlVerdict(host, scheme, "https", Severity.LOW, Confidence.LOW, "external HTTPS host")


def urls_in(text: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in URL_RE.finditer(line):
            url = match.group(0).rstrip(".,;:!?)('\"")
            found.append((line_no, url))
    return found


def brands_in(text: str) -> list[str]:
    lowered = text.lower()
    return sorted(brand for brand in _SERVICE_BRANDS if re.search(rf"\b{re.escape(brand)}\b", lowered))
