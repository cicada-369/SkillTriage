I'll write a scanner that checks each skill's instructions and bundled files, plus a hash baseline to catch changes after you've approved a skill. Then I'll test it on sample skills.

Next I'll build a benign skill and a deliberately malicious one, then run the scanner against them.

The scanner catches most of the planted issues. One gap: the ELF binary in `bin/helper` produced no finding. I'll check that before going further.

The scanner was fine; my shell's `printf` wrote literal backslashes instead of bytes, so the test file was plain text. I'll regenerate it with real bytes and rerun the baseline and drift checks.

Everything works: detection, baseline, drift, JSON, and error handling. I'll copy the tool to the outputs folder for you.

I wrote `skillscan.py`, a single Python file that uses only the standard library, so it runs on Kali without installing anything. It scans each skill folder (any directory with a `SKILL.md`) and reports findings grouped by severity.

Skills are scanned as both text and code, because a `SKILL.md` is read by the model as instructions. A skill can cause harm with no code at all, for example by telling the model to read `~/.ssh/id_rsa` and send it somewhere, or to hide that step from you. The scanner looks for:

- **Hidden or injected instructions:** override phrasing, "don't tell the user," hidden HTML comments, zero-width and bidi characters, and descriptions that claim every request to hijack other skills.
- **Credentials and exfiltration:** references to SSH keys, cloud and git credential files, browser cookie stores, and callback services like webhook.site or pastebin, plus uploads via `curl -F` or `-d`.
- **Dangerous execution:** `curl ... | bash`, base64 decoding, `eval`/`exec`, unsafe deserialization, and inline one-liners.
- **Damage and persistence:** `rm -rf ~`, disk wiping, shell startup edits, crontab and systemd entries, setuid bits, and sudoers changes.
- **File-level issues:** executables and archives, symlinks that point outside the skill folder, and world-writable files.
- **Drift:** `--save-baseline` records file hashes for skills you've approved, and `--diff` flags any skill or file that was added, changed, or removed afterward.

**Usage**

```
python3 skillscan.py                          # default locations
python3 skillscan.py ~/some/skills            # a specific folder
python3 skillscan.py --min-severity high      # hide the noise
python3 skillscan.py --ignore NET-004         # suppress a rule
python3 skillscan.py --save-baseline          # after reviewing a clean scan
python3 skillscan.py --diff                   # later: what changed?
python3 skillscan.py --json                   # for scripting
```

The exit code is 2 for critical findings, 1 for high, and 0 otherwise, so you can use it in a cron job or pre-commit hook.

**Where your skills are:** the default roots are `~/.claude/skills`, `~/.claude/plugins`, and `./.claude/skills`. If your skills live elsewhere, find them with `find / -name SKILL.md 2>/dev/null` and pass those folders as arguments.

I tested it in a sandbox on a benign sample skill and a deliberately malicious one. It flagged the malicious skill's planted issues, including the ones in prose, and found no false positives in the benign skill. I didn't run it on your Kali machine, so the default paths there are unverified. It needs Python 3.9 or newer.

**Limitations**

- It's pattern matching, so a clean result doesn't prove a skill is safe. Heavy obfuscation or encoded payloads can get past it.
- It flags legitimate things too, such as `curl` and `sudo` in install instructions. That's why the findings include the matching line, so you can judge them.
- The baseline trusts whatever state you approve, so review the scan before you save it.

If you want to extend it, the next useful pieces would be a dependency audit for any `requirements.txt` or `package.json` files, and running a skill's scripts inside `firejail` or `bwrap` to see what they actually do. I can add either.
