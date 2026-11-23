# Scanner source (scan.py)

Write the code block below, exactly as it is, to `/tmp/skill-audit-tools/scan.py`. It reads target files as text only and never runs, imports or installs anything from the skill under audit. The regular expressions below are *detection patterns*: they describe attacks so the scanner can find them.

```python
#!/usr/bin/env python3
"""skill-audit static triage scanner.
Reads target files as bytes/text ONLY. Never imports, runs or installs anything from the target.
Usage:
  python3 -I scan.py <skill_dir>
  python3 -I scan.py --extract <archive> <empty_dest_dir>
"""
import os, re, sys, json, zipfile, tarfile

MAX_BYTES = 5_000_000
BIN_EXT = {'.exe','.dll','.so','.dylib','.bin','.pyc','.pyo','.jar','.class','.msi','.dmg','.pkg',
           '.deb','.rpm','.scr','.com','.wasm','.node','.app'}
MEDIA_EXT = {'.png','.jpg','.jpeg','.gif','.webp','.ico','.pdf','.ttf','.otf','.woff','.woff2','.mp3','.mp4','.wav'}
AUTO_RUN_NAMES = {'sitecustomize.py','usercustomize.py','conftest.py','setup.py','.npmrc','.pypirc','Makefile',
                  'package.json','pyproject.toml','hooks.json','settings.json','settings.local.json','.mcp.json',
                  'CLAUDE.md','.bashrc','.zshrc','.profile'}
HIDDEN = re.compile('[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f\U000e0100-\U000e01ef]')

def r(sev, cat, pat, note):
    return (sev, cat, re.compile(pat, re.I), note)

RULES = [
 r('CRITICAL','reverse-shell', r'/dev/tcp/|\bnc(at)?\s+[^\n]*-e\s|socat\s[^\n]*exec|pty\.spawn|bash\s+-i\s*>&', 'Reverse shell / remote access to the machine'),
 r('CRITICAL','download-exec', r'(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b|Invoke-Expression|\biex\s*\(|DownloadString|DownloadFile', 'Downloads code and runs it immediately'),
 r('CRITICAL','decode-exec', r'base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh|exec\s*\(\s*(base64|codecs|zlib|marshal|bytes\.fromhex)|eval\s*\(\s*atob|marshal\.loads|exec\s*\([^\n]*decode\(|eval\s*\(\s*compile', 'Decodes hidden code and executes it (classic malware obfuscation)'),
 r('CRITICAL','exfil-endpoint', r'discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|webhook\.site|requestbin|pipedream\.net|ngrok\.(io|app)|transfer\.sh|pastebin\.com|interact\.sh|burpcollaborator|[./]oast\.(fun|me|pro|live|site|online)', 'Known data-exfiltration / attacker-callback endpoint'),
 r('HIGH','crypto-wallet', r'wallet\.dat|\.electrum|exodus|metamask|nkbihfbeogaeaoehlefnkodbefgpgknn|keystore|seed[\s_-]?phrase|mnemonic|private[\s_-]?key|ledger\s?live|trezor|\.bitcoin/|phantom|solflare', 'Touches crypto wallets / seed phrases / private keys'),
 r('HIGH','crypto-tx', r'setApprovalForAll|\bapprove\s*\(|signTransaction|eth_sendTransaction|sendRawTransaction|withdraw(al)?\s+(all|funds)|transfer\s+(all\s+)?funds', 'Signs/approves blockchain transactions or moves funds'),
 r('HIGH','clipboard', r'pbcopy|pbpaste|xclip|xsel|pyperclip|Get-Clipboard|Set-Clipboard|navigator\.clipboard|clipboard', 'Reads/writes clipboard (crypto-address swapping attack vector)'),
 r('HIGH','credentials', r'\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.git-credentials|\.docker/config|\.kube/config|keychain|security\s+find-(generic|internet)-password|Login Data|Cookies|Local State|\.env\b|_TOKEN\b|API_KEY|SECRET|password', 'Accesses credentials, tokens, cookies or saved passwords'),
 r('HIGH','spyware', r'keylog|pynput|keyboard\.hook|ImageGrab|screencapture|pyautogui\.screenshot|webcam|cv2\.VideoCapture|microphone|sounddevice', 'Keylogging / screen / camera / mic capture'),
 r('HIGH','persistence', r'crontab|LaunchAgents|LaunchDaemons|launchctl|systemctl\s+enable|/etc/systemd|\.bashrc|\.zshrc|\.bash_profile|CurrentVersion\\\\Run|schtasks|\\\\Startup\\\\', 'Installs itself to run on boot/login (persistence)'),
 r('HIGH','destructive', r'rm\s+-rf\s+(/|~|\$HOME|\*)|shred\s|mkfs|dd\s+if=[^\n]*of=/dev|format\s+c:|del\s+/[sq]|Remove-Item[^\n]*-Recurse|shutil\.rmtree', 'Mass deletion / disk destruction'),
 r('HIGH','priv-esc-av', r'\bsudo\b|chmod\s+(\+s|[0-7]*777)|setuid|\brunas\b|xattr\s+-[dc][^\n]*quarantine|spctl\s+--master-disable|csrutil|Set-MpPreference|DisableRealtimeMonitoring|Add-MpPreference\s+-Exclusion', 'Privilege escalation or disabling OS / antivirus protection'),
 r('HIGH','agent-config', r'\.claude/|settings(\.local)?\.json|bypassPermissions|dangerously|skip-permissions|permissions[^\n]{0,20}allow|PreToolUse|PostToolUse|UserPromptSubmit|mcpServers|\.mcp\.json|CLAUDE\.md', 'Changes Claude/agent config, hooks, permissions or MCP servers'),
 r('HIGH','prompt-injection', r'ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines)|disregard\s+(the\s+|your\s+)?(system|previous|safety)|(do\s*n[o\']t|never)\s+(tell|inform|mention|reveal|show)[^\n]{0,40}(user|human|person)|without\s+(asking|telling|informing|notifying)\s+(the\s+)?user|new\s+system\s+prompt|system\s+override|developer\s+mode|jailbreak|you\s+are\s+now\b|highest\s+priority|override\s+(all|any)', 'Prompt injection — tries to override Claude\'s rules or hide actions from you'),
 r('HIGH','obfuscation', r'[A-Za-z0-9+/]{200,}={0,2}|(\\x[0-9a-f]{2}){20,}|(chr\(\d+\)\s*\+\s*){8,}|String\.fromCharCode\(|\bunescape\(|rot13|getattr\(__builtins__', 'Obfuscated / encoded content hiding its real purpose'),
 r('HIGH','risky-deps', r'pip3?\s+install[^\n]*(git\+|https?://|--index-url|--extra-index-url|--trusted-host)|npm\s+(i|install)[^\n]*(https?://|git\+)|"(pre|post)install"\s*:', 'Installs packages from unofficial sources or with install-time scripts'),
 r('MEDIUM','network', r'https?://|requests\.(get|post|put)|urllib|http\.client|\bfetch\(|axios|socket\.|\bcurl\s|\bwget\s|Invoke-WebRequest|WebClient|websocket|smtplib|ftplib|paramiko', 'Network access — check what is sent and where'),
 r('MEDIUM','exec', r'subprocess|os\.system|os\.popen|child_process|execSync|\bspawn\(|ShellExecute|Start-Process|osascript', 'Runs shell commands / other programs'),
 r('MEDIUM','dynamic-code', r'\beval\s*\(|\bexec\s*\(|new\s+Function\(|__import__\(|importlib\.import_module|pickle\.loads', 'Dynamic code execution'),
 r('MEDIUM','deps', r'pip3?\s+install|npm\s+(i|install)\b|yarn\s+add|brew\s+install|apt(-get)?\s+install|cargo\s+install|gem\s+install|go\s+install', 'Installs dependencies — check names for typosquats'),
 r('MEDIUM','home-access', r'~/|\$HOME|os\.path\.expanduser|Path\.home\(\)|%USERPROFILE%|%APPDATA%|/Users/|C:\\\\Users', 'Reads/writes outside its own folder (user home)'),
 r('MEDIUM','broad-trigger', r'(use|trigger|invoke)\s+(this\s+skill\s+)?(always|for\s+(every|all|any)\s+(request|task|message|prompt))', 'Over-broad trigger — skill tries to activate on everything'),
]

def safe_extract(src, dest):
    if os.path.exists(dest) and os.listdir(dest):
        sys.exit('REFUSED: destination must be a new empty directory')
    os.makedirs(dest, exist_ok=True)
    total = 0
    bad = lambda n: n.startswith(('/', '\\')) or '..' in re.split(r'[\\/]', n) or re.match(r'^[A-Za-z]:', n)
    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z:
            for m in z.infolist():
                if bad(m.filename): sys.exit(f'REFUSED (CRITICAL): path traversal in archive: {m.filename}')
                if ((m.external_attr >> 16) & 0o170000) == 0o120000: sys.exit(f'REFUSED (HIGH): symlink in archive: {m.filename}')
                total += m.file_size
                if total > 200_000_000: sys.exit('REFUSED (HIGH): archive expands >200MB (zip bomb?)')
            z.extractall(dest)
    elif tarfile.is_tarfile(src):
        with tarfile.open(src) as t:
            for m in t.getmembers():
                if bad(m.name) or m.issym() or m.islnk() or m.isdev():
                    sys.exit(f'REFUSED (CRITICAL): unsafe tar member: {m.name}')
                total += m.size
                if total > 200_000_000: sys.exit('REFUSED (HIGH): archive expands >200MB')
            t.extractall(dest, filter='data') if hasattr(tarfile, 'data_filter') else t.extractall(dest)
    else:
        sys.exit('Not a zip/tar archive')
    print(f'Extracted safely to {dest}')

def scan(root):
    root = os.path.realpath(root)
    F, inv, urls = [], [], set()
    add = lambda sev, cat, f, ln, note: F.append({'severity': sev, 'category': cat, 'file': f, 'line': ln, 'detail': note})
    for dp, dns, fns in os.walk(root, followlinks=False):
        for n in dns + fns:
            p = os.path.join(dp, n)
            if os.path.islink(p):
                tgt = os.path.realpath(p)
                inside = tgt == root or tgt.startswith(root + os.sep)
                add('MEDIUM' if inside else 'CRITICAL', 'symlink', os.path.relpath(p, root), 0, f'symlink -> {os.readlink(p)}')
        for n in fns:
            p = os.path.join(dp, n); rel = os.path.relpath(p, root)
            if os.path.islink(p): continue
            st = os.lstat(p); ext = os.path.splitext(n)[1].lower()
            inv.append({'file': rel, 'bytes': st.st_size})
            if n.startswith('.'): add('MEDIUM', 'hidden-file', rel, 0, 'Hidden file')
            if st.st_mode & 0o111: add('MEDIUM', 'executable-bit', rel, 0, 'File marked executable')
            if ext == '.pth': add('CRITICAL', 'autorun', rel, 0, '.pth file runs code on every Python start')
            if n in AUTO_RUN_NAMES: add('HIGH', 'autorun-or-config', rel, 0, 'File type that can run automatically or change config — read fully')
            if ext in BIN_EXT: add('HIGH', 'binary', rel, 0, 'Compiled/binary file — cannot be reviewed, treat as unknown code')
            if st.st_size > MAX_BYTES: add('MEDIUM', 'large-file', rel, 0, f'{st.st_size} bytes — not scanned'); continue
            with open(p, 'rb') as fh: data = fh.read()
            head = data[:4]
            if (head == b'\x7fELF' or data[:2] == b'MZ' or head in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe')) and ext not in BIN_EXT:
                add('CRITICAL', 'disguised-binary', rel, 0, 'Executable binary disguised with a non-binary extension'); continue
            if b'\x00' in data[:8192]:
                if ext not in MEDIA_EXT and ext not in BIN_EXT: add('HIGH', 'binary', rel, 0, 'Unexpected binary content')
                continue
            text = data.decode('utf-8', 'replace')
            urls.update(re.findall(r'https?://[^\s\'"<>)\]`]+', text))
            for i, line in enumerate(text.splitlines(), 1):
                if HIDDEN.search(line.lstrip('\ufeff') if i == 1 else line): add('HIGH', 'hidden-unicode', rel, i, 'Invisible / bidi-override characters (can hide instructions or code)')
                for sev, cat, rx, note in RULES:
                    if rx.search(line): add(sev, cat, rel, i, f'{note} | {line.strip()[:160]}')
            for m in re.finditer(r'<!--[\s\S]*?-->', text):
                add('MEDIUM', 'html-comment', rel, text.count('\n', 0, m.start()) + 1, 'Hidden HTML comment — read it: ' + m.group(0)[:160].replace('\n', ' '))
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    F.sort(key=lambda x: (order[x['severity']], x['file'], x['line']))
    counts = {k: sum(1 for x in F if x['severity'] == k) for k in order}
    print(json.dumps({'root': root, 'counts': counts, 'files': inv,
                      'domains': sorted({re.sub(r'^https?://([^/:]+).*', r'\1', u).lower() for u in urls}),
                      'findings': F}, ensure_ascii=False, indent=1))

if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--extract': safe_extract(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 2: scan(sys.argv[1])
    else: sys.exit(__doc__)
```
