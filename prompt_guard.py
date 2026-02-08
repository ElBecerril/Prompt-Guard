#!/usr/bin/env python3
"""
prompt_guard.py - Prompt Injection Scanner

Scans local directories or GitHub repos for prompt injection patterns,
steganographic hidden messages, and other malicious content targeting AI systems.
"""

import re
import json
import os
import sys
import argparse
import base64
import subprocess
import tempfile
import unicodedata
from datetime import datetime
from pathlib import Path

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("colorama not found. Install with: pip install colorama")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Module 1: Direct Pattern Scanner
# ---------------------------------------------------------------------------

PATTERNS = {
    "critical": {
        "score": 10,
        "patterns": [
            # Exfiltration
            (r"(?:env[ií]a|manda|send|forward)\s+(?:credenciales|contrase[ñn]as|tokens?|api[_\s]?keys?|secrets?|passwords?)\s+(?:a|to)\b",
             "exfiltration_send_credentials", "Attempt to exfiltrate credentials"),
            (r"(?:curl|wget)\s+.*(?:/etc/passwd|/etc/shadow|\.env\b|credentials|\.pem\b|\.key\b|id_rsa)",
             "exfiltration_sensitive_file", "curl/wget targeting sensitive file"),
            (r"POST\s+(?:to\s+)?https?://", "exfiltration_post", "Suspicious POST to external URL"),
            (r"forward\s+(?:all\s+)?data\s+to\b", "exfiltration_forward", "Attempt to forward data externally"),
            # System override
            (r"(?:olvida|ignora)\s+(?:tus|todas?\s+(?:las\s+)?(?:tus)?)\s+(?:instrucciones|[oó]rdenes|reglas)",
             "override_forget_instructions_es", "Override: forget instructions (Spanish)"),
            (r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
             "override_ignore_previous", "Override: ignore previous instructions"),
            (r"disregard\s+(?:all\s+)?(?:your\s+)?(?:rules|instructions|guidelines)",
             "override_disregard_rules", "Override: disregard rules"),
            (r"forget\s+(?:your\s+)?system\s+prompt", "override_forget_system_prompt",
             "Override: forget system prompt"),
            (r"override\s+(?:your\s+)?programming", "override_programming",
             "Override: override programming"),
            (r"ignora\s+tu\s+programaci[oó]n", "override_programming_es",
             "Override: override programming (Spanish)"),
            # Prompt reveal
            (r"show\s+(?:me\s+)?your\s+system\s+prompt", "reveal_system_prompt",
             "Attempt to reveal system prompt"),
            (r"mu[eé]strame\s+tu\s+prompt\s+de\s+sistema", "reveal_system_prompt_es",
             "Attempt to reveal system prompt (Spanish)"),
            (r"print\s+(?:your\s+)?(?:hidden\s+)?instructions?", "reveal_print_instructions",
             "Attempt to print hidden instructions"),
            (r"reveal\s+(?:your\s+)?hidden\s+prompt", "reveal_hidden_prompt",
             "Attempt to reveal hidden prompt"),
            (r"dame\s+tu\s+configuraci[oó]n\s+interna", "reveal_config_es",
             "Attempt to reveal internal config (Spanish)"),
        ]
    },
    "high": {
        "score_range": (7, 9),
        "patterns": [
            # Jailbreak
            (r"\bDAN\s+mode\b", "jailbreak_dan", "DAN mode jailbreak attempt"),
            (r"\bdeveloper\s+mode\b", "jailbreak_devmode", "Developer mode jailbreak attempt"),
            (r"act[uú]a\s+como\s+si\s+no\s+tuvieras\s+restricciones",
             "jailbreak_no_restrictions_es", "Jailbreak: no restrictions (Spanish)"),
            (r"pretend\s+you\s+have\s+no\s+limits?", "jailbreak_no_limits",
             "Jailbreak: pretend no limits"),
            (r"you\s+are\s+now\s+unrestricted", "jailbreak_unrestricted",
             "Jailbreak: unrestricted mode"),
            (r"\bjailbreak\b", "jailbreak_keyword", "Jailbreak keyword detected"),
            (r"bypass\s+(?:your\s+)?(?:safety\s+)?filters?", "jailbreak_bypass_filters",
             "Bypass filters attempt"),
            # Impersonation
            (r"eres\s+ahora\s+(?:un\s+)?(?:nuevo\s+)?(?:asistente|AI|IA)",
             "impersonation_new_assistant_es", "Impersonation: new assistant (Spanish)"),
            (r"you\s+are\s+now\s+a\s+different\s+AI", "impersonation_different_ai",
             "Impersonation: different AI"),
            (r"switch\s+to\s+(?:a\s+)?(?:new\s+)?persona", "impersonation_switch_persona",
             "Impersonation: switch persona"),
            (r"tu\s+nuevo\s+rol\s+es", "impersonation_new_role_es",
             "Impersonation: new role (Spanish)"),
            (r"from\s+now\s+on\s+you\s+are", "impersonation_from_now",
             "Impersonation: identity change"),
            # Exfiltration (curl/wget with data-sending flags)
            (r"\bcurl\s+.*(?:-d\s|--data\s|-F\s|--form\s|-X\s*POST|-T\s|--upload-file)",
             "exfiltration_curl_data", "curl with data exfiltration flags"),
            (r"\bwget\s+.*--post-(?:data|file)",
             "exfiltration_wget_post", "wget with POST data flags"),
            # Execution
            (r"ejecuta\s+(?:este\s+)?c[oó]digo", "execution_code_es",
             "Code execution attempt (Spanish)"),
            (r"run\s+this\s+command", "execution_run_command",
             "Command execution attempt"),
            (r"\beval\s*\(", "execution_eval", "eval() call detected"),
            (r"\bexec\s*\(", "execution_exec", "exec() call detected"),
            (r"\bos\.system\s*\(", "execution_os_system", "os.system() call detected"),
            (r"\bsubprocess\b", "execution_subprocess", "subprocess usage detected"),
        ]
    },
    "medium": {
        "score_range": (4, 6),
        "patterns": [
            # Subtle manipulation
            (r"en\s+realidad\s+tu\s+prop[oó]sito\s+es", "manipulation_real_purpose_es",
             "Subtle manipulation: real purpose (Spanish)"),
            (r"your\s+real\s+purpose\s+is", "manipulation_real_purpose",
             "Subtle manipulation: real purpose"),
            (r"the\s+user\s+actually\s+wants", "manipulation_user_wants",
             "Subtle manipulation: user actually wants"),
            (r"lo\s+que\s+realmente\s+necesito\s+es\s+que\s+ignores",
             "manipulation_ignore_es", "Subtle manipulation: ignore request (Spanish)"),
            (r"between\s+you\s+and\s+me", "manipulation_secret",
             "Subtle manipulation: between you and me"),
            # Markdown/HTML injection
            (r"<iframe\b", "html_iframe", "Hidden iframe detected"),
            (r"<script\b", "html_script", "Script tag detected"),
            (r"href\s*=\s*[\"']data:", "html_data_link", "Data URI link detected"),
            (r"href\s*=\s*[\"']javascript:", "html_javascript_link",
             "JavaScript URI link detected"),
            (r"on\w+\s*=\s*[\"']", "html_event_handler",
             "Inline event handler detected"),
        ]
    },
    "low": {
        "score_range": (1, 3),
        "patterns": [
            (r"no\s+le\s+digas\s+al\s+usuario", "secrecy_dont_tell_es",
             "Secrecy indicator: don't tell the user (Spanish)"),
            (r"don'?t\s+tell\s+the\s+user", "secrecy_dont_tell",
             "Secrecy indicator: don't tell the user"),
            (r"\bsecretly\b", "secrecy_secretly", "Secrecy indicator: secretly"),
            (r"\ben\s+secreto\b", "secrecy_secretly_es",
             "Secrecy indicator: secretly (Spanish)"),
            (r"sin\s+que\s+se\s+entere", "secrecy_without_knowing_es",
             "Secrecy indicator: without them knowing (Spanish)"),
            # curl/wget plain (likely documentation/installation instructions)
            (r"\bcurl\s+https?://", "exfiltration_curl_plain",
             "curl to external URL (likely benign)"),
            (r"\bwget\s+https?://", "exfiltration_wget_plain",
             "wget to external URL (likely benign)"),
        ]
    }
}

SEVERITY_SCORES = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
}

DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

DEFAULT_EXTENSIONS = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".py", ".html", ".htm",
    ".xml", ".csv", ".rst", ".toml", ".ini", ".cfg", ".conf",
    ".js", ".ts", ".jsx", ".tsx", ".sh", ".bat", ".ps1",
}

# Pre-compile all regex patterns once at module load
COMPILED_PATTERNS = {}
for _severity, _category in PATTERNS.items():
    COMPILED_PATTERNS[_severity] = []
    for _pattern_re, _name, _desc in _category["patterns"]:
        try:
            COMPILED_PATTERNS[_severity].append({
                "regex": re.compile(_pattern_re, re.IGNORECASE),
                "name": _name,
                "desc": _desc,
                "score": SEVERITY_SCORES[_severity],
            })
        except re.error:
            continue


def scan_direct_patterns(content: str, filepath: str) -> list[dict]:
    """Scan file content against all pre-compiled pattern categories."""
    findings = []
    lines = content.split("\n")

    for severity, compiled_list in COMPILED_PATTERNS.items():
        for entry in compiled_list:
            for line_num, line in enumerate(lines, 1):
                for match in entry["regex"].finditer(line):
                    findings.append({
                        "type": "direct_pattern",
                        "severity": severity,
                        "score": entry["score"],
                        "line": line_num,
                        "content": line.strip()[:200],
                        "pattern_matched": entry["name"],
                        "description": entry["desc"],
                    })
    return findings


# ---------------------------------------------------------------------------
# Module 2: Steganographic Analysis
# ---------------------------------------------------------------------------

DANGEROUS_PHRASES = [
    "ignore", "override", "forget", "system", "prompt", "inject",
    "execute", "eval", "hack", "bypass", "jailbreak", "exfil",
    "password", "token", "secret", "credential", "send", "curl",
    "ignora", "olvida", "ejecuta", "contrasena", "secreto",
]

ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u2060": "WORD JOINER",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
}

CYRILLIC_HOMOGLYPHS = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X", "\u0430": "a",
    "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x",
}

GREEK_HOMOGLYPHS = {
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03b1": "a", "\u03bf": "o",
}


def _check_phrase_match(text: str) -> str | None:
    """Check if extracted text contains dangerous phrases."""
    lower = text.lower()
    for phrase in DANGEROUS_PHRASES:
        if phrase in lower:
            return phrase
    return None


def detect_acrostic(lines: list[str], step: int = 1) -> list[dict]:
    """Detect acrostic messages in first characters of lines."""
    findings = []
    selected = [l for i, l in enumerate(lines) if i % step == 0 and l.strip()]
    if len(selected) < 4:
        return findings
    acrostic = "".join(l.strip()[0] for l in selected if l.strip())
    match = _check_phrase_match(acrostic)
    if match:
        step_label = f"every {step} lines" if step > 1 else "consecutive lines"
        findings.append({
            "type": "steganographic",
            "severity": "medium",
            "score": SEVERITY_SCORES["medium"],
            "line": 1,
            "content": f"Acrostic ({step_label}): '{acrostic}'",
            "pattern_matched": "acrostic_hidden_message",
            "description": f"Acrostic message detected ({step_label}), "
                           f"contains dangerous phrase: '{match}'",
        })
    return findings


def detect_first_word_pattern(content: str) -> list[dict]:
    """Detect patterns in the first word of each paragraph."""
    findings = []
    paragraphs = re.split(r"\n\s*\n", content)
    first_words = []
    for para in paragraphs:
        stripped = para.strip()
        if stripped:
            words = stripped.split()
            if words:
                first_words.append(words[0])
    if len(first_words) >= 3:
        combined = " ".join(first_words)
        match = _check_phrase_match(combined)
        if match:
            findings.append({
                "type": "steganographic",
                "severity": "medium",
                "score": SEVERITY_SCORES["medium"],
                "line": 1,
                "content": f"First words of paragraphs: '{combined[:200]}'",
                "pattern_matched": "first_word_hidden_message",
                "description": f"Hidden message in first words of paragraphs, "
                               f"contains: '{match}'",
            })
    return findings


def detect_diagonal_pattern(lines: list[str]) -> list[dict]:
    """Detect patterns where character N of line N forms a message."""
    findings = []
    diagonal = []
    for i, line in enumerate(lines):
        if i < len(line.rstrip()):
            diagonal.append(line[i])
    if len(diagonal) >= 4:
        text = "".join(diagonal)
        match = _check_phrase_match(text)
        if match:
            findings.append({
                "type": "steganographic",
                "severity": "medium",
                "score": SEVERITY_SCORES["medium"],
                "line": 1,
                "content": f"Diagonal pattern: '{text[:200]}'",
                "pattern_matched": "diagonal_hidden_message",
                "description": f"Hidden message in diagonal pattern, "
                               f"contains: '{match}'",
            })
    return findings


def detect_hidden_base64(content: str) -> list[dict]:
    """Find base64-encoded strings and check decoded content for danger."""
    findings = []
    b64_pattern = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/])")
    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        for m in b64_pattern.finditer(line):
            candidate = m.group(1)
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                if len(decoded) < 4:
                    continue
                match = _check_phrase_match(decoded)
                if match:
                    findings.append({
                        "type": "encoding",
                        "severity": "medium",
                        "score": SEVERITY_SCORES["medium"],
                        "line": line_num,
                        "content": f"Base64: '{candidate[:80]}' -> '{decoded[:120]}'",
                        "pattern_matched": "hidden_base64",
                        "description": f"Base64-encoded string decodes to content "
                                       f"containing: '{match}'",
                    })
                # Also run direct patterns against decoded content
                for sev, cat in PATTERNS.items():
                    for pat_re, pat_name, desc in cat["patterns"]:
                        try:
                            if re.search(pat_re, decoded, re.IGNORECASE):
                                findings.append({
                                    "type": "encoding",
                                    "severity": sev,
                                    "score": SEVERITY_SCORES[sev],
                                    "line": line_num,
                                    "content": f"Base64: '{candidate[:80]}' "
                                               f"-> '{decoded[:120]}'",
                                    "pattern_matched": f"base64_{pat_name}",
                                    "description": f"Base64-encoded content matches "
                                                   f"pattern: {desc}",
                                })
                        except re.error:
                            continue
            except Exception:
                continue
    return findings


def detect_zero_width(content: str) -> list[dict]:
    """Detect zero-width characters that could hide messages."""
    findings = []
    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        for char, name in ZERO_WIDTH_CHARS.items():
            count = line.count(char)
            if count > 0:
                findings.append({
                    "type": "encoding",
                    "severity": "medium",
                    "score": SEVERITY_SCORES["medium"],
                    "line": line_num,
                    "content": f"Found {count}x {name} (U+{ord(char):04X})",
                    "pattern_matched": "zero_width_chars",
                    "description": f"Zero-width character '{name}' found {count} "
                                   f"time(s) -- may hide steganographic content",
                })
    return findings


def detect_homoglyphs(content: str) -> list[dict]:
    """Detect Unicode homoglyphs (Cyrillic/Greek chars that look Latin)."""
    findings = []
    all_homoglyphs = {**CYRILLIC_HOMOGLYPHS, **GREEK_HOMOGLYPHS}
    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        found_in_line = []
        for char in line:
            if char in all_homoglyphs:
                script = unicodedata.name(char, "UNKNOWN").split()[0]
                found_in_line.append(
                    f"'{char}'(U+{ord(char):04X}, {script}) looks like "
                    f"'{all_homoglyphs[char]}'"
                )
        if found_in_line:
            findings.append({
                "type": "encoding",
                "severity": "medium",
                "score": SEVERITY_SCORES["medium"],
                "line": line_num,
                "content": "; ".join(found_in_line[:5]),
                "pattern_matched": "unicode_homoglyphs",
                "description": f"Unicode homoglyph(s) detected -- characters from "
                               f"non-Latin scripts that visually resemble Latin letters",
            })
    return findings


def detect_hidden_comments(content: str, filepath: str) -> list[dict]:
    """Detect hidden comments in HTML/JSON/Markdown with instructions."""
    findings = []
    ext = Path(filepath).suffix.lower()

    # HTML comments
    if ext in (".html", ".htm", ".md", ".xml"):
        html_comments = re.finditer(r"<!--(.*?)-->", content, re.DOTALL)
        for m in html_comments:
            comment_text = m.group(1)
            for sev, cat in PATTERNS.items():
                for pat_re, pat_name, desc in cat["patterns"]:
                    try:
                        if re.search(pat_re, comment_text, re.IGNORECASE):
                            line_num = content[:m.start()].count("\n") + 1
                            findings.append({
                                "type": "steganographic",
                                "severity": sev,
                                "score": SEVERITY_SCORES[sev],
                                "line": line_num,
                                "content": f"Hidden comment: "
                                           f"'{comment_text.strip()[:150]}'",
                                "pattern_matched": f"hidden_comment_{pat_name}",
                                "description": f"Injection pattern found inside "
                                               f"HTML/Markdown comment: {desc}",
                            })
                    except re.error:
                        continue

    # Python/Shell comments
    if ext in (".py", ".sh", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"):
        comment_re = re.compile(r"#\s*(.+)")
        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            for cm in comment_re.finditer(line):
                comment_text = cm.group(1)
                for sev, cat in PATTERNS.items():
                    for pat_re, pat_name, desc in cat["patterns"]:
                        try:
                            if re.search(pat_re, comment_text, re.IGNORECASE):
                                findings.append({
                                    "type": "steganographic",
                                    "severity": sev,
                                    "score": SEVERITY_SCORES[sev],
                                    "line": line_num,
                                    "content": f"Comment: '{comment_text.strip()[:150]}'",
                                    "pattern_matched": f"hidden_comment_{pat_name}",
                                    "description": f"Injection pattern inside "
                                                   f"code comment: {desc}",
                                })
                        except re.error:
                            continue

    return findings


def scan_steganographic(content: str, filepath: str) -> list[dict]:
    """Run all steganographic detection methods."""
    findings = []
    lines = content.split("\n")

    # Acrostics (step 1 through 5)
    for step in range(1, 6):
        findings.extend(detect_acrostic(lines, step))

    findings.extend(detect_first_word_pattern(content))
    findings.extend(detect_diagonal_pattern(lines))
    findings.extend(detect_hidden_base64(content))
    findings.extend(detect_zero_width(content))
    findings.extend(detect_homoglyphs(content))
    findings.extend(detect_hidden_comments(content, filepath))

    return findings


# ---------------------------------------------------------------------------
# Module 3: Input Sources
# ---------------------------------------------------------------------------

def get_files_local(directory: str, extensions: set[str]) -> list[Path]:
    """Recursively get files from a local directory filtered by extension."""
    root = Path(directory).resolve()
    if not root.is_dir():
        print(f"{Fore.RED}Error: '{directory}' is not a valid directory.{Style.RESET_ALL}")
        sys.exit(1)

    files = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv",
                 ".tox", ".mypy_cache", ".pytest_cache", "dist", "build"}
    for path in root.rglob("*"):
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in extensions:
            files.append(path)
    return files


def clone_github_repo(url: str) -> str:
    """Clone a GitHub repo to a temp directory (shallow clone)."""
    tmpdir = tempfile.mkdtemp(prefix="prompt_guard_")
    print(f"{Fore.CYAN}Cloning {url} into {tmpdir}...{Style.RESET_ALL}")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, tmpdir],
            check=True, capture_output=True, text=True,
        )
    except FileNotFoundError:
        print(f"{Fore.RED}Error: 'git' is not installed or not in PATH.{Style.RESET_ALL}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error cloning repo: {e.stderr.strip()}{Style.RESET_ALL}")
        sys.exit(1)
    print(f"{Fore.GREEN}Clone complete.{Style.RESET_ALL}")
    return tmpdir


def is_github_url(source: str) -> bool:
    """Check if source looks like a GitHub URL."""
    return source.startswith(("https://github.com/", "git@github.com:"))


# ---------------------------------------------------------------------------
# Module 4: Scoring & Reporting
# ---------------------------------------------------------------------------

def classify_score(score: int) -> str:
    """Classify a file score into a risk level."""
    if score <= 10:
        return "SAFE"
    if score <= 40:
        return "SUSPICIOUS"
    if score <= 70:
        return "DANGEROUS"
    return "CRITICAL"


def classify_color(classification: str) -> str:
    """Get colorama color for a classification."""
    return {
        "SAFE": Fore.GREEN,
        "SUSPICIOUS": Fore.YELLOW,
        "DANGEROUS": Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }.get(classification, "")


def compute_file_score(detections: list[dict]) -> int:
    """Compute a 0-100 file score from detections."""
    if not detections:
        return 0
    raw = sum(d["score"] for d in detections)
    return min(raw, 100)


def build_report(source: str, results: list[dict]) -> dict:
    """Build the full JSON report structure."""
    flagged = [r for r in results if r["score"] > 0]
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in flagged:
        for d in r["detections"]:
            if d["severity"] in summary:
                summary[d["severity"]] += 1

    return {
        "scan_date": datetime.now().isoformat(),
        "source": source,
        "total_files": len(results),
        "files_flagged": len(flagged),
        "summary": summary,
        "findings": [
            {
                "file": r["file"],
                "score": r["score"],
                "classification": r["classification"],
                "detections": r["detections"],
            }
            for r in flagged
        ],
    }


# ---------------------------------------------------------------------------
# Module 5: CLI & Main
# ---------------------------------------------------------------------------

def print_banner():
    """Print the tool banner."""
    border = "=" * 52
    print()
    print(f"{Fore.CYAN}{Style.BRIGHT}{border}")
    print(f"  PROMPT GUARD - Injection Scanner")
    print(f"  First line of defense against")
    print(f"  prompt injection attacks")
    print(f"{border}{Style.RESET_ALL}")
    print()


def print_results(results: list[dict], verbose: bool = False):
    """Print scan results to terminal with colors."""
    flagged = [r for r in results if r["score"] > 0]
    safe = [r for r in results if r["score"] == 0]

    if not flagged and not verbose:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}All {len(results)} files scanned -- "
              f"no threats detected.{Style.RESET_ALL}\n")
        return

    print(f"\n{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT} SCAN RESULTS{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}\n")

    # Show flagged files
    for r in sorted(flagged, key=lambda x: x["score"], reverse=True):
        color = classify_color(r["classification"])
        print(f"  {color}{r['classification']:12s}{Style.RESET_ALL} "
              f"[score {r['score']:3d}]  {r['file']}")
        for d in r["detections"]:
            sev_color = classify_color(
                "CRITICAL" if d["severity"] == "critical"
                else "DANGEROUS" if d["severity"] == "high"
                else "SUSPICIOUS" if d["severity"] == "medium"
                else "SAFE"
            )
            print(f"    {sev_color}  L{d['line']:<5d} [{d['severity'].upper():8s}] "
                  f"{d['description']}{Style.RESET_ALL}")
            print(f"             {Fore.WHITE}{d['content'][:120]}{Style.RESET_ALL}")
        print()

    # Show safe files if verbose
    if verbose and safe:
        print(f"  {Fore.GREEN}--- Safe files ({len(safe)}) ---{Style.RESET_ALL}")
        for r in safe:
            print(f"    {Fore.GREEN}SAFE          [score   0]  {r['file']}{Style.RESET_ALL}")
        print()

    # Summary
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in flagged:
        for d in r["detections"]:
            if d["severity"] in summary:
                summary[d["severity"]] += 1

    print(f"{Style.BRIGHT}{'-' * 60}{Style.RESET_ALL}")
    print(f"  Total files scanned: {len(results)}")
    print(f"  Files flagged:       {len(flagged)}")
    print(f"  Detections:          "
          f"{Fore.RED + Style.BRIGHT}{summary['critical']} critical{Style.RESET_ALL}, "
          f"{Fore.RED}{summary['high']} high{Style.RESET_ALL}, "
          f"{Fore.YELLOW}{summary['medium']} medium{Style.RESET_ALL}, "
          f"{Fore.GREEN}{summary['low']} low{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{'-' * 60}{Style.RESET_ALL}\n")


def scan_file(filepath: Path, base_dir: Path, max_size: int = DEFAULT_MAX_FILE_SIZE) -> dict:
    """Scan a single file and return results."""
    rel_path = str(filepath.relative_to(base_dir))

    # Skip files exceeding max size
    try:
        file_size = filepath.stat().st_size
    except OSError:
        file_size = 0
    if file_size > max_size:
        return {
            "file": rel_path,
            "score": 0,
            "classification": "SAFE",
            "detections": [{
                "type": "skipped",
                "severity": "low",
                "score": 0,
                "line": 0,
                "content": f"File size {file_size / 1024 / 1024:.1f}MB exceeds limit "
                           f"{max_size / 1024 / 1024:.1f}MB",
                "pattern_matched": "file_too_large",
                "description": f"File skipped: size ({file_size / 1024 / 1024:.1f}MB) "
                               f"exceeds --max-size limit",
            }],
        }

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {
            "file": rel_path,
            "score": 0,
            "classification": "SAFE",
            "detections": [{
                "type": "error",
                "severity": "low",
                "score": 0,
                "line": 0,
                "content": str(e),
                "pattern_matched": "read_error",
                "description": f"Could not read file: {e}",
            }],
        }

    detections = []
    detections.extend(scan_direct_patterns(content, rel_path))
    detections.extend(scan_steganographic(content, rel_path))

    score = compute_file_score(detections)
    classification = classify_score(score)

    return {
        "file": rel_path,
        "score": score,
        "classification": classification,
        "detections": detections,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Prompt Injection Scanner -- detect malicious prompt "
                    "injection patterns in text files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python prompt_guard.py ./my-repo
  python prompt_guard.py https://github.com/user/repo
  python prompt_guard.py ./my-repo --output report.json
  python prompt_guard.py ./my-repo --verbose
  python prompt_guard.py ./my-repo --extensions .md,.txt,.json
        """,
    )
    parser.add_argument("source",
                        help="Local directory path or GitHub repo URL to scan")
    parser.add_argument("--output", "-o", default="report.json",
                        help="Output report filename (default: report.json)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show all files, not just flagged ones")
    parser.add_argument("--extensions", "-e", default=None,
                        help="Comma-separated list of extensions to scan "
                             "(e.g. .md,.txt,.json)")
    parser.add_argument("--max-size", "-m", type=float, default=1.0,
                        help="Max file size in MB to scan (default: 1.0). "
                             "Files exceeding this limit are skipped.")

    args = parser.parse_args()
    print_banner()

    # Parse max file size (MB -> bytes)
    max_size = int(args.max_size * 1024 * 1024)

    # Parse extensions
    if args.extensions:
        extensions = {
            ext.strip() if ext.strip().startswith(".") else f".{ext.strip()}"
            for ext in args.extensions.split(",")
        }
    else:
        extensions = DEFAULT_EXTENSIONS

    # Resolve source
    temp_dir = None
    if is_github_url(args.source):
        temp_dir = clone_github_repo(args.source)
        scan_dir = temp_dir
    else:
        scan_dir = args.source

    base_dir = Path(scan_dir).resolve()

    # Collect files
    print(f"{Fore.CYAN}Scanning: {args.source}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Extensions: {', '.join(sorted(extensions))}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Max file size: {args.max_size:.1f}MB{Style.RESET_ALL}")
    files = get_files_local(scan_dir, extensions)
    print(f"{Fore.CYAN}Files found: {len(files)}{Style.RESET_ALL}\n")

    if not files:
        print(f"{Fore.YELLOW}No files matched the given extensions.{Style.RESET_ALL}")
        sys.exit(0)

    # Scan each file
    results = []
    for i, fpath in enumerate(files, 1):
        print(f"\r  Scanning [{i}/{len(files)}] {fpath.name[:40]:<40s}", end="", flush=True)
        results.append(scan_file(fpath, base_dir, max_size))
    print("\r" + " " * 80 + "\r", end="")

    # Print results
    print_results(results, verbose=args.verbose)

    # Write report
    report = build_report(args.source, results)
    report_path = Path(args.output)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                           encoding="utf-8")
    print(f"{Fore.GREEN}Report saved to: {report_path.resolve()}{Style.RESET_ALL}\n")

    # Cleanup temp dir
    if temp_dir:
        import shutil
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

    # Exit code: non-zero if critical/high findings
    if report["summary"]["critical"] > 0 or report["summary"]["high"] > 0:
        sys.exit(2)
    if report["summary"]["medium"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
