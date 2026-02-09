```
  ██████╗ ██████╗  ██████╗ ███╗   ███╗██████╗ ████████╗
  ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝
  ██████╔╝██████╔╝██║   ██║██╔████╔██║██████╔╝   ██║
  ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔═══╝    ██║
  ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║██║        ██║
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝        ╚═╝

   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**First line of defense against prompt injection attacks.**

Scans local directories or GitHub repos for malicious patterns, steganographic hidden messages, and injection attempts targeting AI systems.

> by **EL_Bcerril**

---

## Quick Start

```bash
pip install -r requirements.txt
```

```bash
# Scan a local folder
python prompt_guard.py ./my-repo

# Scan a GitHub repo
python prompt_guard.py https://github.com/user/repo
```

## What it detects

| Severity | Examples |
|---|---|
| **CRITICAL** | Credential exfiltration, system prompt override, prompt reveal |
| **HIGH** | Jailbreak (DAN mode, developer mode), impersonation, code execution |
| **MEDIUM** | Subtle manipulation, hidden iframes/scripts, javascript: links |
| **LOW** | Secrecy indicators ("don't tell the user", "en secreto") |

**Steganographic analysis:** acrostics, diagonal patterns, hidden base64, zero-width characters, Unicode homoglyphs, hidden comments.

Patterns work in **English and Spanish**.

## Scoring

Each file gets a score from 0 to 100:

| Score | Level | Meaning |
|---|---|---|
| 0-10 | SAFE | No threats detected |
| 11-40 | SUSPICIOUS | Ambiguous patterns, needs manual review |
| 41-70 | DANGEROUS | Clear injection patterns |
| 71-100 | CRITICAL | Multiple high-severity patterns |

## CLI Options

```
python prompt_guard.py <source> [options]

  source                 Local path or GitHub URL (required)
  -o, --output FILE      Report filename (default: report.json)
  -v, --verbose          Show all files, not just flagged ones
  -e, --extensions LIST  Comma-separated extensions to scan
  -m, --max-size MB      Max file size in MB (default: 1.0)
```

## CI/CD Integration

```bash
python prompt_guard.py ./repo && echo "PASS" || echo "ALERT"
```

| Exit code | Meaning |
|---|---|
| `0` | No relevant findings |
| `1` | Medium severity findings |
| `2` | Critical or high findings |

## Example Output

```
====================================================
  PROMPT GUARD - Injection Scanner
  First line of defense against
  prompt injection attacks
====================================================

Scanning: ./my-repo
Files found: 12

============================================================
 SCAN RESULTS
============================================================

  CRITICAL     [score 100]  docs/config.md
      L4     [CRITICAL] Override: ignore previous instructions
      L30    [CRITICAL] Base64-encoded content matches pattern
      L27    [HIGH    ] DAN mode jailbreak attempt

------------------------------------------------------------
  Total files scanned: 12
  Files flagged:       1
  Detections:          2 critical, 1 high, 0 medium, 0 low
------------------------------------------------------------

Report saved to: report.json
```

## Notes

- Analyzes **text content** only. Does not execute code.
- GitHub repos are shallow-cloned to a temp directory and cleaned up after scanning.
- Scanning `prompt_guard.py` itself will produce false positives (expected -- it contains the pattern definitions).
- This is a **first line of defense**. Human review of findings is recommended.

## License

MIT
