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

### Interactive Mode (recommended for beginners)

Just run without arguments — or double-click the `.exe`:

```bash
python prompt_guard.py
```

You'll see a menu where you can:
1. **Scan a folder or GitHub repo** — paste a local path or URL
2. **Analyze a text/prompt** — paste suspicious text directly to check it

### CLI Mode (advanced)

```bash
# Scan a local folder
python prompt_guard.py ./my-repo

# Scan a GitHub repo
python prompt_guard.py https://github.com/user/repo

# With options
python prompt_guard.py ./my-repo --output report.json --verbose
```

## Standalone Executable (.exe)

Build a portable executable that works without Python installed:

```bash
pip install pyinstaller
python build.py
```

The generated `dist/PromptGuard.exe` can be distributed and run with a double-click.

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
  -x, --exclude LIST     Comma-separated files/dirs to exclude
```

### Default extensions

`.md` `.txt` `.json` `.yaml` `.yml` `.py` `.html` `.htm` `.xml` `.csv` `.rst` `.toml` `.ini` `.cfg` `.conf` `.js` `.ts` `.jsx` `.tsx` `.sh` `.bat` `.ps1`

### Skipped directories

`.git` `node_modules` `__pycache__` `.venv` `venv` `.tox` `.mypy_cache` `.pytest_cache` `dist` `build`

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
  ____                            _      ____                     _
 |  _ \ _ __ ___  _ __ ___  _ __ | |_   / ___|_   _  __ _ _ __ __| |
 | |_) | '__/ _ \| '_ ` _ \| '_ \| __| | |  _| | | |/ _` | '__/ _` |
 |  __/| | | (_) | | | | | | |_) | |_  | |_| | |_| | (_| | | | (_| |
 |_|   |_|  \___/|_| |_| |_| .__/ \__|  \____|\__,_|\__,_|_|  \__,_|
                             |_|

  First line of defense against prompt injection attacks
  by EL_Bcerril

Scanning: ./my-repo
Extensions: .json, .md, .py, .txt, .yaml, .yml
Max file size: 1.0MB
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

## Architecture

The scanner is organized in 5 internal modules within a single file:

| Module | Responsibility |
|---|---|
| **Direct Pattern Scanner** | Regex-based detection across 4 severity tiers |
| **Steganographic Analysis** | Acrostics, diagonals, base64, zero-width chars, homoglyphs, hidden comments |
| **Input Sources** | Local directory traversal and GitHub shallow clone |
| **Scoring & Reporting** | 0-100 scoring, classification, JSON report generation |
| **CLI & Interactive** | Argument parsing, interactive menu, colored output |

## Running Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## Known Limitations

- Scanning `prompt_guard.py` itself will produce false positives (expected -- it contains the pattern definitions).
- Patterns like `subprocess` and `eval()` may flag legitimate code. Always review findings manually.
- No parallel file scanning yet. Large repos are scanned sequentially.
- This is a **first line of defense**. It analyzes text content only and does not execute code. Human review of findings is always recommended.

## License

MIT
