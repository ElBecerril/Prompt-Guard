# Contributing to Prompt Guard

Thanks for your interest in contributing! This project is open to anyone who wants to help improve prompt injection detection.

## How to contribute

### Reporting bugs

Open an [issue](../../issues) using the **Bug Report** template. Include:
- Steps to reproduce
- Expected vs actual behavior
- Python version and OS

### Suggesting new patterns

If you've found a prompt injection technique that Prompt Guard doesn't catch:
1. Open an issue with the **Feature Request** template
2. Include example text that should be detected
3. Suggest the severity level (critical/high/medium/low)

### Submitting Pull Requests

1. Fork the repo
2. Create a branch from `main`: `git checkout -b my-feature`
3. Make your changes
4. Test locally: `python prompt_guard.py ./test-directory`
5. Open a PR with a clear description of what you changed and why

### Adding detection patterns

Patterns live in `prompt_guard.py` inside the `PATTERNS` dict. Each entry has:
```python
(r"regex_pattern", "unique_name", "Human-readable description")
```

Guidelines:
- Use `re.IGNORECASE` (applied automatically)
- Keep regexes readable; add comments if complex
- Avoid overly broad patterns that cause false positives
- Include patterns in both English and Spanish when applicable
- Place the pattern in the correct severity level

### Code style

- Follow PEP 8
- Use type hints where possible
- Keep functions focused and well-documented
- Test your changes against repos with known benign content to check for false positives

## Severity levels

| Level | Score | Use for |
|---|---|---|
| **critical** | 10 | Credential exfiltration, system prompt override, prompt reveal |
| **high** | 8 | Jailbreaks, impersonation, code execution |
| **medium** | 5 | Subtle manipulation, hidden HTML/scripts |
| **low** | 2 | Secrecy indicators, ambiguous patterns |

## Questions?

Open an issue with your question. All contributions and feedback are welcome.
