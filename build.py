#!/usr/bin/env python3
"""Build script to generate PromptGuard.exe using PyInstaller.

Usage:
    pip install pyinstaller
    python build.py
"""

import PyInstaller.__main__

PyInstaller.__main__.run([
    "prompt_guard.py",
    "--onefile",
    "--console",
    "--name", "PromptGuard",
])
