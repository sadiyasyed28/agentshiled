"""
Vercel entrypoint for AgentShield FastAPI backend.
"""

import os
from pathlib import Path
import sys

# Add src to sys.path so agentshield package is discoverable
root_path = Path(__file__).resolve().parent.parent
src_path = root_path / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

cwd_src = Path(os.getcwd()) / "src"
if str(cwd_src) not in sys.path:
    sys.path.insert(0, str(cwd_src))

from agentshield.api.app import app

# Explicit top-level assignment for Vercel AST scanner
app = app
