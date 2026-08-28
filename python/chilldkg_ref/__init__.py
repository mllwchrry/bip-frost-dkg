import sys
from pathlib import Path

__all__ = ["chilldkg"]

# Prefer the vendored copy of ed25519lab.
sys.path.insert(0, str(Path(__file__).parent / "../ed25519lab/src"))
