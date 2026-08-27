import sys
from pathlib import Path

# Ensure ed25519lab is found and can be imported directly, so that
# `python3 -m unittest` works in a fresh clone with nothing installed.
sys.path.insert(0, str(Path(__file__).parent / "../src/"))
