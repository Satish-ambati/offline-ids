import os
import sys
import tempfile
from pathlib import Path

os.environ["IDS_DATA_DIR"] = tempfile.mkdtemp(prefix="ids-test-")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "security-engine"))
