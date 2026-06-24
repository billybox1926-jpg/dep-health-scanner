import sys
from pathlib import Path

# Ensure src layout works without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dep_health_scanner.cli import main

if __name__ == "__main__":
    main()
