"""Allow running as `python -m med9tool`."""
from med9tool.cli import main
import sys
sys.exit(main())
