"""Enable `python3 -m log_analyzer` with the CLI's documented exit status."""
from .cli import main

raise SystemExit(main())
