"""Entry point for the SOC Alert Triage & Enrichment Tool.

Usage
-----
    python main.py

The window opens with the bundled sample alerts (``samples/sample_alerts.csv``)
pre-loaded so you can immediately try the Enrich, Triage, and Report
features without needing to bring your own data.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on sys.path so `from utils...` etc. resolve
# regardless of where the script is launched from.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Set up logging as early as possible.
from utils.logger import setup_logging, get_logger  # noqa: E402

setup_logging()
logger = get_logger("main")


def main() -> int:
    """Launch the SOC Triage Tool GUI."""
    try:
        # Defer the import so that logging is configured first.
        from gui.main_window import MainWindow

        logger.info("=== SOC Triage Tool starting ===")
        app = MainWindow()
        app.build()
        app.run()
        logger.info("=== SOC Triage Tool shutting down ===")
        return 0
    except Exception:
        logger.exception("Fatal error in main().")
        # Try to show a GUI error before exiting.
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "SOC Triage Tool — Fatal Error",
                "An unexpected error occurred. See logs/soc_tool.log for details.",
            )
            root.destroy()
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
