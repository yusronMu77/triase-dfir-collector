"""PyInstaller entry. A frozen script has no package context, so import the package explicitly."""

from astria_collector.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
