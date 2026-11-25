"""Keep ``python -m integritywatch`` working for existing users."""
from forace.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
