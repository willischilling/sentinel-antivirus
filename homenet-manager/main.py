"""Home Network Manager — entry point.

Normal run:      python main.py           (opens the window)
Admin helper:    python main.py --elevated <result-file> <action> <args...>
                 (launched by the app itself through the Windows admin prompt;
                  not meant to be run by hand)
"""
import sys

from homenet import elevate


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == elevate.FLAG:
        return elevate.main(sys.argv[2:])
    from homenet import ui
    ui.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
