import logging
import sys

import dfw.listener as listener


def main():
    logging.basicConfig(level=logging.INFO)
    listener.listen()


if __name__ == '__main__':
    sys.exit(main())
