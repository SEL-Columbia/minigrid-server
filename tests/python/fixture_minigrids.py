#!/usr/bin/env python
"""Minigrids fixture"""
import os
import sys

sys.path.insert(1, os.path.join(sys.path[0], '../..'))


def main():
    from minigrid.options import parse_command_line
    parse_command_line(sys.argv)
    from minigrid import models
    # TODO: create minigrid models
    print(models)


if __name__ == '__main__':
    main()
