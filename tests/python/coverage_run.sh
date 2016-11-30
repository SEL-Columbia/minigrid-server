#!/usr/bin/env sh
set -e
coverage erase
coverage run --source=minigrid,server.py --branch -m unittest ${@-discover tests.python}
coverage html
coverage report -m
