#!/usr/bin/env sh
set -e
coverage erase
coverage run --source=demo,demonstration.py --branch -m unittest ${@-discover tests}
coverage html
coverage report -m
