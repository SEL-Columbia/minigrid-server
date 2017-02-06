#!/usr/bin/env sh
set -e
bash -c "psql -d minigrid -c 'drop schema if exists minigrid_test cascade;' -U postgres 1&>/dev/null"
coverage erase
coverage run --source=minigrid,server.py --branch -m unittest ${@:-discover tests.python}
coverage html
coverage report -m
