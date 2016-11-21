#!/usr/bin/env sh
python server.py \
  --application_debug=True \
  --minigrid_https=False \
  --db_schema=minigrid_dev \
  $@
