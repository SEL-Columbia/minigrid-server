#!/usr/bin/env sh
python server.py \
  --application_debug=True \
  --minigrid_https=False \
  $@
