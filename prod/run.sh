#!/usr/bin/env sh
python server.py \
  --log-file-prefix=log/minigrid.log \
  --log-rotate-mode=time \
  --minigrid_website_url=https://www.example.com \
  $@
