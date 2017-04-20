#!/usr/bin/env sh
echo "Installing dependencies..."
pip install -r requirements.txt 1&> /dev/null
npm install
echo "Installing dependencies done"
python server.py \
  --application_debug=True \
  --minigrid_https=False \
  --db_schema=minigrid_dev \
  $@
