#!/usr/bin/env bash
set -euo pipefail
python -m pip install -e '.[browser,devtools]'
python -m playwright install --with-deps chromium
python -m unittest discover -s tests -v
