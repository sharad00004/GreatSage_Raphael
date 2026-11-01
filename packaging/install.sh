#!/bin/sh
set -eu
release_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$release_dir/app/GreatSage_Raphael" --install "$@"
