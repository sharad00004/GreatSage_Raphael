#!/bin/sh
set -eu
install_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$install_dir/app/GreatSage_Raphael" --uninstall "$@"
