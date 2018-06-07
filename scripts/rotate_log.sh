#!/bin/sh

set -eux

if sudo [ -e $1 ]; then
  sudo mv $1 ${1%.*}_$(date +"%Y%m%d%H%M%S").${1##*.}
fi
