#!/bin/bash
set -x
make
systemctl stop crio
mv bin/crio /usr/local/bin/crio
systemctl start crio
