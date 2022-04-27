#!/bin/bash

# installs the ed reporter helper

cd /tmp && git clone -b master https://github.com/elasticdev/host_reporter_helper.git
cd host_reporter_helper || exit 4
./reinstall_pkg_dev.sh || exit 5
cd /tmp && rm -rf host_reporter_helper

