#!/bin/bash

# installs the open source scanner tool trivy

apt-get update
CODE_NAME="focal"
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - || exit 4
echo deb https://aquasecurity.github.io/trivy-repo/deb $CODE_NAME main | tee -a /etc/apt/sources.list.d/trivy.list || exit 4
apt-get update && apt-get install trivy -y
