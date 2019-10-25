#!/bin/bash

# update repositories
apt update

# install debian packages
# note that curling python requires https proxy to use http
apt install -y virtualenv make build-essential libssl-dev zlib1g-dev libbz2-dev \
libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
xz-utils tk-dev libffi-dev liblzma-dev

# compile python
curl -O https://www.python.org/ftp/python/3.8.0/Python-3.8.0.tar.xz
tar -xvf Python-3.8.0.tar.xz
cd Python-3.8.0
./configure --enable-optimizations --with-ensurepip=install
make -j2
make altinstall

# set up virtual environment
virtualenv --python=python3.8 env
. env/bin/activate

# install python packages
pip3 install -r requirements.txt

