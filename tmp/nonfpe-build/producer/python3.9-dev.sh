#!/bin/bash

echo APT package update
apt update 

echo Dependency package install 
echo ==============1==============
apt install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev

echo Python v3.9.12 install 
echo ==============2==============
cd /opt
pwd
wget https://www.python.org/ftp/python/3.9.12/Python-3.9.12.tgz
tar -xf Python-3.9.12.tgz
cd Python-3.9.12
./configure --enable-optimizations

echo Python v3.9.12 build process start
echo ==============3==============
make -j 12

echo Python v3.9.12 install 
echo ==============4=============
make altinstall

echo Done...
python3.9 --version