#!/bin/bash

echo "[*] Running"
mkdir -p /tmp/src/app
apt-get update

sleep 1

echo "[*] ==============================Install Dependency Packages==================================="
apt-get install -y vim net-tools git curl wget unzip && \
    apt-get install -y build-essential pkg-config python3-minimal libboost-all-dev libssl-dev && \
    apt-get install -y libsqlite3-dev doxygen graphviz python3-pip python3-sphinx software-properties-common
echo "[*] =================================Install Dependency Packages Done...=================================="

sleep 1

echo "[*] =================================Settings Dependency Packages==================================+"
mkdir -p /tmp/src/app/.local/bin
export PATH="/tmp/src/app/.local/bin${PATH:+:}${PATH}"
echo "[*] =================================Settings Dependency Packages Done...=================================="

sleep 1

echo "[*] =================================Download NDN OpenSource from Github=================================="
git clone https://github.com/named-data/ndn-cxx.git
git clone https://github.com/named-data/NFD.git

mv ndn-cxx /tmp/src/app
mv NFD /tmp/src/app
ls -al /tmp/src/app

chmod 755 -R /tmp/src/app/ndn-cxx
chmod 755 -R /tmp/src/app/NFD
echo "[*] =================================Download NDN OpenSource from Github Done...=================================="

sleep 1

echo "[*] =================================Build NDN-CXX=================================="
cd /tmp/src/app/ndn-cxx && \
    ./waf configure --enable-static && \
    ./waf && \
    ./waf install && \
    cd /tmp/src/app
echo /usr/local/lib | tee /etc/ld.so.conf.d/ndn-cxx.conf
export LD_LIBRARY_PATH=/usr/local/lib

echo "[*] =================================Build NDN-CXX Done...=================================₩="

sleep 1

echo "[*] =================================Build NFD=================================="
add-apt-repository ppa:named-data/ppa && apt-get install -y libpcap-dev libsystemd-dev valgrind libwebsocketpp-dev
cd /tmp/src/app/NFD && \
    git submodule update --init && \
    mkdir -p /websocketpp && \
    curl -L https://github.com/cawka/websocketpp/archive/0.8.1-hotfix.tar.gz > websocketpp.tar.gz && \
    tar xf websocketpp.tar.gz -C /websocketpp --strip 1

cd /tmp/src/app/NFD && \
    ./waf configure && \
    ./waf && \
    ./waf install && \
    cd /tmp/src/app
echo "[*] =================================Build NFD Done...=================================="

cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf

sleep 1

echo "[*] =================================All Done...=================================="