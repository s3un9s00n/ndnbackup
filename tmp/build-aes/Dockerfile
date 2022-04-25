FROM ubuntu:20.04
LABEL maintainer "Peter Gusev <peter@remap.ucla.edu>"
ARG VERSION_CXX=master
ARG VERSION_NFD=master
ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /usr/src/app
COPY . /usr/src/app

# install tools
RUN  apt-get update \
     && apt-get install -y net-tools git curl wget build-essential

# install Python v3.9.12
RUN chmod 777 python3.9-dev.sh \
    && /usr/src/app/python3.9-dev.sh

# install ndn-cxx and NFD dependencies
RUN apt-get install -y pkg-config libboost-all-dev libssl-dev \
    && apt-get install -y doxygen graphviz python3-pip python3-sphinx software-properties-common libsqlite3-dev libboost-all-dev libpcap-dev \
    && apt-get install -y libpcap-dev libsystemd-dev valgrind libwebsocketpp-dev

# install ndn-cxx
RUN chmod -R 777 /usr/src/app/github_ndn-cxx \
    && cd /usr/src/app/github_ndn-cxx \
    && ./waf configure --with-examples \
    && ./waf \
    && ./waf install \
    && ldconfig \
    && cd ..

# install NFD
RUN chmod -R 777 /usr/src/app/github_NFD \
    && cd /usr/src/app/github_NFD \
    && ./waf configure \
    && ./waf \
    && ./waf install \
    && cd ..

# install ndn-tools
RUN chmod -R 777 /usr/src/app/github_ndn-tools \
    && cd /usr/src/app/github_ndn-tools \
    && ./waf configure \
    && ./waf \
    && ./waf install \
    && cd ..

# NDN Traffic Generator
RUN chmod -R 777 /usr/src/app/github_ndn-traffic-generator \
    && cd /usr/src/app/github_ndn-traffic-generator \
    && ./waf configure \
    && ./waf \
    && ./waf install \
    && cd ..

# initial configuration
RUN cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf \
    && ndnsec-keygen /`whoami` | ndnsec-install-cert - \
    && mkdir -p /usr/local/etc/ndn/keys \
    && ndnsec-cert-dump -i /`whoami` > default.ndncert \
    && mv default.ndncert /usr/local/etc/ndn/keys/default.ndncert

RUN mkdir /share \
    && mkdir /logs

RUN chmod -R 777 /usr/src/app/github_python-ndn \
    && python3.9 -m pip install pycryptodomex \
    && python3.9 -m pip install pycryptodome \
    && python3.9 -m pip install ff3 \
    && python3.9 -m pip install python-ndn \
    && python3.9 -m pip install opencv-python \
    && python3.9 -m pip install numpy \
    && python3.9 -m pip install pillow


EXPOSE 6363/tcp
EXPOSE 6363/udp

ENV CONFIG=/usr/local/etc/ndn/nfd.conf
ENV LOG_FILE=/logs/nfd.log

CMD /usr/local/bin/nfd -c $CONFIG > $LOG_FILE 2>&1