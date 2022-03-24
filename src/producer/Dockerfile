FROM ubuntu:18.04
LABEL maintainer "Peter Gusev <peter@remap.ucla.edu>"
ARG VERSION_CXX=master
ARG VERSION_NFD=master
ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /usr/src/app
COPY . /usr/src/app

# install tools
RUN  apt-get update \
     && apt-get install -y net-tools git curl wget build-essential

# install ndn-cxx and NFD dependencies
RUN apt-get install -y pkg-config python3-minimal libboost-all-dev libssl-dev \
    && apt-get install -y doxygen graphviz python3-pip python3-sphinx software-properties-common libsqlite3-dev libboost-all-dev libpcap-dev \
    && apt-get install -y libpcap-dev libsystemd-dev valgrind libwebsocketpp-dev

# install ndn-cxx
RUN chmod -R 777 /usr/src/app/github_ndn-cxx \
    && cd /usr/src/app/github_ndn-cxx \
    && ./waf configure \
    && ./waf \
    && ./waf install \
    && cd .. \
    && ldconfig

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

RUN pip3 install python-ndn

# initial configuration
RUN cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf \
    && ndnsec-keygen /`whoami` | ndnsec-install-cert - \
    && mkdir -p /usr/local/etc/ndn/keys \
    && ndnsec-cert-dump -i /`whoami` > default.ndncert \
    && mv default.ndncert /usr/local/etc/ndn/keys/default.ndncert

RUN mkdir /share \
    && mkdir /logs

# cleanup
RUN apt autoremove \
    && apt-get remove -y git build-essential python pkg-config

EXPOSE 6363/tcp
EXPOSE 6363/udp

ENV CONFIG=/usr/local/etc/ndn/nfd.conf
ENV LOG_FILE=/logs/nfd.log

CMD /usr/local/bin/nfd -c $CONFIG > $LOG_FILE 2>&1