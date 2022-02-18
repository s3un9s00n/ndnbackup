FROM ubuntu:18.04
LABEL maintainer "Peter Gusev <peter@remap.ucla.edu>"
ARG VERSION_CXX=master
ARG VERSION_NFD=master
ENV DEBIAN_FRONTEND=noninteractive

ARG workdir=/tmp/src/app
WORKDIR $workdir

RUN mkdir -p  $workdir/.local/bin
RUN export PATH="$workdir/.local/bin${PATH:+:}${PATH}"

# install tools
RUN  apt-get update \
     && apt-get install -y vim net-tools git build-essential

# install ndn-cxx and NFD dependencies
RUN apt-get install -y libsqlite3-dev pkg-config libssl-dev libpcap-dev
RUN apt-get install -y python3-minimal libboost-all-dev libssl-dev
RUN apt-get install -y doxygen graphviz python3-pip python3-sphinx software-properties-common

# install ndn-cxx
RUN git clone https://github.com/named-data/ndn-cxx.git \
    && cd ndn-cxx \
    && git checkout $VERSION_CXX \
    && ./waf configure \
    && ./waf \
    && ./waf install \
    && cd .. \
    && rm -Rf ndn-cxx \
    && ldconfig \
    && echo /usr/local/lib | tee /etc/ld.so.conf.d/ndn-cxx.conf \
    && export LD_LIBRARY_PATH=/usr/local/lib

# install NFD
RUN git clone --recursive https://github.com/named-data/NFD \
    && cd NFD \
    && git checkout $VERSION_NFD \
    && ./waf configure \
    && ./waf \
    && ./waf install \
    && cd .. \
    && rm -Rf NFD

# install ndn-tools
RUN git clone --recursive https://github.com/named-data/ndn-tools.git \
    && cd ndn-tools \
    && ./waf configure \
    && ./waf \
    && ./waf install \
    && cd .. \
    && rm -Rf ndn-tools

# initial configuration
RUN cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf \
    && ndnsec-keygen /`whoami` | ndnsec-install-cert - \
    && mkdir -p /usr/local/etc/ndn/keys \
    && ndnsec-cert-dump -i /`whoami` > default.ndncert \
    && mv default.ndncert /usr/local/etc/ndn/keys/default.ndncert

RUN mkdir /share \
    && mkdir /logs

# cleanup
# RUN apt autoremove \
#    && apt-get remove -y git build-essential python pkg-config

EXPOSE 6363/tcp
EXPOSE 6363/udp

ENV CONFIG=/usr/local/etc/ndn/nfd.conf
ENV LOG_FILE=/logs/nfd.log

CMD /usr/local/bin/nfd -c $CONFIG > $LOG_FILE 2>&1
