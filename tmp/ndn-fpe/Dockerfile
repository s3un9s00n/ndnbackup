FROM ubuntu:20.04
LABEL maintainer "Peter Gusev <peter@remap.ucla.edu>"
ARG VERSION_CXX=master
ARG VERSION_NFD=master
ARG DEBIAN_FRONTEND=noninteractive

workdir /usr/src/app
copy github_ndn-cxx /usr/src/app

# install tools
RUN  apt-get update \
     && apt-get install -y net-tools git curl wget build-essential

# install ndn-cxx and NFD dependencies
RUN apt-get install -y pkg-config python3-minimal libboost-all-dev libssl-dev \
    && apt-get install -y doxygen graphviz python3-pip python3-sphinx software-properties-common libsqlite3-dev libboost-all-dev libpcap-dev \
    && apt-get install -y libpcap-dev libsystemd-dev valgrind libwebsocketpp-dev

# install ndn-cxx
# RUN git clone https://github.com/named-data/ndn-cxx.git /usr/src/app \
#     && cd ndn-cxx \
#     && git checkout $VERSION_CXX \
#     && ./waf configure \
#     && ./waf \
#     && ./waf install \
#     && cd .. \
#     && rm -Rf ndn-cxx \
#     && ldconfig
RUN cd github_ndn-cxx \
    && ./waf configure \
    && ./waf \
    && ./waf install \
    && cd .. \
    && ldconfig

# install NFD
RUN git clone --recursive https://github.com/named-data/NFD /usr/src/app/github_NFD \
    && cd NFD \
    && git checkout $VERSION_NFD \
    && ./waf configure \
    && ./waf \
    && ./waf install \
    && cd .. \
    # && rm -Rf NFD

# install ndn-tools
RUN git clone --recursive https://github.com/named-data/ndn-tools.git /usr/src/app/github_ndn-tools \
    && cd ndn-tools \
    && ./waf configure \
    && ./waf \
    && ./waf install \
    && cd .. \
    # && rm -Rf ndn-tools

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
    && apt-get remove -y git build-essential pkg-config

EXPOSE 6363/tcp
EXPOSE 6363/udp

ENV CONFIG=/usr/local/etc/ndn/nfd.conf
ENV LOG_FILE=/logs/nfd.log

CMD /usr/local/bin/nfd -c $CONFIG > $LOG_FILE 2>&1