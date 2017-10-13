FROM debian:jessie

#Special thanks to blacktop for creating this docker config https://github.com/blacktop
MAINTAINER mitrecnd, https://github.com/mitrecnd

# Copy source code to tmp folder
COPY . /tmp
RUN chmod -R 755 /tmp

# Install ChopShop Required Dependencies
RUN buildDeps='apt-utils \
                autoconf \
                automake \
                build-essential \
                git-core \
                libemu-dev \
                libmagic-dev \
                libpcre3-dev \
                libssl-dev \
                python-dev \
                python-setuptools' \
  && set -x \
  && echo "[INFO] Installing Dependancies..." \
  && apt-get -q update \
  && apt-get install -y $buildDeps \
                        ca-certificates \
                        libpcap-dev \
                        libpcre3 \
                        libtool \
                        python \
                        python-yara \
                        swig \
                        python-m2crypto \
                        yara --no-install-recommends \
                        libemu-dev \
  && easy_install pymongo \
                  pycrypto \
                  dnslib \
                  pylibemu \
                  hpack \
  && echo "[INFO] Installing Modules..." \
  && cd /tmp \
  && docker/install/pynids.sh \
  && docker/install/htpy.sh \
  && docker/install/yaraprocessor.sh \
  && echo "[INFO] Installing ChopShop..." \
  && make \
  && make install \
  && echo "[INFO] Remove Build Dependancies..." \
  && apt-get autoremove --purge -y $buildDeps \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

VOLUME ["/pcap"]
WORKDIR /pcap

ENTRYPOINT ["/usr/local/bin/chopshop"]

CMD ["-h"]
