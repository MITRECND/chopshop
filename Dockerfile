FROM debian:jessie-slim

COPY . /tmp/chopshop
ADD https://bootstrap.pypa.io/get-pip.py /tmp/get-pip.py

RUN buildDeps='apt-utils \
               libpcap-dev \
               autoconf \
               automake \
               build-essential \
               git-core \
               libmagic-dev \
               libpcre3-dev \
               libssl-dev \
               python-dev' \
 && apt-get -q update \
 && apt-get install -yq $buildDeps \
                        ca-certificates \
                        libpcap0.8 \
                        libpcre3 \
                        libtool \
                        swig \
                        python \
                        yara --no-install-recommends \
                        libemu-dev \
 && python /tmp/get-pip.py \
 && git clone --recursive https://github.com/MITRECND/pynids /tmp/pynids \
 && git clone --recursive https://github.com/MITRECND/htpy /tmp/htpy \
 && git clone https://github.com/MITRECND/yaraprocessor.git /tmp/yaraprocessor \
 && pip install --no-cache-dir \
                yara \
                m2crypto \
                pymongo \
                pycrypto \
                dnslib \
                pylibemu \
                hpack \
                /tmp/pynids \
                /tmp/htpy \
                /tmp/yaraprocessor \
                /tmp/chopshop \
 && apt-get autoremove --purge -y $buildDeps \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

VOLUME ["/pcap"]
WORKDIR /pcap

ENTRYPOINT ["/usr/local/bin/chopshop"]

CMD ["-h"]
