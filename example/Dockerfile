FROM golang

RUN apt-get update && apt-get install -y automake bison build-essential \
	g++ gcc libbison-dev libcurl4-openssl-dev libfl-dev libgeoip-dev \
	liblmdb-dev libpcre3-dev libtool libxml2-dev libyajl-dev make \
	pkg-config zlib1g-dev

RUN git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity /tmp/modsecurity

WORKDIR /tmp/modsecurity

RUN git submodule init && git submodule update
RUN ./build.sh && ./configure && make && make install

ENV LD_LIBRARY_PATH /usr/local/modsecurity/lib:$LD_LIBRARY_PATH
