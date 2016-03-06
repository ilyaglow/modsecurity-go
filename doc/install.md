# install libmodsecurity

## CentOS 7 

install requisites
```
yum install gcc-c++ flex bison curl-devel curl yajl yajl-devel GeoIP-devel doxygen pcre-devel libxml2-devel
```

install bison 3

```
wget http://ftp.gnu.org/gnu/bison/bison-3.0.4.tar.gz
tar xf bison-3.0.4.tar.gz
cd bison-3.0.4
./configure --prefix=/usr/local
make && make install
```

clone ModSecurity project
```
git clone https://github.com/SpiderLabs/ModSecurity 
```

checkout libmodsecurity branch
```
git checkout libmodsecurity
```

install submodules 

```
git submodule init
git submodule update
```

build it
```
sh build.sh
./configure
PATH=/usr/local/bin:$PATH make && make install
```

install modsecurity go middleware

go get github.com/senghoo/modsecurity-go/modsecurity
