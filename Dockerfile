from ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

# Standard 64-bit packages
RUN apt-get update && apt-get -y -qq install build-essential \
                                             cmake \
                                             wget \
                                             git \
                                             vim \
                                             emacs \
                                             iputils-ping \
                                             sudo

RUN useradd -m docker && echo "docker:docker" | chpasswd && adduser docker sudo
ENV HOME /home/docker
WORKDIR $HOME

ENV OPENSSL_INSTALL "$HOME/openssl-1.0.2r_install"
RUN wget https://www.openssl.org/source/openssl-1.0.2r.tar.gz && tar -xf openssl-1.0.2r.tar.gz
RUN cd openssl-1.0.2r && ./config -fPIC --prefix=$OPENSSL_INSTALL && make clean && make depend && make && make install

ENV CURL_INSTALL "$HOME/curl-7.64.0_install"
RUN wget https://curl.haxx.se/download/curl-7.64.0.tar.gz && tar -xf curl-7.64.0.tar.gz
RUN cd curl-7.64.0 && ./configure --prefix=$CURL_INSTALL --with-ssl=$OPENSSL_INSTALL && make && make install

ENV BORINGSSL_ROOT "$HOME/boringssl"
RUN git clone https://github.com/google/boringssl.git && wget https://dl.google.com/go/go1.12.1.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.12.1.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
RUN cd $BORINGSSL_ROOT && mkdir build && cd build && cmake -DBUILD_SHARED_LIBS=1 .. && make
RUN cd $BORINGSSL_ROOT && mkdir lib && cd lib && cp ../build/crypto/libcrypto.so . && cp ../build/ssl/libssl.so .

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$BORINGSSL_ROOT/lib:$CURL_INSTALL/lib

USER docker
CMD ["/bin/bash"]

