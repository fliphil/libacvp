# Libacvp Client (BoringSSL Crypto Module)

This guide will go over how use Libacvp to test BoringSSL as the cryptography provider. The environment with required dependencies will need to be setup by the developer. The developer can either follow the provided Docker instructions or use the next section to manually install all dependencies.

## Docker

Inside the fliphil/libacvp repo on branch aes-gcm-siv you will find a Dockerfile at the root directory. A Docker image can be built using this file, and then the developer will mount the libacvp/ directory as a volume. Mounting the libacvp/ directory will ensure that any code changes made within the container do not disappear when the container is terminated. The Docker container will have Vim and Emacs installed by default… of course the developer can add packages to the container as needed within the Dockerfile!

```
git clone https://github.com/fliphil/libacvp.git
cd libacvp && git checkout aes-gcm-siv
docker build -t libacvp_w_boringssl .
docker run -v $(pwd):/home/docker/libacvp --user $(id -u) -it libacvp_w_boringssl
```

**Note:** The sudo password inside the running container is “docker”.

You can now skip ahead to [Building Libacvp](#building-libacvp)

## Manually

This is more intensive, as the developer will need to manually setup the proper environment with dependencies.

#### Install OpenSSL

Since BoringSSL and OpenSSL both have the same .so filenames, we must build OpenSSL as a static library. Otherwise, the LD_LIBRARY_PATH would get confused and only resolve to the first instance of each libcrypto/libssl that we need.

```
wget https://github.com/openssl/openssl/archive/OpenSSL_1_0_2r.tar.gz
tar -xvf OpenSSL_1_0_2r.tar.gz
cd OpenSSL_1_0_2r
./config -fPIC --prefix=<OPENSSL_INSTALL>
make clean && make depend
make && make install
```

#### Install Curl

```
wget https://github.com/curl/curl/releases/download/curl-7_64_0/curl-7.64.0.tar.gz
tar -xvf curl-7.64.0.tar.gz
cd curl-7.64.0
./configure --prefix=<CURL_INSTALL> --with-ssl=<OPENSSL_INSTALL>
make && make install
```

#### Install BoringSSL

This will be the crypto module linked and tested by the example application (app/). It is **not** used to build either libacvp or any other components. 

**NOTE:** Building BoringSSL requires that GoLang is installed and accessible on the system… instructions here: https://golang.org/doc/install#install

```
git clone https://github.com/google/boringssl.git
cd boringssl && export BORINGSSL_ROOT=$(pwd)
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=1 ..
make
cd ../
mkdir lib && cd lib
cp ../build/crypto/libcrypto.so .
cp ../build/ssl/libssl.so .
```

#### Download Libacvp

Download the Libacvp repository.

```
git clone https://github.com/fliphil/libacvp.git
cd libacvp && git checkout aes-gcm-siv
```

## Building Libacvp

Now we will build both libacvp and the example application. Libacvp will be linked against the $CURL_INSTALL which is needed for data transport operations. The example application will be linked against the crypto module located at $BORINGSSL_ROOT.

```
./configure --with-ssl-dir=<BORINGSSL_ROOT> --with-libcurl-dir=<CURL_INSTALL>
make
```

Here's an example of how to build with debug symbols:

```
CFLAGS="-O0 -g" ./configure --with-ssl-dir=<BORINGSSL_ROOT> --with-libcurl-dir=<CURL_INSTALL>
make
```

## Environment Variables

There are a few environment variables that need to be set for the acvp_app application to work.

```
export ACV_SERVER="<Get from Hackathon Champion>"
export ACV_PORT="443"
export ACV_URI_PREFIX="acvp/v1/"
export ACV_API_CONTEXT="acvp/"
```

**NOTE:** Setting the LD_LIBRARY_PATH is already done in the Docker container. You only need to do this is you followed the “Manually” section.

`export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$BORINGSSL_ROOT/lib:$CURL_INSTALL/lib`

## Run the application

Now to simply kick off the application, execute the binary!

`./app/acvp_app`
