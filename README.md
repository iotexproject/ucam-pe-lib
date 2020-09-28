# UCam client firmware

This is UCam library that is called by GoKE Camera main firmware to :
* Encrypt snapshot provided by GoKe main firmware.
* Upload encrypted snapshot to AWS S3 cloud server.
* Encrypt video stream frame by frame.
* Upload encrypted video frame file.

## Platform

This library is build on GOKE SDK on linux(Ubuntu) platform.
GOKE SDK is assumed to be installed before next steps.

## install GOKE SDK
Change `Config.mak` to
```
# diff Config.mak Config.mak.old
41c41
<   DECODER ?= GK710XS
---
>   DECODER ?= GK710X
97c97
<   SDK_TOP    ?=/path/to/GK710X_LinuxSDK_v2.1.0
---
>   SDK_TOP    ?=
```
use `make deploy` to make and deploy sdk in system

then
```
source env/build_env.sh
```

## Build
This project is build as an sample project under GOKE SDK.

The following steps assume the SDK is installed on ~/GK710X_LinuxSDK_v2.1.0.

```
$ cd ~/GK710X_LinuxSDK_v2.1.0/applications/sample/
$ git clone git@github.com:iotexproject/UCamClient.git
$ cd UCamClient
$ make
```
The executable binary could be found in
```
$ ls ./bin/
cloudrecord
```
User have to deploy the binary to camera to run. The next section describes one way to deploy the binary.


## Deploy and run

The linux in Camera supports two way/commands to download binary from outside: tftp or wget.
This section describes the 'wget' way i.e, setting up a simple http server to enable wget the binary from the server.
User could choose to set up tftp server as well.

### Set up http server
One simple way to set up a http server is to use python build-in web server SimpleHTTPServer.

```
$ mkdir ~/shared
$ cd ~/shared
$ python -m SimpleHTTPServer 8000 &
```
So a web service is started at port 8000 on the hosting server with folder ~/shared be accessible from client.

Copy the binary to the server.
```
$ cp ./bin/cloudrecord ~/shared/
```

### Login the Camera and download the binary
The camera support telnet login. So the user has to learn the camera's IP address by, for example, checking the router's connected devices' ip.

```bash
$ telnet 192.168.31.146
Trying 192.168.31.146...
Connected to 192.168.31.146.


goke login: root
Password: ******
#
```
The camera only reserves directory /rom for storing executable binary.
Download the binary form http server (192.168.31.210) to /rom
```
# cd /rom
# wget http://192.168.31.210:8000/cloudrecord
# chmod 777 cloudrecord
```

### Download test vector to run
The cloudrecord uses the test vector from a real camera clip(test.pes) , which is also provided in  ./testvectors directory. Copy it to ~/shared, and download it to camera /tmp, where it will be loaded by cloudrecord.

```
cd /tmp
# wget http://192.168.31.210:8000/test.pes
```

### run the binary
```
#cd /rom
#./cloudrecord
```

## Release with static library
This repo is only for internal use. To release a static library:
```
# make release
```
So a static library libioecr.a (along with libioecr.h) will be created and copy to ./release directory.

libioecr.a and libioecr.h is the minimal release set to GOKE.

It is minimal because the libcloudrecord.a is not enough to build. It depends on 'libcurl' and 'libmbedtls' as well. However, if GoKo have already set up libcurl and libmbedtls, it is good enough to update only libcloudrecord.a.

The dependencies are in ./libs.

## DEBUG on camera
```
icatlog -li
icatlog septutkapp -li
```

## DEV on MAC

### Build

1. run
```
./mac_make.sh
```
2. get `.pem` file from other people and put into current directory.

### Run
Get a pem file from others. Then run
```
./mac_run.sh
```
