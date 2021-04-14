#!/bin/sh

# stop on error
set -e

# show commands
set -x

echo The server corresponds to tap0 and HW_ADDR_5=0x01 and IP addr 192.168.1.3

# Create network interfaces
sudo ./contrib/ports/unix/setup-tapif

# Delete executable to be sure it will be built again
rm -f ./build/contrib/ports/unix/example_app/example_app

cd build
cmake . -DCLIENT_OR_SERVER=SERVER; cmake --build .
cd ..


# launch app
# (maybe launch "cmake ." and "make" if changes occurred)
sudo ./build/contrib/ports/unix/example_app/example_app

# grep -r "hard-coded" to find where the bpf file was hard-coded.
# ./contrib/ports/unix/example_app/CMakeLists.txt and ./src/Filelists.cmake -> useful
