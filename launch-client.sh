#!/bin/sh

# stop on error
set -e

# show commands used
set -x

echo The client corresponds to tap1 and HW_ADDR_5=0x88 and IP addr 192.168.1.4

# Create network interfaces if not already done
if !(ifconfig | grep -q "tap0") || !(ifconfig | grep -q "tap1"); then
  echo "Creating interfaces"
  sudo ./contrib/ports/unix/setup-tapif
fi

# Delete executable to be sure it will be built again
rm -f ./build/contrib/ports/unix/example_app_client/example_app_client

cd build
cmake .. -DCLIENT_OR_SERVER=CLIENT; cmake --build .
cd ..

# launch app
# (maybe launch "cmake ." and "make" if changes occurred)
sudo ./build/contrib/ports/unix/example_app_client/example_app_client

# grep -r "hard-coded" to find where the bpf file was hard-coded.
# ./contrib/ports/unix/example_app/CMakeLists.txt and ./src/Filelists.cmake -> useful
