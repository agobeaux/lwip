#!/bin/sh
# Create network interfaces
sudo ./contrib/ports/unix/setup-tapif

cmake . -DCLIENT_OR_SERVER=CLIENT && make

# launch app
# (maybe launch "cmake ." and "make" if changes occurred)
sudo ./contrib/ports/unix/example_app_client/example_app_client

# grep -r "hard-coded" to find where the bpf file was hard-coded.
# ./contrib/ports/unix/example_app/CMakeLists.txt and ./src/Filelists.cmake -> useful
