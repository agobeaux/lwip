#!/bin/sh
# Create network interfaces
sudo ./contrib/ports/unix/setup-tapif

cmake . -DCLIENT_OR_SERVER=SERVER && make

# launch app
# (maybe launch "cmake ." and "make" if changes occurred)
sudo ./contrib/ports/unix/example_app/example_app

# grep -r "hard-coded" to find where the bpf file was hard-coded.
# ./contrib/ports/unix/example_app/CMakeLists.txt and ./src/Filelists.cmake -> useful
