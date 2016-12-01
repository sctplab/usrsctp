#!/bin/sh -e

cmake -DCMAKE_INSTALL_PREFIX=/usr .

cores=`getconf _NPROCESSORS_ONLN`
make -j${cores}
