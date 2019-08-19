#!/bin/bash -e
#
# Build Scripts
# Copyright (C) 2002-2019 by Thomas Dreibholz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Contact: dreibh@iem.uni-due.de


CMAKE_OPTIONS=""
while [ $# -gt 0 ] ; do
   if [[ "$1" =~ ^(-|--)use-clang$ ]] ; then
      # Use these settings for CLang:
      export CXX=clang++
      export CC=clang
   elif [[ "$1" =~ ^(-|--)use-gcc$ ]] ; then
      # Use these settings for GCC:
      export CXX=g++
      export CC=gcc
   elif [[ "$1" =~ ^(-|--)debug$ ]] ; then
      # Enable debugging build:
      CMAKE_OPTIONS="$CMAKE_OPTIONS -DCMAKE_BUILD_TYPE=DEBUG"
   elif [[ "$1" =~ ^(-|--)verbose$ ]] ; then
      # Enable verbose Makefile:
      CMAKE_OPTIONS="$CMAKE_OPTIONS -DCMAKE_VERBOSE_MAKEFILE=ON"
   elif [ "$1" == "--" ] ; then
      break
   else
      echo >&2 "Usage: autogen.sh [--use-clang|--use-gcc] [--debug] [--verbose]"
      exit 1
   fi
   shift
done


# ====== Configure with CMake ===============================================
rm -f CMakeCache.txt
echo "CMake options:${CMAKE_OPTIONS} -DCMAKE_INSTALL_PREFIX=/usr $@ ."
cmake ${CMAKE_OPTIONS} -DCMAKE_INSTALL_PREFIX=/usr $@ .

# ------ Obtain number of cores ---------------------------------------------
# Try Linux
cores=`getconf _NPROCESSORS_ONLN 2>/dev/null || true`
if [ "${cores}" == "" ] ; then
   # Try FreeBSD
   cores=`sysctl -a | grep 'hw.ncpu' | cut -d ':' -f2 | tr -d ' ' || true`
fi
if [ "${cores}" == "" ] ; then
   cores="1"
fi
echo "This system has ${cores} cores!"

# ====== Build ==============================================================
make -j${cores}
