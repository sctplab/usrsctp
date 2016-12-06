#
# Copyright (C) 2015-2015 Oleg Alexeenkov
# Copyright (C) 2015-2015 Felix Weinrank
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

cmake_minimum_required(VERSION 2.6)
project(libusrsctp)

set(BUILD_MAJOR "1")
set(BUILD_MINOR "0")
set(BUILD_PATCH "0~td108")
set(BUILD_VERSION ${BUILD_MAJOR}.${BUILD_MINOR}.${BUILD_PATCH})


# INSTALLATION_DIRECTORIES
#################################################

set(CMAKE_INSTALL_BINDIR_DOC        "user executables [PREFIX/bin]")
set(CMAKE_INSTALL_SBINDIR_DOC       "system admin executables [EPREFIX/sbin]")
set(CMAKE_INSTALL_DATADIR_DOC       "read-only architecture-independent data [PREFIX/share]")
set(CMAKE_INSTALL_SYSCONFDIR_DOC    "read-only single-machine data [PREFIX/etc]")
set(CMAKE_INSTALL_LOCALSTATEDIR_DOC "modifiable single-machine data [PREFIX/var]")
set(CMAKE_INSTALL_LIBDIR_DOC        "object code libraries [PREFIX/lib]")
set(CMAKE_INSTALL_INCLUDEDIR_DOC    "read-only includes [PREFIX/include]")
set(CMAKE_INSTALL_MANDIR_DOC        "man documentation [PREFIX/share/man]")

set(CMAKE_INSTALL_BINDIR "bin"
    CACHE PATH ${CMAKE_INSTALL_BINDIR_DOC})
set(CMAKE_INSTALL_SBINDIR "sbin"
    CACHE PATH ${CMAKE_INSTALL_SBINDIR_DOC})
set(CMAKE_INSTALL_DATADIR "share"
    CACHE PATH ${CMAKE_INSTALL_DATADIR_DOC})
set(CMAKE_INSTALL_SYSCONFDIR "etc"
    CACHE PATH ${CMAKE_INSTALL_SYSCONFDIR_DOC})
set(CMAKE_INSTALL_LOCALSTATEDIR "var"
    CACHE PATH ${CMAKE_INSTALL_LOCALSTATEDIR_DOC})
set(CMAKE_INSTALL_LIBDIR "lib"
    CACHE PATH ${CMAKE_INSTALL_LIBDIR_DOC})
set(CMAKE_INSTALL_INCLUDEDIR "include"
    CACHE PATH ${CMAKE_INSTALL_INCLUDEDIR_DOC})
set(CMAKE_INSTALL_MANDIR "share/man"
    CACHE PATH ${CMAKE_INSTALL_MANDIR_DOC})


# TARBALL
#################################################

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME
   "${CMAKE_PROJECT_NAME}-${BUILD_MAJOR}.${BUILD_MINOR}.${BUILD_PATCH}")
set(CPACK_SOURCE_IGNORE_FILES
   "${PROJECT_SOURCE_DIR}/${CMAKE_PROJECT_NAME}-*;${PROJECT_SOURCE_DIR}/${CMAKE_PROJECT_NAME}_*;/build/;/.git/;/CMakeFiles/;CMakeCache.txt$;.cmake$;.tar.gz$;/_CPack_Packages;/Makefile$;~$;/build-deb;/clean-deb;/filter-empty-entries;/make-symbols;/make-ppa;/make-deb;/debian.conf;/make-rpm;/rpm.conf;${CPACK_SOURCE_IGNORE_FILES}")
message("CPACK_SOURCE_IGNORE_FILES = ${CPACK_SOURCE_IGNORE_FILES}")
include(CPack)

add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} clean package_source)


# Debug build type as default
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, using DEBUG")
    set(CMAKE_BUILD_TYPE "DEBUG")
endif()

# Enable verbose output in DEBUG mode
if (${CMAKE_BUILD_TYPE} MATCHES "DEBUG")
    message(STATUS "enabling verbose outout")
    set(CMAKE_VERBOSE_MAKEFILE on)
endif()

find_package(Threads REQUIRED)

add_subdirectory(usrsctplib)
add_subdirectory(programs)
