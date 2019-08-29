#
# Copyright (C) 2015-2019 Felix Weinrank
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

#project(usrsctp-fuzzer C)

#################################################
# INCLUDE MODULES
#################################################

include(CheckIncludeFile)


#################################################
# CHECK INCLUDES
#################################################

include_directories(${CMAKE_SOURCE_DIR}/usrsctplib)


#################################################
# OS DEPENDENT
#################################################

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_definitions(-D_GNU_SOURCE)
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
	add_definitions(-D__APPLE_USE_RFC_2292)
endif ()

#################################################
# COMPILER FLAGS
#################################################

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-gnu-zero-variadic-macro-arguments -Wno-unused-variable")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=fuzzer")


#################################################
# PROGRAMS
#################################################

configure_file(crashtest.py crashtest.py COPYONLY)
configure_file(fuzzer_listen.sh fuzzer_listen.sh COPYONLY)
configure_file(fuzzer_connect.sh fuzzer_connect.sh COPYONLY)

add_executable(fuzzer_listen fuzzer_listen.c)
target_link_libraries(fuzzer_listen usrsctp-static)

add_executable(fuzzer_connect_cookie_wait fuzzer_connect.c)
target_compile_definitions(fuzzer_connect_cookie_wait PRIVATE FUZZ_COOKIE_WAIT)
target_link_libraries(fuzzer_connect_cookie_wait usrsctp-static)

add_executable(fuzzer_connect_cookie_echoed fuzzer_connect.c)
target_compile_definitions(fuzzer_connect_cookie_echoed PRIVATE FUZZ_COOKIE_ECHOED)
target_link_libraries(fuzzer_connect_cookie_echoed usrsctp-static)

add_executable(fuzzer_connect_established fuzzer_connect.c)
target_compile_definitions(fuzzer_connect_established PRIVATE FUZZ_ESTABLISHED)
target_link_libraries(fuzzer_connect_established usrsctp-static)