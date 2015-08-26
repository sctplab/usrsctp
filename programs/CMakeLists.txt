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
message(">> WARNINING: CMAKE SUPPORT IS EXPERIMENTAL <<")

include_directories(../usrsctplib)

FIND_PACKAGE (Threads)

SET (check_PROGRAMS
client.c
datachan_serv.c
daytime_server.c
discard_server.c
echo_server.c
ekr_client.c
ekr_loop.c
ekr_peer.c
ekr_server.c
rtcweb.c
tsctp.c
)

FOREACH (source_file ${check_PROGRAMS})
	GET_FILENAME_COMPONENT (source_file_we ${source_file} NAME_WE)
	ADD_EXECUTABLE (
		${source_file_we}
		${source_file}
	)
	TARGET_LINK_LIBRARIES (${source_file_we}
		usrsctp-static
		${CMAKE_THREAD_LIBS_INIT}
	)
	ADD_TEST (${source_file_we} ${source_file_we})
	IF ("x${CMAKE_CXX_COMPILER_ID}" STREQUAL "xClang" OR "x${CMAKE_CXX_COMPILER_ID}" STREQUAL "xGNU")
		SET_PROPERTY (TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -g -O3")
	ENDIF ()
	IF ("x${CMAKE_CXX_COMPILER_ID}" STREQUAL "xMSVC")
		IF (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
			STRING(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
		ELSE ()
			SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
		ENDIF ()
	ENDIF ()
ENDFOREACH ()
