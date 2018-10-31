#
# Copyright (C) 2015-2015 Oleg Alexeenkov
# Copyright (C) 2015-2018 Felix Weinrank
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

project(usrsctplib C)
cmake_minimum_required(VERSION 3.0)

# Debug build type as default
if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type selected, using DEBUG")
	set(CMAKE_BUILD_TYPE "DEBUG")
endif ()

include(CheckStructHasMember)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckCCompilerFlag)

#################################################
# SET TARGETS
#################################################

#################################################
# CHECK OPTIONS
#################################################



option(sctp_debug "Provide debug information" 1)
if (sctp_debug)
	add_definitions(-DSCTP_DEBUG)
endif ()

option(sctp_inet "Support IPv4" 1)
if (sctp_inet)
	add_definitions(-DINET)
endif ()

option(sctp_inet6 "Support IPv6" 1)
if (sctp_inet6)
	add_definitions(-DINET6)
endif ()

option(sctp_werror "Treat warning as error" 1)

option(sctp_link_programs_static "Link example programs static" 0)

option(sctp_build_programs "Build example programs" 1)

option(sctp_sanitizer_address "Compile with address sanitizer" 0)

option(sctp_sanitizer_memory "Compile with memory sanitizer" 0)

if (sctp_sanitizer_address AND sctp_sanitizer_memory)
	message(FATAL_ERROR "Can not compile with both sanitizer options")
endif ()




#################################################
# CHECK STRUCT MEMBERS
#################################################

set(CMAKE_REQUIRED_INCLUDES "${CMAKE_SOURCE_DIR}/usrsctplib")

check_include_file(usrsctp.h have_usrsctp_h)
if (NOT have_usrsctp_h)
	message(FATAL_ERROR "usrsctp.h not found")
endif ()




# SETTINGS FOR VISUAL STUDIO COMPILER
if (CMAKE_C_COMPILER_ID MATCHES "MSVC")
	if (CMAKE_C_FLAGS MATCHES "/W[0-4]")
		string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
	else ()
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
	endif ()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4100") # 'identifier' : unreferenced formal parameter
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4127") # conditional expression is constant
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4200") # nonstandard extension used : zero-sized array in struct/union
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4214") # bit field types other than int
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4706") # assignment within conditional expression
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4245") # 'conversion' : conversion from 'type1' to 'type2', signed/unsigned mismatch
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4389") # 'operator' : signed/unsigned mismatch
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4702") # unreachable code
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4701") # Potentially uninitialized local variable 'name' used

	# ToDo
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4244") # 'conversion' conversion from 'type1' to 'type2', possible loss of data

	if (sctp_werror)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX")
	endif ()
endif ()

message(STATUS "Compiler flags (CMAKE_C_FLAGS): ${CMAKE_C_FLAGS}")


#################################################
# INCLUDE SUBDIRS
#################################################

add_subdirectory(usrsctplib)

if (sctp_build_programs)
	add_subdirectory(programs)
endif ()
