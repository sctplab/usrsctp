#
# Copyright (C) 2015-2015 Oleg Alexeenkov
# Copyright (C) 2015-2017 Felix Weinrank
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


#################################################
# INCLUDE MODULES AND SETTINGS
#################################################

set(VERSION "1.0.0")

set(prefix 					${CMAKE_INSTALL_PREFIX})
set(exec_prefix 			${prefix})
set(libdir 					${exec_prefix}/lib)
set(includedir 				${prefix}/include/usrsctp)
set(CMAKE_REQUIRED_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_MACOSX_RPATH 		1)

add_definitions(-D__Userspace__)
add_definitions(-D__Userspace_os_${CMAKE_SYSTEM_NAME})
add_definitions(-DSCTP_SIMPLE_ALLOCATOR)
add_definitions(-DSCTP_PROCESS_LEVEL_LOCKS)


#################################################
# OS DEPENDENT
#################################################

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_definitions(-D_GNU_SOURCE)
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
	add_definitions(-U__FreeBSD__)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}     -Wno-address-of-packed-member")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-address-of-packed-member")
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
	add_definitions(-U__APPLE__)
	add_definitions(-D__APPLE_USE_RFC_2292)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}     -Wno-address-of-packed-member -Wno-deprecated-declarations")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-address-of-packed-member -Wno-deprecated-declarations")
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "DragonFly")
	add_definitions(-U__DragonFly__)
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "NetBSD")
	add_definitions(-U__NetBSD__)
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
	add_definitions(-U__OpenBSD__)
endif ()


#################################################
# LIBRARY FILES
#################################################

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

list(APPEND usrsctp_root_headers
	user_atomic.h
	user_environment.h
	user_inpcb.h
	user_ip_icmp.h
	user_ip6_var.h
	user_malloc.h
	user_mbuf.h
	user_queue.h
	user_recv_thread.h
	user_route.h
	user_socketvar.h
	user_uma.h
	usrsctp.h
)

list(APPEND usrsctp_netinet_headers
	netinet/sctp_asconf.h
	netinet/sctp_auth.h
	netinet/sctp_bsd_addr.h
	netinet/sctp_callout.h
	netinet/sctp_constants.h
	netinet/sctp_crc32.h
	netinet/sctp_header.h
	netinet/sctp_indata.h
	netinet/sctp_input.h
	netinet/sctp_lock_userspace.h
	netinet/sctp_os_userspace.h
	netinet/sctp_os.h
	netinet/sctp_output.h
	netinet/sctp_pcb.h
	netinet/sctp_peeloff.h
	netinet/sctp_process_lock.h
	netinet/sctp_sha1.h
	netinet/sctp_structs.h
	netinet/sctp_sysctl.h
	netinet/sctp_timer.h
	netinet/sctp_uio.h
	netinet/sctp_var.h
	netinet/sctputil.h
	netinet/sctp.h
)

list(APPEND usrsctp_netinet6_headers
	netinet6/sctp6_var.h
)

list(APPEND usrsctp_headers
	${usrsctp_root_headers}
	${usrsctp_netinet_headers}
	${usrsctp_netinet6_headers}
)

list(APPEND usrsctp_sources
	netinet/sctp_asconf.c
	netinet/sctp_auth.c
	netinet/sctp_bsd_addr.c
	netinet/sctp_callout.c
	netinet/sctp_cc_functions.c
	netinet/sctp_crc32.c
	netinet/sctp_indata.c
	netinet/sctp_input.c
	netinet/sctp_output.c
	netinet/sctp_pcb.c
	netinet/sctp_peeloff.c
	netinet/sctp_sha1.c
	netinet/sctp_ss_functions.c
	netinet/sctp_sysctl.c
	netinet/sctp_timer.c
	netinet/sctp_userspace.c
	netinet/sctp_usrreq.c
	netinet/sctputil.c
	netinet6/sctp6_usrreq.c
	user_environment.c
	user_mbuf.c
	user_recv_thread.c
	user_socket.c
)
add_library(usrsctp-lib OBJECT "")
#################################################
# CHECK FOR TYPES AND FUNCTIONS
#################################################

option(sctp_invariants "Add runtime checks" 0)
if (sctp_invariants)
	target_compile_definitions(usrsctp-lib PUBLIC INVARIANTS)
	target_compile_definitions(usrsctp-static PUBLIC INVARIANTS)
endif ()

check_include_files("sys/queue.h" have_sys_queue_h)
if (have_sys_queue_h)
	target_compile_definitions(usrsctp-lib PRIVATE HAVE_SYS_QUEUE_H)
endif ()

check_include_files("sys/socket.h;linux/if_addr.h" have_linux_if_addr_h)
if (have_linux_if_addr_h)
	target_compile_definitions(usrsctp-lib PRIVATE HAVE_LINUX_IF_ADDR_H)
endif ()

check_include_files("sys/socket.h;linux/rtnetlink.h" have_linux_rtnetlink_h)
if (have_linux_rtnetlink_h)
	target_compile_definitions(usrsctp-lib 	  PRIVATE HAVE_LINUX_RTNETLINK_H)
endif ()

check_include_files("sys/types.h;netinet/in.h;netinet/ip.h;netinet/ip_icmp.h" have_netinet_ip_icmp_h)
if (have_netinet_ip_icmp_h)
	target_compile_definitions(usrsctp-lib 	  PRIVATE HAVE_NETINET_IP_ICMP_H)
endif ()

check_include_files("stdatomic.h" have_stdatomic_h)
if (have_stdatomic_h)
	target_compile_definitions(usrsctp-lib 	  PRIVATE HAVE_STDATOMIC_H)
endif ()

#################################################
# CHECK STRUCT MEMBERS
#################################################


check_struct_has_member("struct sockaddr" "sa_len" "sys/types.h;sys/socket.h" have_sa_len)
if (have_sa_len)
	message(STATUS "have_sa_len")
	target_compile_definitions(usrsctp-lib PUBLIC HAVE_SA_LEN)
endif ()

check_struct_has_member("struct sockaddr_in" "sin_len" "sys/types.h;netinet/in.h" have_sin_len)
if (have_sin_len)
	message(STATUS "have_sin_len")
	target_compile_definitions(usrsctp-lib PUBLIC HAVE_SIN_LEN)
endif ()

check_struct_has_member("struct sockaddr_in6" "sin6_len" "sys/types.h;netinet/in.h" have_sin6_len)
if (have_sin6_len)
	message(STATUS "have_sin6_len")
	target_compile_definitions(usrsctp-lib PUBLIC HAVE_SIN6_LEN)
endif ()

check_struct_has_member("struct sockaddr_conn" "sconn_len" "usrsctp.h" have_sconn_len)
if (have_sconn_len)
	message(STATUS "HAVE_SCONN_LEN")
	target_compile_definitions(usrsctp-lib PUBLIC HAVE_SCONN_LEN)
endif ()


#################################################
# COMPILER SETTINGS
#################################################

# SETTINGS FOR UNIX COMPILER
if (CMAKE_C_COMPILER_ID MATCHES "Clang" OR CMAKE_C_COMPILER_ID MATCHES "AppleClang" OR CMAKE_C_COMPILER_ID MATCHES "GNU")
	target_compile_features(usrsctp-lib PUBLIC c_std_99)
	target_compile_options(usrsctp-lib PRIVATE -pedantic -Wall -Wextra)

	check_c_compiler_flag(-Wfloat-equal has_wfloat_equal)
	if (has_wfloat_equal)
		target_compile_options(usrsctp-lib PRIVATE -Wfloat-equal)
	endif ()

	check_c_compiler_flag(-Wshadow has_wshadow)
	if (has_wshadow)
		target_compile_options(usrsctp-lib PRIVATE -Wshadow)
	endif ()

	check_c_compiler_flag(-Wpointer-arith has_wpointer_aritih)
	if (has_wpointer_aritih)
		target_compile_options(usrsctp-lib PRIVATE -Wpointer-arith)
	endif ()

	check_c_compiler_flag(-Wunreachable-code has_wunreachable_code)
	if (has_wunreachable_code)
		target_compile_options(usrsctp-lib PRIVATE -Wunreachable-code)
	endif ()

	check_c_compiler_flag(-Winit-self has_winit_self)
	if (has_winit_self)
		target_compile_options(usrsctp-lib PRIVATE -Winit-self)
	endif ()

	check_c_compiler_flag(-Wno-unused-function has_wno_unused_function)
	if (has_wno_unused_function)
		target_compile_options(usrsctp-lib PRIVATE -Wno-unused-function)
	endif ()

	check_c_compiler_flag(-Wno-unused-parameter has_wno_unused_parameter)
	if (has_wno_unused_parameter)
		target_compile_options(usrsctp-lib PRIVATE -Wno-unused-parameter)
	endif ()

	check_c_compiler_flag(-Wno-unreachable-code has_wno_unreachable_code)
	if (has_wno_unreachable_code)
		target_compile_options(usrsctp-lib PRIVATE -Wno-unreachable-code)
	endif ()

	check_c_compiler_flag(-Wstrict-prototypes has_wstrict_prototypes)
	if (has_wstrict_prototypes)
		target_compile_options(usrsctp-lib PRIVATE -Wstrict-prototypes)
	endif ()

	if (sctp_werror)
		target_compile_options(usrsctp-lib PRIVATE -Werror)
	endif ()

	if (sctp_sanitizer_address)
		target_compile_options(usrsctp-lib PRIVATE  -fsanitize=address -fno-omit-frame-pointer -g)
	endif ()

	if (sctp_sanitizer_memory)
		target_compile_options(usrsctp-lib PRIVATE -fsanitize=memory -fno-omit-frame-pointer -g -fsanitize-memory-track-origins)
	endif ()
endif ()


if (WIN32)
	message(STATUS "link library: ws2_32")
	target_link_libraries(usrsctp-lib ws2_32)
endif ()

# shared libraries need PIC
set_property(TARGET usrsctp-lib PROPERTY POSITION_INDEPENDENT_CODE 1)

# shared and static libraries built from the same object files
add_library(usrsctp-shared SHARED $<TARGET_OBJECTS:usrsctp-lib> ${usrsctp_sources})
add_library(usrsctp-static STATIC $<TARGET_OBJECTS:usrsctp-lib> ${usrsctp_sources})

#add_library(usrsctp-shared SHARED usrsctp-lib)
#add_library(usrsctp-static STATIC usrsctp-lib)
set_target_properties(usrsctp-static PROPERTIES OUTPUT_NAME "usrsctp")
set_target_properties(usrsctp-shared PROPERTIES IMPORT_SUFFIX "_import.lib")
set_target_properties(usrsctp-shared PROPERTIES SOVERSION 1 VERSION 1.0.0)

if (NOT DEFINED CMAKE_INSTALL_LIBDIR)
	SET(CMAKE_INSTALL_LIBDIR lib)
endif ()
if (sctp_link_programs_static OR WIN32)
	add_library(usrsctp ALIAS usrsctp-static)
else ()
	add_library(usrsctp ALIAS usrsctp-shared)
endif ()



#################################################
# INSTALL LIBRARY AND HEADER
#################################################
install(TARGETS usrsctp-shared EXPORT usrsctpTargets 
	LIBRARY DESTINATION lib)

install(EXPORT usrsctpTargets
	FILE usrsctpTargets.cmake
	DESTINATION lib/cmake/usrsctp)

install(TARGETS usrsctp-static DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES usrsctp.h DESTINATION include)
