cmake_minimum_required(VERSION 2.6)

include_directories(${PROJECT_SOURCE_DIR}/../usrsctplib)

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
	IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
		SET_PROPERTY (TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -g -O3")
	ENDIF ()
	IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
		IF (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
			STRING(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
		ELSE ()
			SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
		ENDIF ()
	ENDIF ()
ENDFOREACH ()
