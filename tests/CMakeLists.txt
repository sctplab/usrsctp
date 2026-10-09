#
# Host-side smoke test for the lwIP backend.
#
# This subdirectory is only added when:
#   sctp_use_lwip=ON
#   sctp_build_lwip_smoke=ON
#   LWIP_SRC_DIR and LWIP_PORT_DIR are set (validated by the parent)
#
# The goal is "compiles + runs without crashing", not a real SCTP
# loopback.  We let lwIP supply its own unix-port symbols (pthreads,
# sys_arch, etc.) by linking against the archive that lwIP's own
# unix-port build produces (typically `lwipallapps`).
#

# usrsctp public header (transitively pulls in lwip/errno.h when
# SCTP_USE_LWIP is defined for the build).
include_directories(${CMAKE_SOURCE_DIR}/usrsctplib)

# lwIP public headers + unix-port headers.  The exact directory layout
# matches lwIP STABLE-2_2_x.
include_directories(
	${LWIP_SRC_DIR}/src/include
	${LWIP_PORT_DIR}/port/include
)

# lwIP's default lwipopts.h ships in the example apps directory in the
# 2.2.x line; if the user's port dir already contains an lwipopts.h
# higher up the tree, prefer that.
if (EXISTS "${LWIP_PORT_DIR}/lwipopts.h")
	include_directories(${LWIP_PORT_DIR})
elseif (EXISTS "${LWIP_PORT_DIR}/port/include/lwipopts.h")
	# already covered by the include path above
else ()
	message(WARNING "lwipopts.h not found under LWIP_PORT_DIR; expecting it to be supplied via the lwIP archive's transitive include path")
endif ()

add_executable(lwip_smoke lwip_smoke.c)

# Link against usrsctp (built by ../usrsctplib).  We deliberately do
# *not* hard-code the lwIP archive path: CI passes it via
# LWIP_LIBRARIES, and falls back to "lwipallapps" if unset (that's the
# name produced by lwIP's contrib/ports/unix example_app build).
if (NOT LWIP_LIBRARIES)
	# Best-effort default - lwIP's unix-port CMake build produces this
	# archive in the build directory.  CI is expected to either pass
	# the full path here or to put the build dir on the linker path.
	set(LWIP_LIBRARIES lwipallapps)
endif ()

find_package(Threads REQUIRED)

target_link_libraries(lwip_smoke
	usrsctp
	${LWIP_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
)
