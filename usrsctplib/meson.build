# Includes
include_dirs = [include_directories(
    '.',
    'netinet',
    'netinet6',
)]

# Sources
sources = files([
    'user_environment.c',
    'user_mbuf.c',
    'user_recv_thread.c',
    'user_socket.c',
])
if system == 'android'
    sources += files('android/ifaddrs.c')
    include_dirs += include_directories('android')
endif

subdir('netinet')
subdir('netinet6')

# Install usrsctp.h
install_headers('usrsctp.h')
