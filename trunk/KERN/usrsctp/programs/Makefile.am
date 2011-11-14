EXTRA_DIST = tsctp.c discard_server.c client.c
noinst_PROGRAMS = tsctp discard_server client
tsctp_SOURCES = tsctp.c
tsctp_LDADD = ../usrsctplib/libusrsctp.la
discard_server_SOURCES = discard_server.c
discard_server_LDADD = ../usrsctplib/libusrsctp.la
client_SOURCES = client.c
client_LDADD = ../usrsctplib/libusrsctp.la
INCLUDES = -I$(srcdir)/../usrsctplib

