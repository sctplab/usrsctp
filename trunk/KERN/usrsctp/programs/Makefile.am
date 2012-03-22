EXTRA_DIST = Makefile.nmake tsctp.c daytime_server.c discard_server.c client.c
noinst_PROGRAMS = tsctp daytime_server discard_server client datachan
tsctp_SOURCES = tsctp.c
tsctp_LDADD = ../usrsctplib/libusrsctp.la
daytime_server_SOURCES = daytime_server.c
daytime_server_LDADD = ../usrsctplib/libusrsctp.la
discard_server_SOURCES = discard_server.c
discard_server_LDADD = ../usrsctplib/libusrsctp.la
client_SOURCES = client.c
client_LDADD = ../usrsctplib/libusrsctp.la
datachan_SOURCES = datachan.h datachan_serv.c
datachan_LDADD = ../usrsctplib/libusrsctp.la
INCLUDES = -I$(srcdir)/../usrsctplib

