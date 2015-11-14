#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <usrsctp.h>
#include <assert.h>
#include <arpa/inet.h>

void
debug_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

static int receive_cb(struct socket* socket, union sctp_sockstore address, void *data, size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info) {
    if (data == NULL) {
        usrsctp_close(socket);
        printf("Closed %p from callback\n", (void *)socket);
        return 1;
    }
    printf("Received %zu bytes in the receive_cb.\n", datalen);
    sleep(2);
    printf("Exiting receive_cb now.\n");
    free(data);
    return 1;
}

static struct socket* socketListen(int localPort) {
    struct socket* socket = usrsctp_socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, NULL);
    assert(socket != NULL);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(localPort),
    };
    assert(usrsctp_bind(socket, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(usrsctp_listen(socket, 1) == 0);
    return socket;
}

static struct socket* socketConnect(const char* remoteAddress, int remotePort) {
    struct socket* socket = usrsctp_socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP, receive_cb, NULL, 0, NULL);
    assert(socket != NULL);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(remotePort),
    };
    assert(inet_pton(AF_INET, remoteAddress, &address.sin_addr) == 1);
    assert(usrsctp_connect(socket, (struct sockaddr *)&address, sizeof(struct sockaddr_in)) == 0);
    return socket;
}

int main(int argc, char* argv[]) {
    usrsctp_init(8080, NULL, debug_printf);
#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_NONE);
#endif
    struct socket* server = socketListen(9);
    struct socket* client = socketConnect("127.0.0.1", 9);

    int n = 0xaabbccdd;
    usrsctp_sendv(client, &n, sizeof(n), NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0);
    printf("Message of size %zu sent.\n", sizeof(n));
    sleep(1);
    usrsctp_close(server);
    printf("Closed server socket %p.\n", (void *)server);
    usrsctp_close(client);
    printf("Closed client socket %p.\n", (void *)client);
    sleep(2);
    assert(usrsctp_finish() == 0);
    return(0);
}
