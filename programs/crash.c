#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <usrsctp.h>
#include <assert.h>
#include <arpa/inet.h>

static int receive_cb(struct socket* socket, union sctp_sockstore address, void *data, size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info) {
    if(data == NULL) {
        usrsctp_close(socket);
        printf("Closed from callback\n");
        return 1;
    }
    printf("In receive_cb\n");
    sleep(2);
    printf("Still in receive_cb\n");
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
    usrsctp_init(8080, NULL, NULL);

    struct socket* server = socketListen(9);
    struct socket* client = socketConnect("127.0.0.1", 9);

    int n = 0xaabbccdd;
    usrsctp_sendv(client, &n, sizeof(n), NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0);
    sleep(1);
    usrsctp_close(server);
    usrsctp_close(client);
    printf("Connections closed\n");
    sleep(2);
}
