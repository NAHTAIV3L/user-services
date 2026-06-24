#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include "shared.h"

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s (enable|disable)\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "enable") && strcmp(argv[1], "disable")) {
        fprintf(stderr, "usage: %s (enable|disable)\n", argv[0]);
        return 1;
    }

    bool enable = 0;

    if (!strcmp(argv[1], "enable")) {
        enable = 1;
    }

    uid_t uid = getuid();
    int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sfd < 0) {
        fprintf(stderr, "Failed to open socket: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_un sockaddr = {
        .sun_family = AF_UNIX,
        .sun_path = SOCKET_PATH,
    };

    if (connect(sfd, (struct sockaddr*)&sockaddr, (socklen_t)sizeof(sockaddr)) < 0) {
        fprintf(stderr, "Failed to connect to unix socket %s: %s\n", SOCKET_PATH, strerror(errno));
        return 1;
    }

    struct message msg = {
        .type = enable ? MESSAGE_TYPE_ENABLE : MESSAGE_TYPE_DISABLE,
        .uid = uid,
    };

    ssize_t bytes_written = write(sfd, &msg, sizeof(msg));
    if (bytes_written < 0) {
        fprintf(stderr, "Write call failed: %s\n", strerror(errno));
        return 1;
    }
    if (bytes_written != sizeof(msg)) {
        fprintf(stderr, "Number of bytes written was different from expected\n");
    }
    int ret;
    ssize_t bytes_read = read(sfd, &ret, sizeof(ret));
    if (bytes_read < 0) {
        fprintf(stderr, "Failed to read return value: %s\n", strerror(errno));
        return 1;
    }
    if (bytes_read != sizeof(int)) {
        fprintf(stderr, "Unexpected number of bytes read for the return value\n");
    }
    if (ret == 1) {
        printf("fail\n");
    }
    else if (ret == 0) {
        printf("success\n");
    }
    else {
        printf("Return value: %d\n", ret);
    }
}
