#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <pwd.h>
#include <sys/types.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include "shared.h"

static inline int send_message(pam_handle_t* pamh, uid_t uid, message_type t) {
    int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sfd < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to open socket: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_un sockaddr = {
        .sun_family = AF_UNIX,
        .sun_path = SOCKET_PATH,
    };

    if (connect(sfd, (struct sockaddr*)&sockaddr, (socklen_t)sizeof(sockaddr)) < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to connect to unix socket %s: %s\n", SOCKET_PATH, strerror(errno));
        return 1;
    }

    struct message msg = {
        .type = t,
        .uid = uid,
    };

    ssize_t bytes_written = write(sfd, &msg, sizeof(msg));
    if (bytes_written < 0) {
        pam_syslog(pamh, LOG_ERR, "Write call failed: %s\n", strerror(errno));
        return 1;
    }
    if (bytes_written != sizeof(msg)) {
        pam_syslog(pamh, LOG_ERR, "Number of bytes written was different from expected\n");
    }
    int ret;
    ssize_t bytes_read = read(sfd, &ret, sizeof(ret));
    if (bytes_read < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to read return value: %s\n", strerror(errno));
        return 1;
    }
    if (bytes_read != sizeof(int)) {
        pam_syslog(pamh, LOG_ERR, "Unexpected number of bytes read for the return value\n");
    }
    if (ret == 1) {
        pam_syslog(pamh, LOG_ERR, "fail\n");
    }
    else if (ret == 0) {
        pam_syslog(pamh, LOG_INFO, "success\n");
    }
    else {
        pam_syslog(pamh, LOG_ERR, "Return value: %d\n", ret);
    }
    return 0;
}

static inline uid_t my_getuid(pam_handle_t* pamh) {
    const char* username = NULL;
    struct passwd* pw = NULL;
    int ret = pam_get_user(pamh, &username, NULL);
    if (ret != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Failed to get username: %s", pam_strerror(pamh, ret));
        return -1;
    }

    pw = getpwnam(username);
    if (!pw) {
        pam_syslog(pamh, LOG_ERR, "Username %s not found: %s\n", username, strerror(errno));
    }

    return pw->pw_uid;
}

int pam_sm_open_session(pam_handle_t *pamh, int silent, int argc, const char **argv) {
    pam_syslog(pamh, LOG_ERR, "PAM open session");

    uid_t uid = my_getuid(pamh);
    if (uid < 0) {
        return PAM_SESSION_ERR;
    }

    if (send_message(pamh, uid, MESSAGE_TYPE_LOGIN)) {
        return PAM_SESSION_ERR;
    }
    return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_ERR, "PAM close session");

    uid_t uid = my_getuid(pamh);
    if (uid < 0) {
        return PAM_SESSION_ERR;
    }

    if (send_message(pamh, uid, MESSAGE_TYPE_LOGOUT)) {
        return PAM_SESSION_ERR;
    }
    return PAM_SUCCESS;
}
