#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "shared.h"
#include "config.h"

typedef uint8_t process_state;

// PROCESS_STATE_NIL is for an unused user struct
#define PROCESS_STATE_NIL      0
#define PROCESS_STATE_NODIR    1
#define PROCESS_STATE_UP       2
#define PROCESS_STATE_DOWN     3
#define PROCESS_STATE_DISABLED 4

char** env = NULL;

struct user {
    process_state pstate;
    uid_t uid;
    size_t sessions;
    pid_t pid;
};

#define NUMBER_OF_USERS 100
static struct user users[NUMBER_OF_USERS] = {0};
static struct passwd* pw;
static const char* user_service_dir = USER_SERVICE_DIR;
static size_t user_service_dir_len = sizeof(USER_SERVICE_DIR) - 1;

void kill_user_process(struct user* user) {
    fprintf(stderr, "Killing user s6-svscan: pid %d\n", user->pid);
    if (!kill(user->pid, 0)) {
        if (kill(user->pid, SIGTERM) < 0) {
            fprintf(stderr, "Kill failed to send signal %s\n", strerror(errno));
            if (kill(user->pid, SIGKILL) < 0) {
                fprintf(stderr, "Kill failed to send second signal exiting %s\n", strerror(errno));
                exit(1);
            }
        }
    }
}

int start_process(struct user* user) {
    fprintf(stderr, "Starting uid=%d(%s) s6-svscan\n", user->uid, pw->pw_name);
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
        return 1;
    }
    if (!pid) {
        if (setgid(pw->pw_gid) < 0) {
            fprintf(stderr, "Failed to drop gid\n");
            exit(1);
        }
        if (setuid(pw->pw_uid) < 0) {
            fprintf(stderr, "Failed to drop uid\n");
            exit(1);
        }
        size_t pw_dir_len = strlen(pw->pw_dir);
        //                                 plus 2 for slash and null byte
        size_t len = pw_dir_len + user_service_dir_len + 2;
        char dir[len];
        memcpy(dir, pw->pw_dir, pw_dir_len);
        dir[pw_dir_len] = '/';
        memcpy(&dir[pw_dir_len + 1], user_service_dir, user_service_dir_len + 1);
        char* argv[] = { S6_SVSCAN, dir, NULL };
        fprintf(stderr, "pid=%d: ", getpid());
        for (char** it = argv; *it; it++) {
            fprintf(stderr, "%s ", *it);
        }
        fprintf(stderr, "\n");
        execve(S6_SVSCAN, argv, env);
        fprintf(stderr, "Failed to execv: %s\n", strerror(errno));
        exit(1);
    }
    user->pid = pid;
    user->pstate = PROCESS_STATE_UP;
    return 0;
}

static inline struct user* find_user(uid_t uid) {
    for (int i = 0; i < NUMBER_OF_USERS; i++) {
        if (users[i].uid == uid) {
            return &users[i];
        }
    }
    return NULL;
}

static inline struct user* find_user_or_first_unused_by_uid(uid_t uid) {
    struct user* user = NULL;
    for (int i = 0; i < NUMBER_OF_USERS; i++) {
        if (users[i].uid == uid) {
            return &users[i];
        }
        if (users[i].pstate == PROCESS_STATE_NIL && !user) {
            user = &users[i];
        }
    }
    return user;
}

void initalize_user(struct user* user, uid_t uid) {
    fprintf(stderr, "initalizing user %d\n", uid);
    user->uid = uid;
    // find disable file or service directory
    {
        size_t pw_dir_len = strlen(pw->pw_dir);
        //                                 plus 2 for slash and null byte
        size_t len = pw_dir_len + user_service_dir_len + 2 + DISABLE_FILE_LEN;
        char dir[len];
        memcpy(dir, pw->pw_dir, pw_dir_len);
        dir[pw_dir_len] = '/';
        memcpy(&dir[pw_dir_len + 1], user_service_dir, user_service_dir_len);
        memcpy(&dir[pw_dir_len + 1 + user_service_dir_len], DISABLE_FILE, DISABLE_FILE_LEN + 1);
        dir[pw_dir_len + 1 + user_service_dir_len] = 0;
        struct stat statbuf;
        if (stat(dir, &statbuf) < 0) {
            fprintf(stderr, "No directory: %s\nNot starting user services\n", dir);
            user->pstate = PROCESS_STATE_NODIR;
            return;
        }
        if (!S_ISDIR(statbuf.st_mode)) {
            fprintf(stderr, "%s is not a directory\nNot starting user services\n", dir);
            user->pstate = PROCESS_STATE_NODIR;
            return;
        }
        dir[pw_dir_len + 1 + user_service_dir_len] = '/';
        if (!stat(dir, &statbuf)) {
            user->pstate = PROCESS_STATE_DISABLED;
            return;
        }
    }
    user->pstate = PROCESS_STATE_DOWN;
    user->pid = -1;
    user->sessions = 0;
}

int touch(char* file) {
    int fd = 0;
    uid_t euid = geteuid();
    gid_t egid = getegid();

    if (setegid(pw->pw_gid) < 0) {
        fprintf(stderr, "setegid failed: %s\n", strerror(errno));
        return 1;
    }

    if (seteuid(pw->pw_uid) < 0) {
        fprintf(stderr, "seteuid failed: %s\n", strerror(errno));
        return 1;
    }

    if ((fd = open(file, O_CLOEXEC | O_CREAT)) < 0) {
        fprintf(stderr, "Failed to create file %s\n", file);
        return 1;
    }
    close(fd);

    if (seteuid(euid) < 0) {
        fprintf(stderr, "Failed to setresuid privlages back to root exiting: %s\n", strerror(errno));
        exit(1);
    }
    if (setegid(egid) < 0) {
        fprintf(stderr, "Failed to setresgid privlages back to root exiting: %s\n", strerror(errno));
        exit(1);
    }
    return 0;
}

int handle_disable(uid_t uid) {
    fprintf(stderr, "Disabling for uid=%d(%s)\n", uid, pw->pw_name);
    struct user* user = find_user(uid);
    if (!user) {
        return 1;
    }
    switch (user->pstate) {
    case PROCESS_STATE_NODIR:
    case PROCESS_STATE_NIL:
    case PROCESS_STATE_DISABLED:
        return 0;
    case PROCESS_STATE_UP:
        kill_user_process(user);
    case PROCESS_STATE_DOWN: {
        size_t pw_dir_len = strlen(pw->pw_dir);
        //                                 plus 2 for slash and null byte
        size_t len = pw_dir_len + user_service_dir_len + 2 + DISABLE_FILE_LEN;
        char file[len];
        memcpy(file, pw->pw_dir, pw_dir_len);
        file[pw_dir_len] = '/';
        memcpy(&file[pw_dir_len + 1], user_service_dir, user_service_dir_len);
        memcpy(&file[pw_dir_len + 1 + user_service_dir_len], DISABLE_FILE, DISABLE_FILE_LEN + 1);
        if (touch(file)) {
            fprintf(stderr, "disable wont be saved: %s\n", strerror(errno));
        }
    }
    }
    return 0;
}

int handle_enable(uid_t uid) {
    fprintf(stderr, "Enabling for uid=%d(%s)\n", uid, pw->pw_name);
    struct user* user = find_user_or_first_unused_by_uid(uid);
    if (!user) {
        return 1;
    }
    if (user->pstate == PROCESS_STATE_NIL) {
        initalize_user(user, uid);
    }
    switch (user->pstate) {
    case PROCESS_STATE_UP:
    case PROCESS_STATE_NODIR:
        return 0;
    case PROCESS_STATE_DISABLED: {
        size_t pw_dir_len = strlen(pw->pw_dir);
        //                                 plus 2 for slash and null byte
        size_t len = pw_dir_len + user_service_dir_len + 2 + DISABLE_FILE_LEN;
        char file[len];
        memcpy(file, pw->pw_dir, pw_dir_len);
        file[pw_dir_len] = '/';
        memcpy(&file[pw_dir_len + 1], user_service_dir, user_service_dir_len);
        memcpy(&file[pw_dir_len + 1 + user_service_dir_len], DISABLE_FILE, DISABLE_FILE_LEN + 1);
        if (unlink(file) < 0) {
            fprintf(stderr, "Failed to unlink %s enable wont save after reboot\n", file);
        }
    }
    case PROCESS_STATE_DOWN:
        if (start_process(user)) {
            return 1;
        }
    }
    return 0;
}

int handle_logout(uid_t uid) {
    fprintf(stderr, "Logout uid=%d(%s)\n", pw->pw_uid, pw->pw_name);
    struct user* user = find_user(uid);
    if (!user) {
        fprintf(stderr, "User not found\n");
        return 1;
    }
    user->sessions--;

    if (user->sessions == 0) {
        if (user->pstate == PROCESS_STATE_UP) {
            kill_user_process(user);
        }
        memset(user, 0, sizeof(*user));
    }
    return 0;
}

int handle_login(uid_t uid) {
    fprintf(stderr, "Login uid=%d(%s)\n", pw->pw_uid, pw->pw_name);
    struct user* user = find_user_or_first_unused_by_uid(uid);
    if (!user) {
        fprintf(stderr, "Failed to create new user: too many users logged in\n");
        return 1;
    }
    if (user->pstate == PROCESS_STATE_NIL) {
        initalize_user(user, uid);
    }
    user->sessions++;
    fprintf(stderr, "before switch\n");
    switch (user->pstate) {
    case PROCESS_STATE_UP:
    case PROCESS_STATE_DISABLED:
    case PROCESS_STATE_NODIR:
        return 0;
    case PROCESS_STATE_DOWN: {
        if (start_process(user)) {
            return 1;
        }
    }
    }
    return 0;
}

void term_and_int_signal_handler(int signum) {
    if (signum == SIGTERM || signum == SIGINT) {
        unlink(SOCKET_PATH);
        exit(0);
    }
}

int main(int argc, char** argv, char** envp) {
    env = envp;
    int notification_fd = -1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-n")) {
            if (i == argc - 1) {
                fprintf(stderr, "usage: %s [-n fd]\n", argv[0]);
                return 1;
            }
            notification_fd = atoi(argv[i + 1]);
            i++;
        }
    }
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (gid != 0 || uid != 0) {
        fprintf(stderr, "must be run as root\n");
        return 1;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_IGN;
    action.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    sigaction(SIGCHLD, &action, NULL);
    action.sa_handler = term_and_int_signal_handler;
    action.sa_flags = 0;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);

    int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (socket < 0) {
        fprintf(stderr, "Failed to open unix socket: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_un sockaddr = {
        .sun_family = AF_UNIX,
        .sun_path = SOCKET_PATH,
    };

    mode_t mask = umask(0);
    if (bind(sfd, (struct sockaddr*)&sockaddr, (socklen_t)sizeof(sockaddr)) < 0) {
        fprintf(stderr, "Failed to bind to socket %s: %s\n", sockaddr.sun_path, strerror(errno));
        close(sfd);
        return 1;
    }
    umask(mask);

    if (listen(sfd, 1) < 0) {
        fprintf(stderr, "Failed to set socket to listening: %s\n", strerror(errno));
        close(sfd);
        return 1;
    }

    if (notification_fd >= 0) {
        if (write(notification_fd, "\n", 1) < 0) {
            fprintf(stderr, "Failed to write to notification fd: %s\n", strerror(errno));
        }
    }

    struct sockaddr client_sockaddr;
    socklen_t client_addrlen;
    int cfd;
    while (true) {
        cfd = accept(sfd, &client_sockaddr, &client_addrlen);
        if (cfd < 0) {
            fprintf(stderr, "Failed to accept client: %s\n", strerror(errno));
            continue;
        }

        struct message msg = {0};
        ssize_t bytes_read = read(cfd, &msg, sizeof(msg));
        if (bytes_read < 0) {
            fprintf(stderr, "Failed to read from client closing connection\n");
            goto err;
        }
        if (bytes_read != sizeof(msg)) {
            fprintf(stderr, "Invalid data read closing client connection\n");
            goto err;
        }
        if (msg.type >= MESSAGE_TYPE_MAX) {
            fprintf(stderr, "Invalid message: msg.type = %d\n", msg.type);
            goto err;
        }
        pw = getpwuid(msg.uid);
        if (!pw) {
            fprintf(stderr, "Invalid uid: %d\n", msg.uid);
            goto err;
        }
        int ret = 0;
        switch (msg.type) {
        case MESSAGE_TYPE_LOGIN:
            ret = handle_login(msg.uid);
            break;
        case MESSAGE_TYPE_LOGOUT:
            ret = handle_logout(msg.uid);
            break;
        case MESSAGE_TYPE_DISABLE:
            ret = handle_disable(msg.uid);
            break;
        case MESSAGE_TYPE_ENABLE:
            ret = handle_enable(msg.uid);
            break;
        }
        ssize_t bytes_written = write(cfd, &ret, sizeof(ret));
        if (bytes_written < 0) {
            fprintf(stderr, "Failed to write return value: %s\n", strerror(errno));
            goto err;
        }
        if (bytes_written != sizeof(int)) {
            fprintf(stderr, "Unexpected number of bytes written for return value\n");
        }

    err:
        close(cfd);
    }
    return 0;
}
