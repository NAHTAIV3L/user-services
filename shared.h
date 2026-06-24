#ifndef SHARED_H_
#define SHARED_H_
#include <sys/types.h>
#include <stdint.h>

typedef uint8_t message_type;

#define MESSAGE_TYPE_LOGIN   0
#define MESSAGE_TYPE_LOGOUT  1
#define MESSAGE_TYPE_DISABLE 2
#define MESSAGE_TYPE_ENABLE  3
#define MESSAGE_TYPE_MAX     4

struct message {
    message_type type;
    uid_t uid;
};

// USER_SERVICE_DIR=$HOME/.local/service

#define SOCKET_PATH "/tmp/user-services.sock"
#define USER_SERVICE_DIR ".local/service"
#define DISABLE_FILE "/disabled"
#define DISABLE_FILE_LEN (sizeof(DISABLE_FILE) - 1)
#define ARRAY_LENGTH(x) (sizeof(x) / sizeof(*x))


#endif // SHARED_H_
