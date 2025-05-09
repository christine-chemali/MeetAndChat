#ifndef MESSAGE_H
#define MESSAGE_H

// Codes of message types
#define LOGIN_REQUEST 1
#define REGISTER_REQUEST 2
#define SEND_MESSAGE 3
#define FETCH_MESSAGES 4
#define LOGOUT 5
#define LOGIN_RESPONSE 6
#define SEND_MESSAGE_RESPONSE 7
#define FETCH_MESSAGES_RESPONSE 8
#define CONVERSATION_OPENED 9
#define SUBSCRIBE_REQUEST 10
#define USER_STATUS_UPDATE 11
#define HEARTBEAT 12
#define KEY_ROTATION 13
#define CONNECTION_ERROR 14
#define RECONNECT_REQUEST 15
#define KEY_ROTATION_REQUEST 16
#define REGISTER_RESPONSE 17
#define USER_LIST_REQUEST 18
#define DISCONNECT_RESPONSE 19
#define USER_LIST_RESPONSE 20
#define LOGOUT_REQUEST 21

#define MAX_MESSAGE_LENGTH 1024
#define MESSAGE_HEADER_SIZE (sizeof(int) * 2)  // type + length

// Data structure
typedef struct {
    int type;
    int length;
    unsigned int checksum;
    char data[MAX_MESSAGE_LENGTH];
    char padding[4];
} Message;

#endif 
