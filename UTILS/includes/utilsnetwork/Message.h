#ifndef MESSAGE_H
#define MESSAGE_H

#define MAX_MESSAGE_LENGTH 1024

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

// Define the structure of a Message
typedef struct {
    int type;          // message type
    int length;        // length of the data in the message
    char data[MAX_MESSAGE_LENGTH];   // The actual data being sent or received
    unsigned int checksum;  // Checksum for verifying message integrity
} Message;

#endif
//cc
