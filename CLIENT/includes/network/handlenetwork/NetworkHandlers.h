#ifndef NETWORKHANDLERS_H
#define NETWORKHANDLERS_H

#include <stdbool.h>
#include "network/log/ClientLogging.h" 
#include <glib.h>
#include <gtk/gtk.h>
#include "utilsnetwork/Message.h"
#include <winsock2.h>

//Network config constants 
#define CONNECTION_TIMEOUT 30        // Connection timeout in seconds
#define MAX_RECONNECT_ATTEMPTS 5     // Maximum number of reconnection attempts
#define HEARTBEAT_INTERVAL 30        // Heartbeat interval in seconds
#define MAX_ADDRESS_LENGTH 128       // Maximum length for server address
#define REGISTER_RESPONSE 9
#define USER_LIST_REQUEST 10
#define USER_LIST_RESPONSE 11
#define LOGOUT_REQUEST 13

//External variables for network management 
extern SOCKET clientSocket;          // Main client socket
extern bool isConnected;             // Connection status flag
extern HANDLE networkThread;         // Network receiving thread handle
extern HANDLE heartbeatThread;       // Heartbeat thread handle
extern char last_known_address[MAX_ADDRESS_LENGTH];  // Last server address
extern int last_known_port;          // Last server port

// callbacks
extern void on_message_received(const char* username, const char* message);
extern void on_history_received(const char* username, const char** messages, int count);
extern void on_user_status_changed(const char* username, bool is_online);
extern void on_login_response(bool success, const char* message);
extern void on_register_response(bool success, const char* message);

//Network init and cleanup 
bool initialize_network(const char* address, int port);
void disconnect_from_server(void);
void cleanup_network(void);
bool attempt_reconnection(void);
void handle_network_error(void);

//Socket management
bool set_socket_timeout(void);
bool send_message_to_server(Message* msg);

//Authentication and registration
bool send_login_request(const char* username, const char* password);
bool send_register_request(const char* username, const char* password);
bool send_logout_request(void);

//Message and chat
bool send_chat_message(const char* username, const char* message);
bool request_message_history(const char* username);
void request_conversation_history(const char* username);
void notify_server_conversation_opened(const char* username);
void subscribe_to_messages(const char* username);

//User management 
void request_user_list(void);
void update_user_status(const char* username, bool is_online);

//Callback function
void on_message_received(const char* username, const char* message);
void on_history_received(const char* username, const char** messages, int count);
void on_user_status_changed(const char* username, bool is_online);
void on_login_response(bool success, const char* message);
void on_register_response(bool success, const char* message);

//Thread function prototypes 
static DWORD WINAPI network_receive_thread(LPVOID lpParam);
static DWORD WINAPI heartbeat_thread(LPVOID lpParam);

#endif 