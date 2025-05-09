/* 
#ifndef NETWORKHANDLERS_H
#define NETWORKHANDLERS_H

#include <stdbool.h>
#include "network/log/ClientLogging.h" 
#include <glib.h>
#include <gtk/gtk.h>
#include "utilsnetwork/Message.h"
#include <winsock2.h>
#include <ws2tcpip.h>  // for inet_pton

#define INVALID_PORT(p) ((p) <= 0 || (p) > 65535)
#define INVALID_ADDRESS(a) (!(a) || !*(a))
#define SOCKET_TIMEOUT 5000
#define DEFAULT_PROTOCOL IPPROTO_TCP

//Network config constants 
#define CONNECTION_TIMEOUT 5       
#define MAX_RECONNECT_ATTEMPTS 3    
#define HEARTBEAT_INTERVAL 30        
#define MAX_ADDRESS_LENGTH 128      

typedef enum {
    NETWORK_STATE_DISCONNECTED,
    NETWORK_STATE_CONNECTING,
    NETWORK_STATE_CONNECTED,
    NETWORK_STATE_AUTHENTICATING,
    NETWORK_STATE_AUTHENTICATED
} NetworkState;

//External variables for network management 
extern SOCKET clientSocket;         
extern bool isConnected;             
extern HANDLE networkThread;        
extern HANDLE heartbeatThread;      
extern char last_known_address[MAX_ADDRESS_LENGTH];  
extern int last_known_port;         

// Network callbacks
extern void on_message_received(const char* username, const char* message);
extern void on_history_received(const char* username, const char** messages, int count);
extern void on_user_status_changed(const char* username, bool is_online);
extern void on_login_response(bool success, const char* message);
extern void on_register_response(bool success, const char* message);
extern void on_disconnect_response(bool success, const char* message);

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
bool send_disconnect_request(const char* username);

//Message and chat
bool send_chat_message(const char* username, const char* message);
bool request_message_history(const char* username);
void request_conversation_history(const char* username);
void notify_server_conversation_opened(const char* username);
void subscribe_to_messages(const char* username);

//User management 
void request_user_list(void);
void update_user_status(const char* username, bool is_online);

//Thread function prototypes 
static DWORD WINAPI network_receive_thread(LPVOID lpParam);
static DWORD WINAPI heartbeat_thread(LPVOID lpParam);

//Registration request
bool send_registration_request(const char *first_name, const char *last_name, 
    const char *username, const char *email, 
    const char *password, const char *first_question, 
    const char *second_question);

    // User management
const char* get_current_user(void);
void set_current_user(const char* username);

#endif
*/