#ifndef NETWORKCORE_H
#define NETWORKCORE_H

#include <stdbool.h>
#include "utilsnetwork/Message.h"
#include <winsock2.h>
#include <ws2tcpip.h>  // for inet_pton

//Network config constants
#define CONNECTION_TIMEOUT 5      
#define MAX_RECONNECT_ATTEMPTS 3    
#define HEARTBEAT_INTERVAL 30        
#define MAX_ADDRESS_LENGTH 128  
#define INVALID_PORT(p) ((p) <= 0 || (p) > 65535)
#define INVALID_ADDRESS(a) (!(a) || !*(a))
#define SOCKET_TIMEOUT 5000
#define DEFAULT_PROTOCOL IPPROTO_TCP

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
extern char last_known_address[MAX_ADDRESS_LENGTH];  
extern int last_known_port;        

// Network initialization and state management
void update_network_state(NetworkState newState);
bool check_connection_status(void);
bool initialize_network(const char* address, int port);
void cleanup_network(void);
void handle_network_error(void);
void disconnect_from_server(void);

#endif 