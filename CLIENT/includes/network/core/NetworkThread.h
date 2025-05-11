#ifndef NETWORKTHREAD_H
#define NETWORKTHREAD_H

#include <windows.h>
#include "utilsnetwork/Message.h"

// External thread handles
extern HANDLE networkThread;
extern HANDLE heartbeatThread;

// Thread function prototypes
DWORD WINAPI network_receive_thread(LPVOID lpParam);
DWORD WINAPI heartbeat_thread(LPVOID lpParam);

// Function to stop network threads
void stop_network_threads(void);
void process_received_message(Message* message);

#endif
