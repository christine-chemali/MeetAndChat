#ifndef MESSAGESENDER_H
#define MESSAGESENDER_H

#include "utilsnetwork/Message.h"
#include <stdbool.h>
#include <stddef.h>

extern bool send_message_to_server(Message* msg);
bool send_generic_message(int type, const char* data, size_t length);

#endif 