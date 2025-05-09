#ifndef APPUTILS_H
#define APPUTILS_H

#include <gtk/gtk.h>
#include <stdbool.h>

bool parse_server_config(const char* connection_info, char* server_address, int* server_port);
void cleanup_application(GtkApplication* app);
void setup_signal_handlers(void);

#endif 