#ifndef GUICALLBACKS_H
#define GUICALLBACKS_H

#include <gtk/gtk.h>
#include <stdbool.h>

// Stack management
void set_gui_stack(GtkWidget *stack);
gboolean show_main_content(gpointer stack);

// Network response callbacks
gboolean on_login_response(gpointer user_data);
gboolean on_register_response(gpointer user_data);
void on_message_received(const char* username, const char* message);
void on_history_received(const char* username, const char** messages, int count);
void on_user_status_changed(const char* username, bool is_online);
void on_disconnect_response(bool success, const char* message);

#endif