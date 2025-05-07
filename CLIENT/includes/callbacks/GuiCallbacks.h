#ifndef GUI_CALLBACKS_H
#define GUI_CALLBACKS_H

#include <gtk/gtk.h>
#include <stdbool.h>

// Stack management
void set_gui_stack(GtkWidget *stack);
gboolean show_main_content(gpointer stack);

// Network response callbacks
void on_login_response(bool success, const char* message);
void on_register_response(bool success, const char* message);
void on_message_received(const char* username, const char* message);
void on_history_received(const char* username, const char** messages, int count);
void on_user_status_changed(const char* username, bool is_online);

#endif