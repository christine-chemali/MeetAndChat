
#include "network/log/ClientLogging.h"
#include "callbacks/GuiCallbacks.h"
#include "graphics/utils/Utils.h"
#include <stdio.h>  
#include <gtk/gtk.h>

// Global variable to stock stack 
static GtkWidget *g_stack = NULL;

// func to define stack
void set_gui_stack(GtkWidget *stack) {
    log_client_message(LOG_INFO, "Setting GUI stack");
    g_stack = stack;
}

// Func to show home main content
gboolean show_main_content(gpointer stack) {
    log_client_message(LOG_INFO, "Displaying home main content");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "main_window");
    return G_SOURCE_REMOVE;
}

//Callback login
void on_login_response(bool success, const char* message) {
    if (success) {
        log_client_message(LOG_INFO, "Login successful");
        g_idle_add(show_main_content, g_stack);
    } else {
        log_client_message(LOG_ERROR, "Login failed");
        char error_message[256];
        snprintf(error_message, sizeof(error_message), "Login failed: %s", message);
        show_custom_dialog("Error", error_message);
    }
}

//TODO: those are temporary versions
void on_message_received(const char* username, const char* message) {
    printf("Message received from %s: %s\n", username, message);
}

void on_history_received(const char* username, const char** messages, int count) {
    printf("History received from %s (%d messages)\n", username, count);
}

void on_user_status_changed(const char* username, bool is_online) {
    printf("User %s is now %s\n", username, is_online ? "online" : "offline");
}

void on_register_response(bool success, const char* message) {
    printf("Register response: %s - %s\n", success ? "Success" : "Failed", message);
}