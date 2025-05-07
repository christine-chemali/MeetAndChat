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

// Callback login avec gestion d'erreur améliorée
void on_login_response(bool success, const char* message) {
    if (success) {
        log_client_message(LOG_INFO, "Login successful");
        g_idle_add(show_main_content, g_stack);
    } else {
        log_client_message(LOG_ERROR, "Login failed");
        
        // Message d'erreur plus détaillé
        const char* error_msg = message ? message : "Unknown error occurred";
        g_idle_add((GSourceFunc)show_custom_dialog, g_strdup_printf("Login Error: %s", error_msg));
    }
}

// Callback pour les messages reçus
void on_message_received(const char* username, const char* message) {
    log_client_message(LOG_INFO, "Message received");
    // Implémentation à venir pour l'interface de chat
    g_idle_add((GSourceFunc)show_custom_dialog, 
               g_strdup_printf("New message from %s", username));
}

// Callback pour l'historique des messages
void on_history_received(const char* username, const char** messages, int count) {
    log_client_message(LOG_INFO, "History received");
    // Implémentation à venir pour l'affichage de l'historique
    g_idle_add((GSourceFunc)show_custom_dialog, 
               g_strdup_printf("Received %d messages from history", count));
}

// Callback pour les changements de statut utilisateur
void on_user_status_changed(const char* username, bool is_online) {
    log_client_message(LOG_INFO, "User status changed");
    char* status_message = g_strdup_printf("User %s is now %s", 
                                         username, 
                                         is_online ? "online" : "offline");
    g_idle_add((GSourceFunc)show_custom_dialog, status_message);
}

// Callback pour la réponse d'enregistrement
void on_register_response(bool success, const char* message) {
    log_client_message(LOG_INFO, "Register response received");
    if (success) {
        g_idle_add((GSourceFunc)show_custom_dialog, 
                   g_strdup("Registration successful"));
        // Retour à l'écran de login
        if (g_stack) {
            g_idle_add((GSourceFunc)gtk_stack_set_visible_child_name, 
                      GINT_TO_POINTER("login"));
        }
    } else {
        g_idle_add((GSourceFunc)show_custom_dialog, 
                   g_strdup_printf("Registration failed: %s", message));
    }
}