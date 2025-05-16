#include "callbacks/LoginCallbacks.h"
#include "network/core/MessageSender.h"
#include "network/core/NetworkCore.h"
#include "network/core/NetworkThread.h"
#include "network/core/SessionManager.h"
#include "network/handlers/LoginMessageHandler.h"
#include "network/log/ClientLogging.h"
#include "graphics/utils/Utils.h"
#include "logic/login/ValidationProcess.h"
#include "graphics/login/UiCreateAccount.h"
#include "graphics/login/UiForgotPassword.h"
#include "graphics/mainapp/UiMainContent.h"
#include "graphics/utils/BottomBar.h"

// Handle login button click event to validate inputs and send login request
void on_login_button_clicked(GtkButton *button, LoginData *data) {
    const char *username = gtk_editable_get_text(GTK_EDITABLE(data->username_entry));
    const char *password = gtk_editable_get_text(GTK_EDITABLE(data->password_entry));

    // Verify if entry are empty
    if (strlen(username) == 0 || strlen(password) == 0) {
        log_client_message(LOG_WARNING, "Login fields are empty");
        show_custom_dialog("Error", "Please fill in all fields");
        return;
    }

    // Validate email
    if (!validate_email(username)) {
        log_client_message(LOG_WARNING, "Invalid email format");
        show_custom_dialog("Error", "Invalid email format");
        return;
    }

    // Validate password
    if (!validate_password(password)) {
        log_client_message(LOG_WARNING, "Invalid password format");
        show_custom_dialog("Error", "Password must be at least\n10 characters long\nand contain uppercase, lowercase,\nnumber and special character");
        return;
    }

    // Send request only if validation are ok
    log_client_message(LOG_INFO, "Sending login request");
    if (!send_login_request(username, password)) {
        show_custom_dialog("Error", "Failed to send login request");
        return;
    }
}
// Display create account page
void show_create_account(GtkWidget *widget, gpointer stack) {
    log_client_message(LOG_INFO, "Displaying create account page");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "create_account");
}

// Display forgot password page
void show_forgot_password(GtkWidget *widget, gpointer stack) {
    log_client_message(LOG_INFO, "Displaying forgot password page");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "forgot_password");
}

// Display login interface
void show_login(GtkWidget *widget, gpointer stack) {
    log_client_message(LOG_INFO, "Displaying login interface");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "login");
}

// Handle disconnect button click event to logout and show login interface
void on_disconnect_button_clicked(GtkWidget *widget, gpointer stack) {
    log_client_message(LOG_INFO, "Disconnecting from server");
    
    const char* current_user = get_current_user();
    if (send_disconnect_request(current_user)) {
        log_client_message(LOG_INFO, "Disconnect request sent successfully");
        
        // Re init connection without closing it completely
        if (reinitialize_network_connection()) {
            show_login(widget, stack);
        } else {
            // if re init fail try a bright new connection
            if (safe_reconnect()) {
                show_login(widget, stack);
            } else {
                show_custom_dialog("Error", "Failed to maintain connection. Please restart the application.");
                cleanup_network();
                show_login(widget, stack);
            }
        }
    } else {
        log_client_message(LOG_ERROR, "Failed to send disconnect request");
        show_custom_dialog("Error", "Failed to disconnect properly");
    }
}

// Clean up resources related to the login interface
void cleanup_login_interface(LoginData *data) {
    log_client_message(LOG_INFO, "Cleaning up login interface");
    if (data) {
        g_free(data);
    }
}
