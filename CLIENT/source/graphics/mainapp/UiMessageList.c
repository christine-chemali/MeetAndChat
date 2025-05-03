#include <gtk/gtk.h>
#include <stdlib.h>
#include "graphics/mainapp/UiMessageList.h"
#include "network/handlenetwork/NetworkHandlers.h"
#include "network/log/ClientLogging.h"

//when user name is clicked
static void on_user_button_clicked(GtkButton *button, const char *username) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "User button clicked for: %s", username);
    log_client_message(LOG_DEBUG, log_message);

    GtkWidget *stack = gtk_widget_get_ancestor(GTK_WIDGET(button), GTK_TYPE_STACK);
    if (stack) {
        char *page_name = g_strdup_printf("conversation_%s", username);
        GtkWidget *existing_page = gtk_stack_get_child_by_name(GTK_STACK(stack), page_name);
        
        if (existing_page) {
            gtk_stack_set_visible_child(GTK_STACK(stack), existing_page);
            notify_server_conversation_opened(username);
            subscribe_to_messages(username);
            g_free(page_name);
        } else {
            request_conversation_history(username);
            subscribe_to_messages(username);
            display_conversation(GTK_STACK(stack), username);
            g_free(page_name);
        }
    }
}

// When send button is clicked
static void on_send_message(GtkButton *button, GtkEntry *entry) {
    // Cast GtkEntry to GtkEditable and get the text from the entry widget
    const char *message = gtk_editable_get_text(GTK_EDITABLE(entry));

    if (message && *message) {
        char log_message[512];
        snprintf(log_message, sizeof(log_message), "Sending message from UI: %s", message);
        log_client_message(LOG_DEBUG, log_message);
        
        // Send the message
        send_message("current_user", message);
        
        // Clear the entry 
        gtk_editable_set_text(GTK_EDITABLE(entry), "");
    }
}

// Display conversation between two users
void display_conversation(GtkStack *stack, const char *username) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Displaying conversation for user: %s", username);
    log_client_message(LOG_INFO, log_message);

    char *page_name = g_strdup_printf("conversation_%s", username);
    GtkWidget *existing_page = gtk_stack_get_child_by_name(stack, page_name);
    
    if (existing_page) {
        gtk_stack_set_visible_child(stack, existing_page);
        request_conversation_history(username);
        g_free(page_name);
        return;
    }

    GtkWidget *conversation_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(conversation_container, 20);
    gtk_widget_set_margin_bottom(conversation_container, 8);
    gtk_widget_set_margin_start(conversation_container, 8);
    gtk_widget_set_margin_end(conversation_container, 0);

    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    GtkWidget *username_label = gtk_label_new(username);
    gtk_box_append(GTK_BOX(header), username_label);

    GtkWidget *messages_area = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), messages_area);
    gtk_widget_set_vexpand(scrolled, TRUE);

    GtkWidget *input_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *send_button = gtk_button_new_with_label("Send");
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_box_append(GTK_BOX(input_box), entry);
    gtk_box_append(GTK_BOX(input_box), send_button);

    g_signal_connect(send_button, "clicked", G_CALLBACK(on_send_message), entry);

    gtk_box_append(GTK_BOX(conversation_container), header);
    gtk_box_append(GTK_BOX(conversation_container), scrolled);
    gtk_box_append(GTK_BOX(conversation_container), input_box);

    gtk_stack_add_named(stack, conversation_container, page_name);
    gtk_stack_set_visible_child(stack, conversation_container);
    g_free(page_name);
}

//To update the users list
void update_user_list(GtkWidget *messages_box, const char **usernames, int num_users) {
    char log_message[256];
    snprintf(log_message, sizeof(log_message), "Updating user list with %d users", num_users);
    log_client_message(LOG_INFO, log_message);

    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(messages_box)) != NULL) {
        gtk_box_remove(GTK_BOX(messages_box), child);
    }

    GtkWidget *user_list_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    for (int i = 0; i < num_users; i++) {
        GtkWidget *user_button = gtk_button_new_with_label(usernames[i]);
        gtk_widget_set_halign(user_button, GTK_ALIGN_FILL);
        
        char *username_copy = g_strdup(usernames[i]);
        g_signal_connect(user_button, "clicked",
                        G_CALLBACK(on_user_button_clicked),
                        username_copy);
        g_signal_connect_swapped(user_button, "destroy",
                               G_CALLBACK(g_free),
                               username_copy);
        
        gtk_box_append(GTK_BOX(user_list_box), user_button);
    }

    gtk_box_append(GTK_BOX(messages_box), user_list_box);
}

//To free memory 
//TODO: Update this function when network ready
void free_usernames(const char **usernames) {
    log_client_message(LOG_DEBUG, "Freeing username list");
    for (int i = 0; i < 50; i++) {
        g_free((gpointer)usernames[i]);
    }
}

//To Display a list of the current conversations the log in user have with other users
void display_messages(GtkStack *stack) {
    log_client_message(LOG_INFO, "Initializing messages display");

    GtkWidget *main_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(main_container, 20);
    gtk_widget_set_margin_bottom(main_container, 8);
    gtk_widget_set_margin_start(main_container, 8);
    gtk_widget_set_margin_end(main_container, 0);

    GtkWidget *messages_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    GtkWidget *scrolled_window = gtk_scrolled_window_new();
    gtk_widget_set_margin_start(scrolled_window, 10);
    gtk_widget_set_css_classes(scrolled_window, (const char*[]){"channel-area", NULL});
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), 
                                 GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_hexpand(scrolled_window, TRUE);
    gtk_widget_set_vexpand(scrolled_window, TRUE);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), messages_box);

    const char *usernames[50];
    for (int i = 0; i < 50; i++) {
        usernames[i] = g_strdup_printf("User%d", i + 1);
    }
    int num_users = sizeof(usernames) / sizeof(usernames[0]);

    update_user_list(messages_box, usernames, num_users);

    gtk_box_append(GTK_BOX(main_container), scrolled_window);

    gtk_stack_add_named(stack, main_container, "messages_window");
    gtk_stack_set_visible_child(stack, main_container);
    
    g_signal_connect(main_container, "destroy", G_CALLBACK(free_usernames), usernames);
}