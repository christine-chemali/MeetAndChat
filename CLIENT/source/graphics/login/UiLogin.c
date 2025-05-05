#include <gtk/gtk.h>
#include "network/handlenetwork/NetworkHandlers.h"
#include "graphics/login/UiCreateAccount.h"
#include "graphics/mainapp/UiMainContent.h"
#include "graphics/login/UiForgotPassword.h"
#include "graphics/utils/CssLoading.h"
#include "graphics/utils/Utils.h"
#include "graphics/utils/AppData.h"
#include "logic/login/ValidationProcess.h"
#include "callbacks/GuiCallbacks.h"

// struct to stock necessary widgets
typedef struct {
    GtkEntry *username_entry;
    GtkEntry *password_entry;
    GtkStack *stack;
} LoginData;

// Send login request when login button is clicked
static void on_login_button_clicked(GtkButton *button, LoginData *data) {

    const char *username = gtk_editable_get_text(GTK_EDITABLE(data->username_entry));
    const char *password = gtk_editable_get_text(GTK_EDITABLE(data->password_entry));

    // handle network connection errors
    if (!isConnected) {
        log_client_message(LOG_ERROR, "Not connected to server");
        show_custom_dialog("Error", "Not connected to server");
        return;
    }

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

//Display Create an account page
static void
show_create_account(GtkWidget *widget, gpointer stack)
{
    log_client_message(LOG_INFO, "Displaying create account page");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "create_account");
}

//Display forgotten password page
static void
show_forgot_password(GtkWidget *widget, gpointer stack)
{
    log_client_message(LOG_INFO, "Displaying forgot password page");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "forgot_password");
}

//Display first main content 
static gboolean
local_show_main_content(GtkWidget *widget, gpointer stack)
{
    log_client_message(LOG_INFO, "Displaying home content page");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "main_window");
    return TRUE;
}

//Display login interface
static void
show_login(GtkWidget *widget, gpointer stack)
{
    log_client_message(LOG_INFO, "Displaying login interface");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "login");
}

//Disconnect
void on_disconnect_button_clicked(GtkWidget *widget, gpointer stack) {
    log_client_message(LOG_INFO, "Disconnecting from server");
    send_logout_request();
    show_login(widget, stack); 
}

// clean login interface
void cleanup_login_interface(LoginData *data) {
    log_client_message(LOG_INFO, "Cleaning up login interface");
    disconnect_from_server();
    g_free(data);
}

// Create Elements of the Login page
void create_login_interface(GtkWidget *stack) {

    log_client_message(LOG_INFO, "Creating login interface");
    // Stock callbacks stack
    set_gui_stack(stack); 

    GtkWidget *login_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(login_box, 0);
    gtk_widget_set_margin_bottom(login_box, 20);
    gtk_widget_set_margin_start(login_box, 20);
    gtk_widget_set_margin_end(login_box, 20);

    int container_width = 220;

    // Title container : Welcome back & text
    GtkWidget *title_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_size_request(title_container, container_width, -1);
    gtk_widget_set_halign(title_container, GTK_ALIGN_CENTER);

    GtkWidget *title_label = gtk_label_new("WELCOME BACK!");
    gtk_widget_set_halign(title_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(title_label, (const char *[]){"custom-title", NULL}); 
    gtk_widget_set_margin_top(title_label, 0);

    GtkWidget *text_label = gtk_label_new("We're happy to see you again :)");
    gtk_widget_set_halign(text_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(text_label, (const char *[]){"custom-text", NULL}); 
    gtk_widget_set_margin_top(text_label, 0);
    gtk_widget_set_margin_bottom(text_label, 10);

    gtk_box_append(GTK_BOX(title_container), title_label); 
    gtk_box_append(GTK_BOX(title_container), text_label); 

    //Create an account
    GtkWidget *create_account_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(create_account_container, container_width, -1);
    gtk_widget_set_halign(create_account_container, GTK_ALIGN_CENTER);

    GtkWidget *small_text_label = gtk_label_new("OR");
    gtk_widget_set_halign(small_text_label, GTK_ALIGN_CENTER);
    gtk_widget_set_css_classes(small_text_label, (const char *[]){"small-custom-text", NULL});
    gtk_widget_set_margin_top(small_text_label, 10);

    GtkWidget *create_account_link = gtk_button_new_with_label("CREATE AN ACCOUNT");
    gtk_widget_set_halign(create_account_link, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(create_account_link, 0);
    gtk_widget_set_css_classes(create_account_link, (const char *[]){"link-account-button", NULL});
    
    g_signal_connect(create_account_link, "clicked", G_CALLBACK(show_create_account), stack);
    gtk_box_append(GTK_BOX(create_account_container), small_text_label);
    gtk_box_append(GTK_BOX(create_account_container), create_account_link);
    
    //logo icon 
    GtkWidget *logo_icon = gtk_image_new_from_file("CLIENT/media/icons/MeetAndChatLogo.png");   
    int desired_width = 123;   
    int desired_height = 200; 
    gtk_widget_set_size_request(logo_icon, desired_width, desired_height);
    gtk_widget_set_margin_top(logo_icon, 0); 
    gtk_widget_set_margin_bottom(logo_icon, 0); 
    gtk_widget_set_css_classes(logo_icon, (const char *[]){"logo", NULL}); 

    // Email 
    GtkWidget *username_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(username_container, container_width, -1);
    gtk_widget_set_halign(username_container, GTK_ALIGN_CENTER);

    GtkWidget *username_label = gtk_label_new("Email*");
    gtk_widget_set_halign(username_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(username_label, (const char *[]){"custom-label", NULL}); 

    GtkWidget *username_entry = gtk_entry_new();
    gtk_widget_set_size_request(username_entry, 200, -1);
    gtk_widget_set_css_classes(username_entry, (const char *[]){"custom-entry", NULL});
    gtk_widget_set_margin_bottom(username_entry, 8);

    gtk_box_append(GTK_BOX(username_container), username_label);
    gtk_box_append(GTK_BOX(username_container), username_entry);

    // Password 
    GtkWidget *password_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(password_container, container_width, -1);
    gtk_widget_set_halign(password_container, GTK_ALIGN_CENTER);

    GtkWidget *password_label = gtk_label_new("Password*");
    gtk_widget_set_halign(password_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(password_label, (const char *[]){"custom-label", NULL}); 

    GtkWidget *password_entry = gtk_entry_new(); 
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE);
    gtk_widget_set_size_request(password_entry, 200, -1);
    gtk_widget_set_css_classes(password_entry, (const char *[]){"custom-entry", NULL}); 

        //login data struct 
        LoginData *data = g_new(LoginData, 1);
        data->username_entry = GTK_ENTRY(username_entry);
        data->password_entry = GTK_ENTRY(password_entry);
        data->stack = GTK_STACK(stack);

    GtkWidget *show_password_check = gtk_check_button_new_with_label("Show");
    gtk_widget_set_halign(show_password_check, GTK_ALIGN_END);
    g_signal_connect(show_password_check, "toggled", G_CALLBACK(toggle_passwordVisibility), password_entry);
    gtk_widget_set_css_classes(show_password_check, (const char *[]){"custom-checkbox", NULL}); 

    GtkWidget *password_label_checkbox_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_set_spacing(GTK_BOX(password_label_checkbox_box), 115); 
    gtk_box_append(GTK_BOX(password_label_checkbox_box), password_label);
    gtk_box_append(GTK_BOX(password_label_checkbox_box), show_password_check);

    GtkWidget *forgot_password_link = gtk_button_new_with_label("Forgot your password?");
    gtk_widget_set_halign(forgot_password_link, GTK_ALIGN_END);
    gtk_widget_set_css_classes(forgot_password_link, (const char *[]){"link-button", NULL}); 
    g_signal_connect(forgot_password_link, "clicked", G_CALLBACK(show_forgot_password), stack);

    gtk_box_append(GTK_BOX(password_container), password_label_checkbox_box);
    gtk_box_append(GTK_BOX(password_container), password_entry);
    gtk_box_append(GTK_BOX(password_container), forgot_password_link);

    //Sign In
    GtkWidget *login_button = gtk_button_new_with_label("LOGIN");
    gtk_widget_set_size_request(login_button, 210, -1);
    gtk_widget_set_halign(login_button, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(login_button, 5);

    gtk_widget_set_css_classes(login_button, (const char *[]){"custom-button", NULL});
    g_signal_connect(login_button, "clicked", G_CALLBACK(on_login_button_clicked), data);
    /*g_signal_connect(login_button, "clicked", G_CALLBACK(show_main_content), stack);*/

    // Add container to main box
    gtk_box_append(GTK_BOX(login_box), logo_icon);
    gtk_box_append(GTK_BOX(login_box), title_container);
    gtk_box_append(GTK_BOX(login_box), username_container);
    gtk_box_append(GTK_BOX(login_box), password_container);
    gtk_box_append(GTK_BOX(login_box), login_button);
    gtk_box_append(GTK_BOX(login_box), create_account_container);

    gtk_stack_add_named(GTK_STACK(stack), login_box, "login");
    log_client_message(LOG_INFO, "Login interface created");
}

//Initialize the main app window 
void
activate(GtkApplication *app, gpointer user_data)
{
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "MEET & CHAT");
    gtk_window_set_default_size(GTK_WINDOW(window), 360, 640);

    load_application_css(GTK_WINDOW(window)); 

    GtkWidget *stack = gtk_stack_new();
    gtk_window_set_child(GTK_WINDOW(window), stack);

    const char *window_classes[] = {"window", NULL};
    gtk_widget_set_css_classes(window, window_classes);
   
    AppData *data = malloc(sizeof(AppData));    
        if (!data) {        
            g_critical("Unable to allocate AppData");       
             return;    
    } 

    data->left_box = NULL;     
    data->stack = stack;     
    
    connect_window_destroy_signal(window, data);

    create_login_interface(stack);

    show_create_account_content(stack, G_CALLBACK(show_login));   
    show_first_main_content(stack, G_CALLBACK(show_login)); 
    show_forgot_password_content(stack, G_CALLBACK(show_login));

    gtk_stack_set_visible_child_name(GTK_STACK(stack), "login");
    gtk_window_present(GTK_WINDOW(window));
}
