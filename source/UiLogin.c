#include <gtk/gtk.h>
#include "UiForgotPassword.h"
#include "UiMainContent.h"
#include "UiCreateAccount.h"
#include "CssLoading.h"
#include "Utils.h"
#include "AppData.h"


//Display Create an account page
static void
show_create_account(GtkWidget *widget, gpointer stack)
{
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "create_account");
}

//Display forgotten password page
static void
show_forgot_password(GtkWidget *widget, gpointer stack)
{
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "forgot_password");
}

//Display first main content / had to adapt to log process
static void
show_main_content(GtkWidget *widget, gpointer stack)
{
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "main_window");
}

//Display login interface
static void
show_login(GtkWidget *widget, gpointer stack)
{
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "login");
}

//Disconnect
void on_disconnect_button_clicked(GtkWidget *widget, gpointer stack) {
    show_login(widget, stack); 
}
// Create Elements of the Login page
void create_login_interface(GtkWidget *stack) {
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
    gtk_widget_set_css_classes(title_label, (const char *[]){"custom-title", NULL}); //css
    gtk_widget_set_margin_top(title_label, 0);

    GtkWidget *text_label = gtk_label_new("We're happy to see you again :)");
    gtk_widget_set_halign(text_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(text_label, (const char *[]){"custom-text", NULL}); //css
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
    gtk_widget_set_css_classes(create_account_link, (const char *[]){"link-account-button", NULL});//css
    
    g_signal_connect(create_account_link, "clicked", G_CALLBACK(show_create_account), stack);
    gtk_box_append(GTK_BOX(create_account_container), small_text_label);
    gtk_box_append(GTK_BOX(create_account_container), create_account_link);
    
    //logo icon 
    GtkWidget *logo_icon = gtk_image_new_from_file("./media/icons/MeetAndChatLogo.png");   
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
    gtk_widget_set_css_classes(username_label, (const char *[]){"custom-label", NULL}); // css

    GtkWidget *username_entry = gtk_entry_new();
    gtk_widget_set_size_request(username_entry, 200, -1);
    gtk_widget_set_css_classes(username_entry, (const char *[]){"custom-entry", NULL}); // css
    gtk_widget_set_margin_bottom(username_entry, 8);

    gtk_box_append(GTK_BOX(username_container), username_label);
    gtk_box_append(GTK_BOX(username_container), username_entry);

    // Password 
    GtkWidget *password_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(password_container, container_width, -1);
    gtk_widget_set_halign(password_container, GTK_ALIGN_CENTER);

    GtkWidget *password_label = gtk_label_new("Password*");
    gtk_widget_set_halign(password_label, GTK_ALIGN_START);
    gtk_widget_set_css_classes(password_label, (const char *[]){"custom-label", NULL}); // css

    GtkWidget *password_entry = gtk_entry_new(); 
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE);
    gtk_widget_set_size_request(password_entry, 200, -1);
    gtk_widget_set_css_classes(password_entry, (const char *[]){"custom-entry", NULL}); // css

    GtkWidget *show_password_check = gtk_check_button_new_with_label("Show");
    gtk_widget_set_halign(show_password_check, GTK_ALIGN_END);
    g_signal_connect(show_password_check, "toggled", G_CALLBACK(toggle_passwordVisibility), password_entry);
    gtk_widget_set_css_classes(show_password_check, (const char *[]){"custom-checkbox", NULL}); // css

    GtkWidget *password_label_checkbox_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_set_spacing(GTK_BOX(password_label_checkbox_box), 115); 
    gtk_box_append(GTK_BOX(password_label_checkbox_box), password_label);
    gtk_box_append(GTK_BOX(password_label_checkbox_box), show_password_check);

    GtkWidget *forgot_password_link = gtk_button_new_with_label("Forgot your password?");
    gtk_widget_set_halign(forgot_password_link, GTK_ALIGN_END);
    gtk_widget_set_css_classes(forgot_password_link, (const char *[]){"link-button", NULL}); // css
    g_signal_connect(forgot_password_link, "clicked", G_CALLBACK(show_forgot_password), stack);

    gtk_box_append(GTK_BOX(password_container), password_label_checkbox_box);
    gtk_box_append(GTK_BOX(password_container), password_entry);
    gtk_box_append(GTK_BOX(password_container), forgot_password_link);

    //Sign In
    GtkWidget *login_button = gtk_button_new_with_label("LOGIN");
    gtk_widget_set_size_request(login_button, 210, -1);
    gtk_widget_set_halign(login_button, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(login_button, 5);

    gtk_widget_set_css_classes(login_button, (const char *[]){"custom-button", NULL});//css
    g_signal_connect(login_button, "clicked", G_CALLBACK(show_main_content), stack);

    // Add container to main box
    gtk_box_append(GTK_BOX(login_box), logo_icon);
    gtk_box_append(GTK_BOX(login_box), title_container);
    gtk_box_append(GTK_BOX(login_box), username_container);
    gtk_box_append(GTK_BOX(login_box), password_container);
    gtk_box_append(GTK_BOX(login_box), login_button);
    gtk_box_append(GTK_BOX(login_box), create_account_container);

    gtk_stack_add_named(GTK_STACK(stack), login_box, "login");
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

    const char *window_classes[] = {"window", NULL};//css
    gtk_widget_set_css_classes(window, window_classes);//css
   
    AppData *data = malloc(sizeof(AppData));    
        if (!data) {        
            g_critical("Unable to allocate AppData");       
             return;    
    } 

    data->left_box = NULL;     
    data->stack = stack;     
    data->servers = NULL;    
    
    connect_window_destroy_signal(window, data);

    create_login_interface(stack);

    show_create_account_content(stack, G_CALLBACK(show_login));   
    show_first_main_content(stack, G_CALLBACK(show_login)); 
    show_forgot_password_content(stack, G_CALLBACK(show_login));

    gtk_stack_set_visible_child_name(GTK_STACK(stack), "login");
    gtk_window_present(GTK_WINDOW(window));
}
