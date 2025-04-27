#include <gtk/gtk.h>

    //Display user page
    void show_user(GtkWidget *widget, gpointer stack)
    {
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "user_profile");
    }
    // Display create server page
    void show_create(GtkWidget *widget, gpointer stack)
    {
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "create_server");
    }
    //Display main interface
    void show_main(GtkWidget *widget, gpointer stack)
    {
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "main_window");
    }
    // Callback for home button
    void on_home_button_clicked(GtkButton *button, gpointer stack)
    {    
        show_main(NULL, stack);
    }