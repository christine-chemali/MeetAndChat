#ifndef UILOGIN_H
#define UILOGIN_H

#include <gtk/gtk.h>

typedef struct {
    GtkEntry *username_entry;
    GtkEntry *password_entry;
    GtkStack *stack;
} LoginData;

void create_login_interface(GtkWidget *stack);
void activate(GtkApplication *app, gpointer user_data);
void on_disconnect_button_clicked(GtkWidget *widget, gpointer stack); 
void show_main_content(GtkWidget *widget, gpointer stack);
void cleanup_login_interface(LoginData *data);

#endif