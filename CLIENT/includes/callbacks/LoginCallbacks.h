#ifndef LOGINCALLBACKS_H
#define LOGINCALLBACKS_H

#include <gtk/gtk.h>

typedef struct {
    GtkEntry *username_entry;
    GtkEntry *password_entry;
    GtkStack *stack;
} LoginData;

void on_login_button_clicked(GtkButton *button, LoginData *data);
void show_create_account(GtkWidget *widget, gpointer stack);
void show_forgot_password(GtkWidget *widget, gpointer stack);
void show_login(GtkWidget *widget, gpointer stack);
void on_disconnect_button_clicked(GtkWidget *widget, gpointer stack);
void cleanup_login_interface(LoginData *data);
void show_create_account_content(GtkWidget *stack, GCallback callback);
void show_first_main_content(GtkWidget *stack, GCallback callback);
void show_forgot_password_content(GtkWidget *stack, GCallback callback);

#endif