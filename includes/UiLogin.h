#ifndef UILOGIN_H
#define UILOGIN_H

#include <gtk/gtk.h>

void create_login_interface(GtkWidget *stack);
void activate(GtkApplication *app, gpointer user_data);
void on_disconnect_button_clicked(GtkWidget *widget, gpointer stack); 

#endif 