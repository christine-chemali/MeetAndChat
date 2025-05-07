#ifndef UILOGIN_H
#define UILOGIN_H

#include <gtk/gtk.h>
#include "callbacks/LoginCallbacks.h"

void create_login_interface(GtkWidget *stack);
void activate(GtkApplication *app, gpointer user_data);

#endif