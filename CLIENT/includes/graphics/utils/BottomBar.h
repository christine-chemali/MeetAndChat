#ifndef BOTTOMBAR_H
#define BOTTOMBAR_H

#include <gtk/gtk.h>
#include "callbacks/LoginCallbacks.h"

GtkWidget *create_bottom_bar(GtkWidget *stack, GCallback return_to_login_callback);

#endif