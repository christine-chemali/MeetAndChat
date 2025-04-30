#ifndef UINOTIFICATION_H
#define UINOTIFICATION_H

#include <gtk/gtk.h> 

void show_notification_content(GtkWidget *stack, GCallback return_to_main_callback);

#endif