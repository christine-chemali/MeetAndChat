/* 
#ifndef UICREATESERVER_H
#define UICREATESERVER_H

#include <gtk/gtk.h>
#include "AppData.h"

void show_create_server_content(GtkWidget *button, AppData *data);

#endif 
*/
#ifndef UICREATESERVER_H
#define UICREATESERVER_H

void show_create_server_content(GtkWidget *stack, GCallback return_to_main_callback);

#endif