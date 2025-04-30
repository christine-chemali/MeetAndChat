
#ifndef APPDATA_H
#define APPDATA_H

#include <gtk/gtk.h>

// to stock data structure
typedef struct {
    GtkWidget *left_box;
    GtkWidget *stack;
    GList *servers; 
} AppData;

void connect_window_destroy_signal(GtkWidget *window, AppData *data); 

#endif 