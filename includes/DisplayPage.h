#ifndef DISPLAYPAGE_H
#define DISPLAYPAGE_H

#include <gtk/gtk.h>

// Display user page
void show_user(GtkWidget *widget, gpointer stack);

// Display user page
void show_create(GtkWidget *widget, gpointer stack);

// Display main interface
void show_main(GtkWidget *widget, gpointer stack);

// Callback for home button
void on_home_button_clicked(GtkButton *button, gpointer stack);

#endif 