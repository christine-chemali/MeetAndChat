#ifndef UTILS_H
#define UTILS_H

#include <gtk/gtk.h>

void toggle_passwordVisibility(GtkWidget *widget, gpointer data);
void show_custom_dialog(const char *title, const char *message);

#endif 