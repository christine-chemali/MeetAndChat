#ifndef CATEGORYMANAGER_H
#define CATEGORYMANAGER_H

#include <gtk/gtk.h>

void populate_category_dropdown(GtkDropDown *dropdown);
void delete_selected_category(GtkWidget *button, GtkDropDown *drop_down);
void handle_create_category(GtkWidget *button, GtkEntry *entry);

#endif