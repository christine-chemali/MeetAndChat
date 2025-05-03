#ifndef CHANNELMANAGER_H
#define CHANNELMANAGER_H

#include <gtk/gtk.h>

void populate_channel_dropdown(GtkDropDown *dropdown);
void delete_selected_channel(GtkWidget *button, GtkDropDown *drop_down);
void handle_create_channel(GtkWidget *button, GtkEntry *entry);

#endif
