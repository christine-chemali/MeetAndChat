#ifndef CHANNELMANAGER_H
#define CHANNELMANAGER_H

#include <gtk/gtk.h>

// Current version functions
void populate_channel_dropdown(GtkDropDown *dropdown);
void delete_selected_channel(GtkWidget *button, GtkDropDown *drop_down);
void handle_create_channel(GtkWidget *button, GtkEntry *entry);

// Future network version
/*
#include <curl/curl.h>
#include <glib.h>

// Data structures
struct string {
    char *ptr;
    size_t len;
};

// String handling functions
void init_string(struct string *s);
size_t write_callback(void *ptr, size_t size, size_t nmemb, struct string *s);

// Network operations
gpointer fetch_channels(gpointer data);
gpointer create_channel_request(gpointer data);
gpointer delete_channel(gpointer data);
*/

#endif
