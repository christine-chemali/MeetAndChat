#ifndef CHANNELMANAGER_H
#define CHANNELMANAGER_H

#include <gtk/gtk.h>

// Current version functions
void populate_channel_dropdown(GtkDropDown *dropdown);
void delete_selected_channel(GtkWidget *button, GtkDropDown *drop_down);

// Future network version (commented out until needed)
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

// Dropdown update helpers
static gboolean update_dropdown(gpointer user_data);
static gboolean append_to_dropdown(gpointer user_data);

// Network operations
gpointer fetch_channels(gpointer data);
gpointer delete_channel(gpointer data);

// Main interface function
void delete_selected_channel(GtkWidget *button, GtkDropDown *drop_down);

// Channel management functions
void update_dropdown_with_channels(GtkDropDown *dropdown, const char *channels_str);
*/

#endif
