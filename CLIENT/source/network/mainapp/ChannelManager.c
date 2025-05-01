#include <gtk/gtk.h>
#include <stdlib.h>

// Function to populate channel dropdown
void populate_channel_dropdown(GtkDropDown *dropdown) {

    GtkStringList *string_list = gtk_string_list_new(NULL);
    
    const char *channels[] = {"channel 1", "channel 2", "channel 3", NULL};
    for (int i = 0; channels[i] != NULL; i++) {
        gtk_string_list_append(string_list, channels[i]);
    }
    
    gtk_drop_down_set_model(dropdown, G_LIST_MODEL(string_list));
}

// Function to delete the selected channel
void delete_selected_channel(GtkWidget *button, GtkDropDown *drop_down) {
    guint selected_index = gtk_drop_down_get_selected(drop_down);
    GtkStringObject *selected_item = GTK_STRING_OBJECT(gtk_drop_down_get_selected_item(drop_down));
    
    if (selected_item) {
        const char *selected_channel = gtk_string_object_get_string(selected_item);
        g_print("Deleting channel: %s\n", selected_channel);
    } else {
        g_print("No channel selected.\n");
    }
}

/*
// when server ready 
#include <gtk/gtk.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include <glib.h>

struct string {
    char *ptr;
    size_t len;
};

void init_string(struct string *s) {
    s->len = 0;
    s->ptr = malloc(1);
    s->ptr[0] = '\0';
}

size_t write_callback(void *ptr, size_t size, size_t nmemb, struct string *s) {
    size_t new_len = s->len + size * nmemb;
    s->ptr = realloc(s->ptr, new_len + 1);
    if (s->ptr == NULL) {
        fprintf(stderr, "realloc() failed\n");
        return 0;
    }
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;
    return size * nmemb;
}

static gboolean update_dropdown(gpointer user_data) {
    GtkDropDown *drop_down = GTK_DROP_DOWN(user_data);
    GtkStringList *string_list = gtk_string_list_new(NULL);
    gtk_drop_down_set_model(drop_down, G_LIST_MODEL(string_list));
    return G_SOURCE_REMOVE;
}

static gboolean append_to_dropdown(gpointer user_data) {
    struct {
        GtkDropDown *drop_down;
        char *channel;
    } *data = user_data;

    GtkStringList *string_list;
    if (gtk_drop_down_get_model(data->drop_down) == NULL) {
        string_list = gtk_string_list_new(NULL);
        gtk_drop_down_set_model(data->drop_down, G_LIST_MODEL(string_list));
    } else {
        string_list = GTK_STRING_LIST(gtk_drop_down_get_model(data->drop_down));
    }

    gtk_string_list_append(string_list, data->channel);
    g_free(data->channel);
    g_free(data);
    return G_SOURCE_REMOVE;
}

gpointer fetch_channels(gpointer data) {
    GtkDropDown *drop_down = GTK_DROP_DOWN(data);
    CURL *curl;
    CURLcode res;
    struct string s;
    init_string(&s);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8081/api/channels");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
        } else {
            g_idle_add(update_dropdown, drop_down);
            
            char *token = strtok(s.ptr, ",");
            while (token) {
                struct {
                    GtkDropDown *drop_down;
                    char *channel;
                } *append_data = g_new(typeof(*append_data), 1);
                
                append_data->drop_down = drop_down;
                append_data->channel = g_strdup(g_strstrip(token));
                
                g_idle_add(append_to_dropdown, append_data);
                token = strtok(NULL, ",");
            }
        }

        curl_easy_cleanup(curl);
    }

    free(s.ptr);
    curl_global_cleanup();
    return NULL;
}

gpointer delete_channel(gpointer data) {
    gpointer *params = (gpointer *)data;
    const gchar *selected_channel = (const gchar *)params[0];
    GtkDropDown *drop_down = (GtkDropDown *)params[1];

    if (selected_channel) {
        CURL *curl;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
        if (curl) {
            char url[256];
            snprintf(url, sizeof(url), "http://127.0.0.1:8081/api/channels/%s", selected_channel);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
            } else {
                g_print("Deleted channel: %s\n", selected_channel);
                g_idle_add((GSourceFunc)fetch_channels, drop_down);
            }

            curl_easy_cleanup(curl);
        }
        curl_global_cleanup();
    }

    g_free((gpointer)selected_channel);
    return NULL;
}

void delete_selected_channel(GtkWidget *button, GtkDropDown *drop_down) {
    GtkStringObject *selected_item = GTK_STRING_OBJECT(gtk_drop_down_get_selected_item(drop_down));

    if (selected_item) {
        const char *selected_channel = gtk_string_object_get_string(selected_item);
        gchar *selected_channel_copy = g_strdup(selected_channel);

        gpointer *params = g_new(gpointer, 2);
        params[0] = selected_channel_copy;
        params[1] = drop_down;

        g_thread_new("delete_channel_thread", delete_channel, params);
    } else {
        g_print("No channel selected.\n");
    }
}
*/