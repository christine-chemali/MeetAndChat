#include <gtk/gtk.h>
#include <stdlib.h>
#include <glib.h>

//Password visibility
void
toggle_passwordVisibility(GtkWidget *widget, gpointer data)
{
    GtkWidget *password_entry = data;
    gboolean visible = gtk_entry_get_visibility(GTK_ENTRY(password_entry));
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), !visible);
}

// Error, info popup dialog box
   void show_custom_dialog(const char *title, const char *message) {

    char* utf8_message = g_utf8_make_valid(message, -1);

    GtkApplication *app = GTK_APPLICATION(g_application_get_default());
    GtkWindow *parent_window = app ? gtk_application_get_active_window(app) : NULL;

    GtkWidget *dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog), title);
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 320, -1);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE); 
    gtk_widget_set_css_classes(dialog, (const char *[]){"dialog_box", NULL});

    if (parent_window) {
        gtk_window_set_transient_for(GTK_WINDOW(dialog), parent_window);
    }

    GtkWidget *content_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_window_set_child(GTK_WINDOW(dialog), content_box);

    gtk_widget_set_margin_start(content_box, 10);
    gtk_widget_set_margin_end(content_box, 10);
    gtk_widget_set_margin_top(content_box, 10);
    gtk_widget_set_margin_bottom(content_box, 10);

    //GtkWidget *pop_label = gtk_label_new(message);
    GtkWidget *pop_label = gtk_label_new(utf8_message); 
    gtk_label_set_wrap(GTK_LABEL(pop_label), TRUE); //*Rmber
    gtk_widget_set_css_classes(pop_label, (const char *[]){"custom-label", NULL});
    gtk_box_append(GTK_BOX(content_box), pop_label);

    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_halign(button_box, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(content_box), button_box);

    GtkWidget *ok_button = gtk_button_new_with_label("OK");
    gtk_widget_set_css_classes(ok_button, (const char *[]){"ok-custom-button", NULL});
    gtk_widget_set_hexpand(ok_button, FALSE); 
    gtk_widget_set_size_request(ok_button, 40, -1); 
    g_signal_connect_swapped(ok_button, "clicked", G_CALLBACK(gtk_window_destroy), dialog);
    gtk_box_append(GTK_BOX(button_box), ok_button);

    g_free(utf8_message);
    gtk_window_present(GTK_WINDOW(dialog));
}