#include <gtk/gtk.h>

//Password visibility
void
toggle_passwordVisibility(GtkWidget *widget, gpointer data)
{
    GtkWidget *password_entry = data;
    gboolean visible = gtk_entry_get_visibility(GTK_ENTRY(password_entry));
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), !visible);
}
