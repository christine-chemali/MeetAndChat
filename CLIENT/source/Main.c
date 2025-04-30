#include <gtk/gtk.h>
#include "graphics/utils/CssLoading.h"
#include "graphics/login/UiLogin.h"

//main 
int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("org.gtk.example", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);

    status = g_application_run(G_APPLICATION(app), argc, argv);

    if (status == 0) {
        GtkWindow *window = gtk_application_get_active_window(app);
        if (window) {
            load_application_css(window);
        }
    }

    g_object_unref(app);
    return status;
}
