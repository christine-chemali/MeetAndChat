#include <gtk/gtk.h>
#include "graphics/mainapp/UiCreateCategory.h"
#include "graphics/utils/BottomBar.h"
#include "graphics/utils/DisplayPage.h"
#include "network/mainapp/CategoryManager.h"
#include "graphics/utils/TopBar.h"


//Create  category content page
void show_create_category_content(GtkWidget *stack, GCallback return_to_main_callback) {
    // main box
    GtkWidget *create_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_top(create_box, 0);
    gtk_widget_set_margin_bottom(create_box, 8);
    gtk_widget_set_margin_start(create_box, 0);
    gtk_widget_set_margin_end(create_box, 0);

    int container_width = 220;

    // scroll box
    GtkWidget *scrolled_window = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_css_classes(scrolled_window, (const char*[]){"scroll", NULL});
    gtk_widget_set_hexpand(scrolled_window, TRUE); 
    gtk_widget_set_vexpand(scrolled_window, TRUE); 

    // Scroll box content
    GtkWidget *create_content_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(create_content_box, 220, -1); 
    gtk_widget_set_halign(create_content_box, GTK_ALIGN_FILL);
    gtk_widget_set_margin_top(create_content_box, 0);
    gtk_widget_set_margin_bottom(create_content_box, 0);
    gtk_widget_set_margin_start(create_content_box, 0);
    gtk_widget_set_margin_end(create_content_box, 0);
    gtk_widget_set_css_classes(create_content_box, (const char*[]){"user-area", NULL});
    gtk_widget_set_hexpand(create_content_box, TRUE);

    //Container for Labels and buttons
    GtkWidget *create_category = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_size_request(create_category, container_width, -1);
    gtk_widget_set_halign(create_category, GTK_ALIGN_CENTER);

    // Top bar
    GtkWidget *top_bar = create_top_bar(stack);
    gtk_box_append(GTK_BOX(create_category), top_bar);
    
    // Title
    GtkWidget *create_category_title = gtk_label_new("Set up a category");
    gtk_widget_set_halign(create_category_title, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_start(create_category_title, 0);
    gtk_widget_set_margin_top(create_category_title, 10);
    gtk_widget_set_css_classes(create_category_title, (const char *[]){"custom-title", NULL});
    gtk_box_append(GTK_BOX(create_category), create_category_title);

    //Label
    GtkWidget *create_category_label = gtk_label_new("CREATE A CATEGORY");
    gtk_widget_set_halign(create_category_label, GTK_ALIGN_START);
    gtk_widget_set_margin_start(create_category_label, 0);
    gtk_widget_set_margin_top(create_category_label, 10);
    gtk_widget_set_css_classes(create_category_label, (const char *[]){"custom-label-title", NULL});
    gtk_box_append(GTK_BOX(create_category), create_category_label);

    //entry
    GtkWidget *create_category_entry = gtk_entry_new();
    gtk_widget_set_size_request(create_category_entry, 200, -1);
    gtk_entry_set_placeholder_text(GTK_ENTRY(create_category_entry), "Category name");
    gtk_widget_set_css_classes(create_category_entry, (const char *[]){"custom-entry", NULL});
    gtk_box_append(GTK_BOX(create_category), create_category_entry);
    
    // Private Category Box
    GtkWidget *private_category_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

     // Private Channel Description
     GtkWidget *private_category_description = gtk_label_new("Private category can only be accessed\nby selected members and roles.");
     gtk_label_set_wrap(GTK_LABEL(private_category_description), TRUE);
     gtk_widget_set_size_request(private_category_description, 90, -1);
     gtk_widget_set_halign(private_category_description, GTK_ALIGN_START);
     gtk_widget_set_margin_top(private_category_description, 5);

     // Private Toggle Box
     GtkWidget *private_toggle_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);

     // Private Channel Icon
     GtkWidget *private_category_icon = gtk_image_new_from_file("CLIENT/media/icons/lock.png");
     gtk_widget_set_size_request(private_category_icon, 24, 24);
     
     // Private Channel Label
     GtkWidget *private_label = gtk_label_new("Private Category");
     gtk_widget_set_halign(private_label, GTK_ALIGN_START);
     gtk_widget_set_css_classes(private_label, (const char*[]){"custom-sublabel", NULL});
 
     // Private Toggle Switch
     GtkWidget *private_switch = gtk_switch_new();
     gtk_widget_set_margin_start(private_switch, 40);
     gtk_widget_set_css_classes(private_switch, (const char*[]){"small-switch", NULL});

     gtk_box_append(GTK_BOX(private_toggle_box), private_category_icon);
     gtk_box_append(GTK_BOX(private_toggle_box), private_label);
     gtk_box_append(GTK_BOX(private_toggle_box), private_switch);
 
     gtk_box_append(GTK_BOX(private_category_box), private_category_description);
     gtk_box_append(GTK_BOX(private_category_box), private_toggle_box);
     gtk_box_append(GTK_BOX(create_category), private_category_box);

    //button
    GtkWidget *create_category_button = gtk_button_new_with_label("ADD A NEW CATEGORY");
    g_signal_connect(create_category_button, "clicked", G_CALLBACK(handle_create_category), create_category_entry);
    gtk_widget_set_css_classes(create_category_button,(const char *[]){"custom-button", NULL});
    gtk_widget_set_margin_top(create_category_button, 5);
    gtk_box_append(GTK_BOX(create_category), create_category_button);

    // Delete a category
    GtkWidget *delete_category_label_title = gtk_label_new("DELETE A CATEGORY");
    gtk_widget_set_halign(delete_category_label_title, GTK_ALIGN_START);
    gtk_widget_set_margin_start(delete_category_label_title, 0);
    gtk_widget_set_margin_top(delete_category_label_title, 10);
    gtk_widget_set_css_classes(delete_category_label_title, (const char *[]){"custom-label-title", NULL});
    
    // Category dropdown list
    GtkWidget *dropdown_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *category_dropdown = gtk_drop_down_new(NULL, NULL);
    populate_category_dropdown(GTK_DROP_DOWN(category_dropdown));

    //Delete category button
    GtkWidget *delete_category_button = gtk_button_new_with_label("DELETE THE SELECTED CATEGORY");
    gtk_widget_set_css_classes(delete_category_button, (const char *[]){"custom-button", NULL});
    gtk_widget_set_margin_top(delete_category_button, 5); 

    g_signal_connect(delete_category_button, "clicked", G_CALLBACK(delete_selected_category), category_dropdown);
   
    //Append 
    gtk_box_append(GTK_BOX(create_content_box), create_category);
    gtk_box_append(GTK_BOX(create_category), delete_category_label_title);
    gtk_box_append(GTK_BOX(dropdown_box), category_dropdown);
    gtk_box_append(GTK_BOX(dropdown_box), delete_category_button);

    gtk_box_append(GTK_BOX(create_category), dropdown_box);

    // Add content to scroll box
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), create_content_box);

    // Bottom nav bar
    GtkWidget *bottom_bar = create_bottom_bar(stack, return_to_main_callback);    
    gtk_box_append(GTK_BOX(create_box), scrolled_window);
    gtk_box_append(GTK_BOX(create_box), bottom_bar);

    // Add main box to stack
    gtk_stack_add_named(GTK_STACK(stack), create_box, "create_category");
}