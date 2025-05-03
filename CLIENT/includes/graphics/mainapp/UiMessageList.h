#ifndef UIMESSAGELIST_H
#define UIMESSAGELIST_H

#include <gtk/gtk.h>
#include "graphics/utils/AppData.h"

void display_messages(GtkStack *stack);
void display_conversation(GtkStack *stack, const char *username);
void update_user_list(GtkWidget *messages_box, const char **usernames, int num_users);

#endif
