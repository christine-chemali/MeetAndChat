#ifndef CREATEACCOUNTCALLBACKS_H
#define CREATEACCOUNTCALLBACKS_H

#include <gtk/gtk.h>

typedef struct {
    GtkEntry *first_name_entry;
    GtkEntry *last_name_entry;
    GtkEntry *username_entry;
    GtkEntry *email_entry;
    GtkEntry *password_entry;
    GtkEntry *retype_password_entry;
    GtkEntry *first_question_entry;
    GtkEntry *second_question_entry;
    GtkStack *stack;
} CreateAccountData;

void on_create_account_button_clicked(GtkButton *button, CreateAccountData *data);
void cleanup_create_account_interface(CreateAccountData *data);

#endif