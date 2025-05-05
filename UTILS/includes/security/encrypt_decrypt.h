#ifndef ENCRYPT_DECRYPT_H
#define ENCRYPT_DECRYPT_H

#include <stdbool.h>

void xor_cipher(char *message, const char *key);
void generate_random_key(char *key, int length);
bool verify_message_integrity(const char* original, const char* decrypted);

#endif 
//vs
