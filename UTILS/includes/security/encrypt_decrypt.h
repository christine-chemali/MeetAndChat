#ifndef ENCRYPT_DECRYPT_H
#define ENCRYPT_DECRYPT_H

#include <stdbool.h>
#include <stddef.h>

bool verify_message_integrity(const char* original, const char* decrypted, size_t length);
void xor_cipher(char *message, const char *key, size_t message_length);
void generate_random_key(char *key, int length);

#endif
