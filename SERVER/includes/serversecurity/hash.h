#ifndef HASH_H
#define HASH_H

#include <stdbool.h>
#include <stddef.h>
#include <openssl/evp.h>

void generate_salt(char *salt, size_t length);
void hash_password(const char *password, const char *salt, char *hashed_password);
bool verify_password(const char *password, const char *salt, const char *stored_hash);

#endif