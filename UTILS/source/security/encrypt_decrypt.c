#include "security/encrypt_decrypt.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

bool verify_message_integrity(const char* original, const char* decrypted, size_t length) {
    return memcmp(original, decrypted, length) == 0;
}

void xor_cipher(char *message, const char *key, size_t message_length) {
    size_t key_len = strlen(key);
    
    for (size_t i = 0; i < message_length; i++) {
        message[i] ^= key[i % key_len];
    }
}

void generate_random_key(char *key, int length) {
    static bool seeded = false;
    static unsigned int seed;
    
    if (!seeded) {
        seed = (unsigned int)time(NULL);
        srand(seed);
        seeded = true;
    }
    
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    
    for (int i = 0; i < length; i++) {
        int index = rand() % (sizeof(charset) - 1);
        key[i] = charset[index];
    }
    key[length] = '\0';
}
