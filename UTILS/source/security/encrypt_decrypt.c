#include "security/encrypt_decrypt.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

bool verify_message_integrity(const char* original, const char* decrypted) {
    return strcmp(original, decrypted) == 0;
}

void xor_cipher(char *message, const char *key) {
    int key_len = strlen(key);
    int i = 0;
    while (*message) {
        *message = *message ^ key[i % key_len];
        message++;
        i++;
    }
}

void generate_random_key(char *key, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    srand(time(NULL)); // Initialize the random number generator
    // srand((unsigned int)time(NULL)); // Initialize the random number generator  
    
    for (int i = 0; i < length; i++) {
        int index = rand() % (sizeof(charset) - 1);
        key[i] = charset[index];
    }
    key[length] = '\0';
}

//vs