#include "serversecurity/hash.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

//Generate salt
void generate_salt(char *salt, size_t length) {
    if (!salt || length == 0) return;

    RAND_bytes((unsigned char*)salt, length);
    for(size_t i = 0; i < length; i++) {
        salt[i] = (salt[i] & 0x7F) + 33; 
    }
    salt[length] = '\0';
}

//Hash password
void hash_password(const char *password, const char *salt, char *hashed_password) {
    if (!password || !salt || !hashed_password) return;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    char salted_pass[512];
    
    // Combine password and salt
    snprintf(salted_pass, sizeof(salted_pass), "%s%s", password, salt);

    // Create hash context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return;

    // Initialize hash context with SHA256
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Update hash with data
    if (EVP_DigestUpdate(mdctx, salted_pass, strlen(salted_pass)) != 1) {
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Finalize hash
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Clean up
    EVP_MD_CTX_free(mdctx);

    // Convert to hex string
    for(unsigned int i = 0; i < hash_len; i++) {
        sprintf(hashed_password + (i * 2), "%02x", hash[i]);
    }
    hashed_password[hash_len * 2] = '\0';
}

//Verify password
bool verify_password(const char *password, const char *salt, const char *stored_hash) {
    if (!password || !salt || !stored_hash) return false;

    char computed_hash[EVP_MAX_MD_SIZE * 2 + 1];
    hash_password(password, salt, computed_hash);
    return strcmp(computed_hash, stored_hash) == 0;
}