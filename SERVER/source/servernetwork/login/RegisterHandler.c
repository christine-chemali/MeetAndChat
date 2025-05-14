#include "servernetwork/login/RegisterHandler.h"
#include "serverdatabase/ServerDatabase.h"
#include "serversecurity/hash.h"
#include "security/NetworkSecurity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>

//Handle register request
bool handle_register_request(ClientSession* session, Message* msg) {
    printf("Processing registration request from client %d\n", (int)session->clientSocket);
    
    char error_buffer[256] = {0};
    
    if (!session || !msg || !msg->data) {
        snprintf(error_buffer, sizeof(error_buffer), "Invalid request parameters");
        return send_register_response(session, false, error_buffer);
    }

    char first_name[256] = {0};
    char last_name[256] = {0};
    char username[256] = {0};
    char email[256] = {0};
    char password[256] = {0};
    char first_question[256] = {0};
    char second_question[256] = {0};

    // Parse registration data
    if (sscanf(msg->data, "%[^|]|%[^|]|%[^|]|%[^|]|%[^|]|%[^|]|%s",
               first_name, last_name, username, email, password,
               first_question, second_question) != 7) {
        snprintf(error_buffer, sizeof(error_buffer), "Invalid registration format");
        return send_register_response(session, false, error_buffer);
    }

    // Validate field lengths
    if (strlen(username) < 3 || strlen(password) < 8 || strlen(email) < 5) {
        snprintf(error_buffer, sizeof(error_buffer), "Invalid field lengths");
        return send_register_response(session, false, error_buffer);
    }

    PGconn *conn = get_database_connection();
    if (!conn) {
        snprintf(error_buffer, sizeof(error_buffer), "Database connection error");
        return send_register_response(session, false, error_buffer);
    }

    // Convert input to valid UTF-8
    char *utf8_first_name = g_utf8_make_valid(first_name, -1);
    char *utf8_last_name = g_utf8_make_valid(last_name, -1);
    char *utf8_username = g_utf8_make_valid(username, -1);
    char *utf8_email = g_utf8_make_valid(email, -1);
    char *utf8_question1 = g_utf8_make_valid(first_question, -1);
    char *utf8_question2 = g_utf8_make_valid(second_question, -1);

    // Check if email exists
    const char *check_email = "SELECT COUNT(*) FROM users WHERE email = $1";
    const char *email_params[1] = {utf8_email};
    PGresult *email_result = PQexecParams(conn, check_email, 1, NULL, email_params, NULL, NULL, 0);

    if (PQresultStatus(email_result) != PGRES_TUPLES_OK) {
        snprintf(error_buffer, sizeof(error_buffer), "Database error during email verification");
        PQclear(email_result);
        goto cleanup;
    }

    if (atoi(PQgetvalue(email_result, 0, 0)) > 0) {
        snprintf(error_buffer, sizeof(error_buffer), "Email already exists");
        PQclear(email_result);
        goto cleanup;
    }
    PQclear(email_result);

    // Check if username exists
    const char *check_username = "SELECT COUNT(*) FROM users WHERE username = $1";
    const char *username_params[1] = {utf8_username};
    PGresult *username_result = PQexecParams(conn, check_username, 1, NULL, username_params, NULL, NULL, 0);

    if (PQresultStatus(username_result) != PGRES_TUPLES_OK) {
        snprintf(error_buffer, sizeof(error_buffer), "Database error during username verification");
        PQclear(username_result);
        goto cleanup;
    }

    if (atoi(PQgetvalue(username_result, 0, 0)) > 0) {
        snprintf(error_buffer, sizeof(error_buffer), "Username already exists");
        PQclear(username_result);
        goto cleanup;
    }
    PQclear(username_result);

    // Generate salt and hash password
    unsigned char raw_salt[33] = {0};
    generate_salt((char*)raw_salt, 32);
    raw_salt[32] = '\0';

    // Convert salt to hexadecimal
    char hex_salt[65] = {0};
    for(int i = 0; i < 32; i++) {
        sprintf(hex_salt + (i * 2), "%02x", raw_salt[i]);
    }

    char hashed_password[65] = {0};
    hash_password(password, hex_salt, hashed_password);

    // Insert new user
    const char *insert_query = 
        "INSERT INTO users ("
            "first_name, last_name, username, email, password_hash, "
            "salt, question_1, question_2, created_at, status, is_online"
        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP, 'active', false)";

    const char *params[8] = {
        utf8_first_name,
        utf8_last_name,
        utf8_username,
        utf8_email,
        hashed_password,
        hex_salt,
        utf8_question1,
        utf8_question2
    };

    PGresult *insert_result = PQexecParams(conn, insert_query, 8, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(insert_result) != PGRES_COMMAND_OK) {
        snprintf(error_buffer, sizeof(error_buffer), "Failed to create account: %s", PQerrorMessage(conn));
        PQclear(insert_result);
        goto cleanup;
    }

    PQclear(insert_result);

    // Free UTF-8 strings
    g_free(utf8_first_name);
    g_free(utf8_last_name);
    g_free(utf8_username);
    g_free(utf8_email);
    g_free(utf8_question1);
    g_free(utf8_question2);

    return send_register_response(session, true, "Registration successful");

cleanup:
    g_free(utf8_first_name);
    g_free(utf8_last_name);
    g_free(utf8_username);
    g_free(utf8_email);
    g_free(utf8_question1);
    g_free(utf8_question2);
    return send_register_response(session, false, error_buffer);
}

// Send register response
bool send_register_response(ClientSession* session, bool success, const char* message) {
    Message response;
    memset(&response, 0, sizeof(Message));
    response.type = REGISTER_RESPONSE;
    
    // Convert message to valid UTF-8
    char *utf8_message = g_utf8_make_valid(message, -1);
    
    snprintf(response.data, MAX_MESSAGE_LENGTH, "%d:%s", success ? 1 : 0, utf8_message);
    response.length = strlen(response.data);
    response.checksum = calculate_checksum(response.data, response.length);
    
    g_free(utf8_message);
    
    encrypt_message(&response, get_session_key());
    
    return send(session->clientSocket, (char*)&response, sizeof(Message), 0) > 0;
}