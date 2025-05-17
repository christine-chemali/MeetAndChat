   #include "servernetwork/login/LoginHandler.h"
   #include "serverlogging/ServerLogging.h"
   #include "serverdatabase/ServerDatabase.h"
   #include "serversecurity/hash.h"
   #include "security/NetworkSecurity.h"
   #include <stdio.h>
   #include <string.h>
   #include <stdlib.h>
   #include <glib.h>

   // Handle login request
bool handle_login_request(ClientSession* session, Message* msg) {
    char log_buffer[256];
        // Log incoming request with socket ID
    snprintf(log_buffer, sizeof(log_buffer), 
        "Processing login request from socket %d", 
        (int)session->clientSocket);
    log_server_message(LOG_INFO, log_buffer);
    
    
    char email[256], password[256];
    if (sscanf(msg->data, "%[^:]:%s", email, password) != 2) {
        return send_login_response(session, false, "Invalid request format");
    }

    PGconn *conn = get_database_connection();
    if (!conn) {
        return send_login_response(session, false, "Database connection error");
    }

    // Verify if email exist
    const char *check_query = "SELECT COUNT(*) FROM users WHERE email = $1";
    const char *check_params[1] = {email};
    PGresult *check_res = PQexecParams(conn, check_query, 1, NULL, check_params, NULL, NULL, 0);

    if (PQresultStatus(check_res) != PGRES_TUPLES_OK) {
        PQclear(check_res);
        return send_login_response(session, false, "Database error during verification");
    }

    int user_count = atoi(PQgetvalue(check_res, 0, 0));
    PQclear(check_res);

    if (user_count == 0) {
        // Email doesn't exist - send answer keep connection
        return send_login_response(session, false, "No account found with this email. Please register first");
    }

    // Verify connection informations 
    const char *query = 
        "SELECT id, password_hash, salt, status FROM users WHERE email = $1";
    
    const char *paramValues[1] = {email};
    PGresult *res = PQexecParams(conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        char *error_msg = PQerrorMessage(conn);
        printf("Database error: %s\n", error_msg);
        PQclear(res);
        return send_login_response(session, false, "Database query error");
    }

    if (PQntuples(res) == 0) {
        PQclear(res);
        return send_login_response(session, false, "Invalid credentials");
    }

    char *stored_hash = PQgetvalue(res, 0, 1);
    char *salt = PQgetvalue(res, 0, 2);
    char *user_id = PQgetvalue(res, 0, 0);
    char *status = PQgetvalue(res, 0, 3);

    if (strcmp(status, "active") != 0) {
        PQclear(res);
        return send_login_response(session, false, "Account is not active");
    }

    char hashed_input[65];
    hash_password(password, salt, hashed_input);

    if (strcmp(hashed_input, stored_hash) == 0) {
        const char *update_query = 
            "UPDATE users SET is_online = true, last_seen = CURRENT_TIMESTAMP "
            "WHERE id = $1";
        
        const char *update_params[1] = {user_id};
        PGresult *update_res = PQexecParams(conn, update_query, 1, NULL, 
                                          update_params, NULL, NULL, 0);
        
        if (PQresultStatus(update_res) == PGRES_COMMAND_OK) {
            session->isAuthenticated = true;
            session->userId = atoi(user_id);
            strncpy(session->email, email, sizeof(session->email) - 1);
            PQclear(update_res);
            PQclear(res);
            return send_login_response(session, true, "Login successful");
        }
        PQclear(update_res);
    }

    PQclear(res);
    // Invalid password - send response and keep connection
    return send_login_response(session, false, "Invalid password");
}

// send response and return the result of the sending for login
bool send_login_response(ClientSession* session, bool success, const char* message) {
    Message response;
    response.type = LOGIN_RESPONSE;
    
    // Convert in vali UTF-8 
    char utf8_message[MAX_MESSAGE_LENGTH];
    g_strlcpy(utf8_message, message, sizeof(utf8_message));
    
    // Verify and cleanup UTF-8
    if (!g_utf8_validate(utf8_message, -1, NULL)) {
        g_utf8_make_valid(utf8_message, -1);
    }
    
    snprintf(response.data, MAX_MESSAGE_LENGTH, "%d:%s", success ? 1 : 0, utf8_message);
    response.length = strlen(response.data);
    response.checksum = calculate_checksum(response.data, response.length);
    
    encrypt_message(&response, get_session_key());
    
    return send(session->clientSocket, (char*)&response, sizeof(Message), 0) > 0;
}

// Handle disconnect request
   bool handle_disconnect_request(ClientSession* session, const char* email) {
    PGconn *conn = get_database_connection();
    if (!conn) {
        return false;
    }

    const char *query = "UPDATE users SET is_online = false, last_seen = CURRENT_TIMESTAMP WHERE email = $1";
    const char *paramValues[1] = {email};
    PGresult *res = PQexecParams(conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    bool success = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);

    if (success) {
        // re init session without closing connection
        session->isAuthenticated = false;
        session->userId = 0;
        memset(session->email, 0, sizeof(session->email));
        
        //keep the socket open to allow reconnection
        return send_login_response(session, true, "Disconnected successfully");
    }
    
    return false;
}

// Handle logout request
void handle_logout_request(ClientSession* session) {
    if (!session->isAuthenticated) return;

    PGconn *conn = get_database_connection();
    if (!conn) return;

    const char *query = "UPDATE users SET is_online = false WHERE id = $1";
    const char *paramValues[1] = {(char*)&session->userId};
    PGresult *res = PQexecParams(conn, query, 1, NULL, paramValues, NULL, NULL, 0);
    PQclear(res);

    session->isAuthenticated = false;
    session->userId = 0;
    memset(session->email, 0, sizeof(session->email));
}