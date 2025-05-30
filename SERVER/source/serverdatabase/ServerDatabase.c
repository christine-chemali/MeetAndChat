#include "serverdatabase/ServerDatabase.h"
#include "serverlogging/ServerLogging.h" 
#include <stdio.h>
#include <string.h>

static DatabaseConnection db = {NULL};

//init server database
bool init_server_database(const char *connection_info) {
    char log_buffer[256];
    
    db.conn = PQconnectdb(connection_info);
    
    if (PQstatus(db.conn) != CONNECTION_OK) {
        snprintf(log_buffer, sizeof(log_buffer),
            "DB: Connection failed");
        log_server_message(LOG_ERROR, log_buffer);
        return false;
    }

    const char *create_tables = 
        // Users table
        "CREATE TABLE IF NOT EXISTS users ("
        "    id SERIAL PRIMARY KEY,"
        "    username VARCHAR(50) UNIQUE,"
        "    first_name VARCHAR(50),"
        "    last_name VARCHAR(50),"
        "    email VARCHAR(100) NOT NULL UNIQUE,"
        "    password_hash TEXT NOT NULL,"
        "    salt VARCHAR(255),"
        "    is_online BOOLEAN DEFAULT false,"
        "    status VARCHAR(20) DEFAULT 'active',"
        "    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    question_1 TEXT,"
        "    question_2 TEXT,"
        "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");"

        // Servers table
        "CREATE TABLE IF NOT EXISTS servers ("
        "    id SERIAL PRIMARY KEY,"
        "    name VARCHAR(100) NOT NULL UNIQUE,"
        "    description TEXT,"
        "    owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,"
        "    icon_path VARCHAR(255),"
        "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");"

        // Categories table
        "CREATE TABLE IF NOT EXISTS categories ("
        "    id SERIAL PRIMARY KEY,"
        "    server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,"
        "    name VARCHAR(100) NOT NULL,"
        "    is_private BOOLEAN DEFAULT false,"
        "    position INTEGER DEFAULT 0,"
        "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    UNIQUE(server_id, name)"
        ");"

        // Channels table
        "CREATE TABLE IF NOT EXISTS channels ("
        "    id SERIAL PRIMARY KEY,"
        "    server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,"
        "    category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,"
        "    name VARCHAR(100) NOT NULL,"
        "    type VARCHAR(20) CHECK (type IN ('text', 'voice')),"
        "    is_private BOOLEAN DEFAULT false,"
        "    description TEXT,"
        "    position INTEGER DEFAULT 0,"
        "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    UNIQUE(server_id, category_id, name)"
        ");"

        // Channel permissions
        "CREATE TABLE IF NOT EXISTS channel_permissions ("
        "    channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE,"
        "    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,"
        "    can_view BOOLEAN DEFAULT true,"
        "    can_send BOOLEAN DEFAULT true,"
        "    can_manage BOOLEAN DEFAULT false,"
        "    PRIMARY KEY (channel_id, user_id)"
        ");"

        // Category permissions
        "CREATE TABLE IF NOT EXISTS category_permissions ("
        "    category_id INTEGER REFERENCES categories(id) ON DELETE CASCADE,"
        "    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,"
        "    can_view BOOLEAN DEFAULT true,"
        "    can_manage BOOLEAN DEFAULT false,"
        "    PRIMARY KEY (category_id, user_id)"
        ");"

        // Server members
        "CREATE TABLE IF NOT EXISTS server_members ("
        "    server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,"
        "    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,"
        "    role VARCHAR(20) DEFAULT 'member',"
        "    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    PRIMARY KEY (server_id, user_id)"
        ");"

        // Recovery tokens
        "CREATE TABLE IF NOT EXISTS password_recovery_tokens ("
        "    id SERIAL PRIMARY KEY,"
        "    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,"
        "    token VARCHAR(65) UNIQUE NOT NULL,"
        "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "    expires_at TIMESTAMP NOT NULL,"
        "    used BOOLEAN DEFAULT false"
        ");"

        // Create indexes
        "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);"
        "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);"
        "CREATE INDEX IF NOT EXISTS idx_servers_owner ON servers(owner_id);"
        "CREATE INDEX IF NOT EXISTS idx_categories_server ON categories(server_id);"
        "CREATE INDEX IF NOT EXISTS idx_channels_server ON channels(server_id);"
        "CREATE INDEX IF NOT EXISTS idx_channels_category ON channels(category_id);"
        "CREATE INDEX IF NOT EXISTS idx_channel_perms_channel ON channel_permissions(channel_id);"
        "CREATE INDEX IF NOT EXISTS idx_channel_perms_user ON channel_permissions(user_id);"
        "CREATE INDEX IF NOT EXISTS idx_category_perms_category ON category_permissions(category_id);"
        "CREATE INDEX IF NOT EXISTS idx_category_perms_user ON category_permissions(user_id);"
        "CREATE INDEX IF NOT EXISTS idx_server_members_server ON server_members(server_id);"
        "CREATE INDEX IF NOT EXISTS idx_server_members_user ON server_members(user_id);";

    snprintf(log_buffer, sizeof(log_buffer),
        "DB: Initializing database schema");
    log_server_message(LOG_INFO, log_buffer);

    PGresult *res = PQexec(db.conn, create_tables);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        snprintf(log_buffer, sizeof(log_buffer),
            "DB: Schema initialization failed");
        log_server_message(LOG_ERROR, log_buffer);
        PQclear(res);
        return false;
    }
    
    PQclear(res);
    
    // Log successful table creation without exposing schema details
    const char* tables[] = {
        "users", "servers", "categories", "channels",
        "channel_permissions", "category_permissions",
        "server_members", "password_recovery_tokens"
    };
    
    for(int i = 0; i < sizeof(tables)/sizeof(tables[0]); i++) {
        snprintf(log_buffer, sizeof(log_buffer),
            "DB: Verified table: %s", tables[i]);
        log_server_message(LOG_DEBUG, log_buffer);
    }

    snprintf(log_buffer, sizeof(log_buffer),
        "DB: Schema initialization completed successfully");
    log_server_message(LOG_INFO, log_buffer);
    
    return true;
}

//close server database
void close_server_database(void) {
    char log_buffer[256];
    
    if (db.conn) {
        snprintf(log_buffer, sizeof(log_buffer),
            "DB: Closing database connection");
        log_server_message(LOG_INFO, log_buffer);
        
        PQfinish(db.conn);
        db.conn = NULL;
        
        snprintf(log_buffer, sizeof(log_buffer),
            "DB: Database connection closed");
        log_server_message(LOG_DEBUG, log_buffer);
    }
}

//get database connection
PGconn *get_database_connection(void) {
    char log_buffer[256];
    
    if (!db.conn) {
        snprintf(log_buffer, sizeof(log_buffer),
            "DB: Attempted to access null database connection");
        log_server_message(LOG_ERROR, log_buffer);
    }
    return db.conn;
}
