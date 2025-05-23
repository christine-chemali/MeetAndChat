#ifndef NETWORKENUMS_H
#define NETWORKENUMS_H

// Error codes
typedef enum {
    NETWORK_SUCCESS = 0,
    NETWORK_ERROR_CONNECTION_FAILED,
    NETWORK_ERROR_INVALID_MESSAGE,
    NETWORK_ERROR_AUTHENTICATION_FAILED,
    NETWORK_ERROR_PERMISSION_DENIED,
    NETWORK_ERROR_USER_NOT_FOUND,
    NETWORK_ERROR_CHANNEL_NOT_FOUND,
    NETWORK_ERROR_INVALID_REQUEST,
    NETWORK_ERROR_SERVER_ERROR,
    NETWORK_ERROR_TIMEOUT,
    NETWORK_ERROR_PROTOCOL_MISMATCH,
    NETWORK_ERROR_INVALID_DATA,
    NETWORK_ERROR_RESOURCE_UNAVAILABLE,
    NETWORK_ERROR_RATE_LIMITED,
    NETWORK_ERROR_INVALID_STATE
} NetworkError;

// User status
typedef enum {
    USER_STATUS_OFFLINE = 0,
    USER_STATUS_ONLINE,
    USER_STATUS_AWAY,
    USER_STATUS_BUSY,
    USER_STATUS_INVISIBLE
} UserStatus;

// Channel types
typedef enum {
    CHANNEL_TYPE_TEXT = 0,
    CHANNEL_TYPE_VOICE,
    CHANNEL_TYPE_VIDEO,
    CHANNEL_TYPE_FILE_SHARING,
    CHANNEL_TYPE_PRIVATE
} ChannelType;

// Permission flags
typedef enum {
    PERMISSION_NONE = 0x00,
    PERMISSION_READ = 0x01,
    PERMISSION_WRITE = 0x02,
    PERMISSION_ADMIN = 0x04,
    PERMISSION_MODERATE = 0x08,
    PERMISSION_INVITE = 0x10,
    PERMISSION_FILE_SHARE = 0x20,
    PERMISSION_VOICE = 0x40,
    PERMISSION_VIDEO = 0x80
} PermissionFlag;

#endif 