cmake_minimum_required(VERSION 3.15)
project(MYDISCORD C)

set(CMAKE_C_STANDARD 99)

# Définir le compilateur explicitement pour Windows MSYS2
if (WIN32)
    set(CMAKE_C_COMPILER "C:/msys64/mingw64/bin/gcc.exe")
endif()

# Ajout d’options de compilation pour GCC
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-finput-charset=UTF-8 -fexec-charset=UTF-8)
endif()

# === GTK4 (sur Windows avec MSYS2 ou sur Unix) ===
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK4 REQUIRED gtk4)
include_directories(${GTK4_INCLUDE_DIRS})
link_directories(${GTK4_LIBRARY_DIRS})
add_definitions(${GTK4_CFLAGS_OTHER})

# === Client ===
file(GLOB CLIENT_SOURCES "*.c")
add_executable(client ${CLIENT_SOURCES})
include_directories(client/include)

target_link_libraries(client ${GTK4_LIBRARIES})