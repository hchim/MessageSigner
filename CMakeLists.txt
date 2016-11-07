# Sets the minimum version of CMake required to build the native
# library. You should either keep the default value or only pass a
# value of 3.4.0 or lower.

cmake_minimum_required(VERSION 3.4.1)

add_library( scrypto_shared
             SHARED
             IMPORTED )

# scrypto lib
set_target_properties( # Specifies the target library.
                       scrypto_shared

                       # Specifies the parameter you want to define.
                       PROPERTIES IMPORTED_LOCATION

                       # Provides the path to the library you want to import.
                       ${CMAKE_CURRENT_LIST_DIR}/src/main/libs/${ANDROID_ABI}/libscrypto_shared.so )

# jsonc lib
add_library( json-c
             STATIC
             IMPORTED )

set_target_properties( # Specifies the target library.
                       json-c

                       # Specifies the parameter you want to define.
                       PROPERTIES IMPORTED_LOCATION

                       # Provides the path to the library you want to import.
                       ${CMAKE_CURRENT_LIST_DIR}/src/main/libs/${ANDROID_ABI}/libjson-c.a )

include_directories(
                src/main/cpp/scrypto/include/
                src/main/cpp/jsonc/include/
                src/main/cpp/libzip/
                )

include(src/main/cpp/libzip/CMakeLists.txt)
include(src/main/cpp/msigner/CMakeLists.txt)