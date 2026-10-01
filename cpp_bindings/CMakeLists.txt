# CMakeLists.txt for IPC C++ Bindings
cmake_minimum_required(VERSION 3.16)
project(ipc_cpp_bindings VERSION 1.0.0 LANGUAGES CXX)

# ============================================================================
# CONFIGURATION
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Release por defecto
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Opciones
option(IPC_USE_OPENSSL "Usar OpenSSL para criptografía" ON)
option(IPC_BUILD_SHARED "Construir como biblioteca compartida" OFF)
# OFF por defecto para no arrastrar gtest a quien sólo consume la biblioteca.
# El runner de CI y la documentación lo activan explícitamente con
# -DIPC_BUILD_TESTS=ON.
option(IPC_BUILD_TESTS "Construir tests" OFF)

# ============================================================================
# DEPENDENCIAS
# ============================================================================

if(IPC_USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
endif()

# ============================================================================
# INCLUDE DIRECTORIES
# ============================================================================

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# ============================================================================
# SOURCE FILES
# ============================================================================

set(CONTRACT_SOURCES
    src/contract.cpp
)

set(CLIENT_SOURCES
    src/client.cpp
)

# La v2.1 tenía `src/security.cpp` con un HMAC disfrazado de firma Ed25519 y
# `public_key = SHA256(private_key)`. Se sustituye por `crypto.cpp` (Ed25519
# real vía OpenSSL 3, derivación de claves y anti-replay) y `blake3.cpp`
# (BLAKE3-256 propio, que OpenSSL 3.0 no expone).
set(SECURITY_SOURCES
    src/crypto.cpp
    src/blake3.cpp
)

# ============================================================================
# LIBRARY: ipc_contract
# ============================================================================

add_library(ipc_contract STATIC ${CONTRACT_SOURCES})

# Build: se usan las cabeceras del árbol de fuentes.
# Install: rutas relativas a ${CMAKE_INSTALL_PREFIX}, porque CMake rechaza
# exportar un target cuyo INTERFACE_INCLUDE_DIRECTORIES apunte al árbol de
# fuentes (error en generate, no en build).
target_include_directories(ipc_contract
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(IPC_USE_OPENSSL)
    target_compile_definitions(ipc_contract PUBLIC USE_OPENSSL)
    target_link_libraries(ipc_contract PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

set_target_properties(ipc_contract PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "include/ipc/contract.hpp"
)

# ============================================================================
# LIBRARY: ipc_client
# ============================================================================

add_library(ipc_client STATIC ${CLIENT_SOURCES})

target_link_libraries(ipc_client PRIVATE ipc_contract)

set_target_properties(ipc_client PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "include/ipc/client.hpp"
)

# ============================================================================
# LIBRARY: ipc_security
# ============================================================================

add_library(ipc_security STATIC ${SECURITY_SOURCES})

target_include_directories(ipc_security
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(IPC_USE_OPENSSL)
    target_compile_definitions(ipc_security PUBLIC USE_OPENSSL)
    target_link_libraries(ipc_security PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

set_target_properties(ipc_security PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "include/ipc/security.hpp"
)

# ============================================================================
# ALIAS (para uso simple)
# ============================================================================

add_library(ipc::contract ALIAS ipc_contract)
add_library(ipc::client ALIAS ipc_client)
add_library(ipc::security ALIAS ipc_security)

# ============================================================================
# TESTS
# ============================================================================

if(IPC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ============================================================================
# INSTALL
# ============================================================================

install(TARGETS ipc_contract ipc_client ipc_security
    EXPORT ipc_targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/ipc
)

install(EXPORT ipc_targets
    FILE ipcTargets.cmake
    NAMESPACE ipc::
    DESTINATION lib/cmake/ipc
)

# ============================================================================
# EXPORT
# ============================================================================

export(PACKAGE ipc)

# ============================================================================
# DOCUMENTATION
# ============================================================================

find_package(Doxygen)
if(Doxygen_FOUND)
    add_subdirectory(docs)
endif()

# ============================================================================
# TESTS
# ============================================================================
#
# Los tests de conformidad se compilan contra la misma biblioteca que el
# producto, para que no puedan divergir de ella.
