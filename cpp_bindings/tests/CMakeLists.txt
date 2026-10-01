# Tests de conformidad de los bindings C++.
#
# Se compilan contra las mismas bibliotecas que consume el producto, de modo
# que no pueden divergir de ellas. La conformidad cross-language se verifica
# contra los vectores dorados de `tests/vectors/crypto.json`, que genera Rust.

add_executable(ipc_blake3_test blake3_test.cpp)
target_link_libraries(ipc_blake3_test PRIVATE ipc_security)

add_executable(ipc_conformance_test conformance_test.cpp)
target_link_libraries(ipc_conformance_test
    PRIVATE ipc_security ipc_contract OpenSSL::Crypto)

# Los ejecutables se quedan en el directorio de build de este subdirectorio,
# pero ctest se ejecuta desde el raíz: se registra la ruta completa.
add_test(NAME blake3_vectors
         COMMAND $<TARGET_FILE:ipc_blake3_test>)
add_test(NAME conformance
         COMMAND $<TARGET_FILE:ipc_conformance_test>)
