#!/usr/bin/env bash
#
# Verificación completa del IPC Contract System.
#
# Ejecuta el gate de CI en los tres lenguajes y comprueba la conformidad
# cross-language contra los vectores dorados de `tests/vectors/crypto.json`.
#
# Es el mismo gate que la revisión P0 (punto 10) señal como nunca ejecutado:
# antes de v2.1 el proyecto no compilaba en ningún lenguaje.
#
# Uso:  ./run_all_tests.sh
#
set -uo pipefail

cd "$(dirname "$0")"

export CARGO_HOME="${CARGO_HOME:-$PWD/.cargohome}"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
KOTLINC="${KOTLINC:-kotlinc}"
KOTLIN_LIB="${KOTLIN_LIB:-/opt/kotlinc/lib/kotlin-stdlib.jar}"
COROUTINES_JAR="${COROUTINES_JAR:-}"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
FAILURES=0
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

step() { printf '\n%s=== %s ===%s\n' "$YELLOW" "$1" "$RESET"; }
ok()   { printf '%s ok   %s%s\n' "$GREEN" "$1" "$RESET"; }
fail() { printf '%s FAIL %s%s\n' "$RED" "$1" "$RESET"; FAILURES=$((FAILURES + 1)); }

# Un gate que no se puede ejecutar NO es un gate que pasa.
#
# La v2.1.1 omitía en silencio cualquier herramienta ausente y aun así
# imprimía "Todos los gates pasaron", lo que es exactamente la degradación
# silenciosa que la política zero-trust prohíbe: un runner que reporta verde
# sin haber comprobado nada es peor que no tener runner.
#
# `SKIP_MISSING=1` mantiene el comportamiento histórico para quien quiera
# verificar sólo un binding, pero el resultado se marca como INCOMPLETO.
SKIPPED=""
SKIP_MISSING="${SKIP_MISSING:-0}"
skip() {
    SKIPPED="${SKIPPED}${SKIPPED:+, }$1"
    if [ "$SKIP_MISSING" = "1" ]; then
        printf '%s SKIP %s (herramienta ausente; resultado INCOMPLETO)%s\n' \
               "$YELLOW" "$1" "$RESET"
    else
        printf '%s FAIL %s (herramienta ausente)%s\n' "$RED" "$1" "$RESET"
        FAILURES=$((FAILURES + 1))
    fi
}

# ---------------------------------------------------------------------------
step "Rust: cargo check --all-targets --all-features"
# El gate que la revisión P0 identificó como no ejecutado.
if cargo check --all-targets --all-features 2>&1 | tee "$BUILD_DIR/check.log" | grep -q '^error'; then
    fail "cargo check"
    grep '^error' "$BUILD_DIR/check.log" | head -20
else
    ok "cargo check (0 errores)"
fi

step "Rust: cargo test --all-features"
if cargo test --all-features 2>&1 | tee "$BUILD_DIR/test.log" | grep -q 'test result: FAILED'; then
    fail "cargo test"
    grep -E 'FAILED|panicked' "$BUILD_DIR/test.log" | head -20
else
    PASSED=$(grep -oE '[0-9]+ passed' "$BUILD_DIR/test.log" | awk '{s+=$1} END {print s}')
    ok "cargo test ($PASSED tests)"
fi

# ---------------------------------------------------------------------------
step "C++: compilación de la librería"
CPP_FLAGS=(-std=c++20 -O2 -Wall -DUSE_OPENSSL -Icpp_bindings/include)
CXX_OK=1
command -v g++ >/dev/null 2>&1 || skip "g++ (bindings C++)"
for f in contract crypto blake3 client; do
    if ! g++ "${CPP_FLAGS[@]}" -c "cpp_bindings/src/$f.cpp" -o "$BUILD_DIR/$f.o" 2>"$BUILD_DIR/$f.log"; then
        fail "g++ $f.cpp"
        head -20 "$BUILD_DIR/$f.log"
        CXX_OK=0
    elif [ -s "$BUILD_DIR/$f.log" ]; then
        printf '%swarn %s.cpp%s\n' "$YELLOW" "$f" "$RESET"
        head -10 "$BUILD_DIR/$f.log"
    fi
done
if [ "$CXX_OK" = 1 ]; then
    ar rcs "$BUILD_DIR/libipc.a" "$BUILD_DIR"/*.o
    ok "librería estática construida"
fi

step "C++: vectores BLAKE3"
if g++ "${CPP_FLAGS[@]}" cpp_bindings/tests/blake3_test.cpp \
        "$BUILD_DIR/blake3.o" -o "$BUILD_DIR/b3" 2>"$BUILD_DIR/b3.log"; then
    if "$BUILD_DIR/b3" | tail -2 | grep -q "ALL PASS"; then
        ok "BLAKE3 coincide con los vectores oficiales"
    else
        fail "BLAKE3 vectors"
        "$BUILD_DIR/b3"
    fi
else
    fail "compilar blake3_test"
    head -20 "$BUILD_DIR/b3.log"
fi

step "C++: conformidad cross-language"
if [ "$CXX_OK" = 1 ] && g++ "${CPP_FLAGS[@]}" cpp_bindings/tests/conformance_test.cpp \
        -L"$BUILD_DIR" -lipc -lcrypto -o "$BUILD_DIR/conf" 2>"$BUILD_DIR/conf.log"; then
    if "$BUILD_DIR/conf" > "$BUILD_DIR/conf.out" 2>&1; then
        ok "C++ conformidad ($(grep -oE '[0-9]+ checks' "$BUILD_DIR/conf.out" | tail -1))"
    else
        fail "C++ conformance"
        grep -A3 FAIL "$BUILD_DIR/conf.out" | head -30
    fi
else
    fail "compilar conformance_test"
    head -20 "$BUILD_DIR/conf.log"
fi

step "C++: build con CMake y ctest"
if command -v cmake >/dev/null 2>&1; then
    if cmake -S cpp_bindings -B "$BUILD_DIR/cm" -DCMAKE_BUILD_TYPE=Release \
             -DIPC_BUILD_TESTS=ON > "$BUILD_DIR/cmake.log" 2>&1 &&
       cmake --build "$BUILD_DIR/cm" -j2 >> "$BUILD_DIR/cmake.log" 2>&1; then
        # -DIPC_BUILD_TESTS=ON es obligatorio: con el default (OFF) ctest
        # encuentra cero tests y devuelve éxito, de modo que el gate pasaba
        # sin haber ejecutado nada.
        if (cd "$BUILD_DIR/cm" && ctest --output-on-failure) > "$BUILD_DIR/ctest.log" 2>&1; then
            N=$(grep -oE '[0-9]+% tests passed' "$BUILD_DIR/ctest.log" | head -1)
            if [ -z "$N" ] || grep -q 'No tests were found' "$BUILD_DIR/ctest.log"; then
                fail "ctest no encontró tests (¿falta -DIPC_BUILD_TESTS=ON?)"
                tail -5 "$BUILD_DIR/ctest.log"
            else
                ok "CMake build + ctest ($N)"
            fi
        else
            fail "ctest"
            tail -20 "$BUILD_DIR/ctest.log"
        fi
    else
        fail "cmake build"
        tail -20 "$BUILD_DIR/cmake.log"
    fi
else
    skip "cmake build + ctest"
fi

# ---------------------------------------------------------------------------
step "Kotlin: compilación de los bindings"
KT_OK=1
if ! command -v "$KOTLINC" >/dev/null 2>&1; then
    skip "kotlinc bindings"
    skip "kotlin conformance"
    KT_OK=0
fi
if [ "${KT_OK:-1}" = 1 ]; then
    CP=""
    [ -n "$COROUTINES_JAR" ] && [ -f "$COROUTINES_JAR" ] && CP="$COROUTINES_JAR"
    if ! "$KOTLINC" -nowarn ${CP:+-cp "$CP"} \
            kotlin_bindings/src/main/kotlin/com/ipc/contract/*.kt \
            -d "$BUILD_DIR/kt" 2>"$BUILD_DIR/kt.log"; then
        fail "kotlinc bindings"
        grep 'error:' "$BUILD_DIR/kt.log" | head -20
        KT_OK=0
    else
        ok "bindings Kotlin compilados"
    fi
fi

if [ "${KT_OK:-0}" = 1 ]; then
    step "Kotlin: conformidad cross-language"
    CP="$BUILD_DIR/kt"
    [ -n "$COROUTINES_JAR" ] && [ -f "$COROUTINES_JAR" ] && CP="$CP:$COROUTINES_JAR"
    [ -f "$KOTLIN_LIB" ] && CP="$CP:$KOTLIN_LIB"

    if "$KOTLINC" -nowarn -cp "$CP" \
            kotlin_bindings/src/test/kotlin/com/ipc/contract/KotlinConformanceTest.kt \
            -d "$BUILD_DIR/kttest" 2>"$BUILD_DIR/kttest.log"; then
        if java -cp "$CP:$BUILD_DIR/kttest" com.ipc.contract.KotlinConformanceTest \
                > "$BUILD_DIR/ktconf.out" 2>&1; then
            ok "Kotlin conformidad ($(grep -oE '[0-9]+ checks' "$BUILD_DIR/ktconf.out" | tail -1))"
        else
            fail "Kotlin conformance"
            grep -A3 FAIL "$BUILD_DIR/ktconf.out" | head -30
        fi
    else
        fail "compilar KotlinConformanceTest"
        grep 'error:' "$BUILD_DIR/kttest.log" | head -20
    fi
fi

# ---------------------------------------------------------------------------
printf '\n%s=== RESULTADO ===%s\n' "$YELLOW" "$RESET"
if [ "$FAILURES" = 0 ]; then
    printf '%sTodos los gates pasaron.%s\n' "$GREEN" "$RESET"
    exit 0
else
    printf '%s%d gate(s) fallaron.%s\n' "$RED" "$FAILURES" "$RESET"
    exit 1
fi
