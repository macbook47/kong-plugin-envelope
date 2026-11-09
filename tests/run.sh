#!/usr/bin/env bash
# Runs the offline tests. First run downloads lua-resty-openssl 1.5.1 (the version in Kong 3.9) into .deps/.
# macOS (Homebrew):  brew install luajit openssl@3 luarocks && luarocks --lua-version 5.1 install lua-cjson
#   then: OPENSSL_CRYPTO_LIB=$(brew --prefix openssl@3)/lib/libcrypto.dylib \
#         OPENSSL_SSL_LIB=$(brew --prefix openssl@3)/lib/libssl.dylib ./tests/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."
# Let LuaJIT find rocks installed with luarocks (lua-cjson)
if command -v luarocks >/dev/null 2>&1; then eval "$(luarocks --lua-version 5.1 path)"; fi
if [ -z "${LUA_RESTY_OPENSSL:-}" ] && [ ! -d .deps/lua-resty-openssl ]; then
  git -c advice.detachedHead=false clone -q --depth 1 --branch 1.5.1 https://github.com/fffonion/lua-resty-openssl.git .deps/lua-resty-openssl
fi
exec luajit tests/offline_test.lua
