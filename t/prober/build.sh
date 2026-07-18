#!/usr/bin/env bash
#
# Build the rule-driven prober. Strict by default: this is test infrastructure,
# and a harness that compiles with warnings is a harness nobody trusts.
set -euo pipefail

cd "$(dirname "$0")"

CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O1 -g -std=c11 -Wall -Wextra -Werror -Wshadow -Wpointer-arith}"

# SAN=1 builds the prober itself under ASan/UBSan. The prober parses attacker-
# shaped text from rule files and untrusted-shaped bytes off the socket, so it
# gets the same treatment the module under test does.
if [ "${SAN:-0}" = "1" ]; then
    CFLAGS="$CFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"
fi

# shellcheck disable=SC2086
$CC $CFLAGS -o prober prober.c json.c http.c

# The JSON reader is the oracle every rule assertion is evaluated against, so it
# gets its own TAP self-test rather than being trusted because the rules pass.
# shellcheck disable=SC2086
$CC $CFLAGS -o json_test json_test.c json.c

echo "built: $PWD/prober $PWD/json_test"
