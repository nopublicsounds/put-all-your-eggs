#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
PWMGR="$ROOT_DIR/pwmgr"
TMP_XDG=$(mktemp -d)
export XDG_CONFIG_HOME="$TMP_XDG"

cleanup() {
	rm -rf "$TMP_XDG"
}

trap cleanup EXIT INT TERM

PASS=0
FAIL=0

assert_matches() {
	output=$1
	pattern=$2
	label=$3

	pw=$(printf '%s' "$output" | sed 's/\x1b\[[0-9;]*m//g' | grep '^Generated password:' | sed 's/Generated password: //')
	if echo "$pw" | grep -Eqx "$pattern"; then
		printf '  PASS  %s  [%s]\n' "$label" "$pw"
		PASS=$((PASS + 1))
	else
		printf '  FAIL  %s\n' "$label"
		printf '        password : %s\n' "$pw"
		printf '        pattern  : %s\n' "$pattern"
		FAIL=$((FAIL + 1))
	fi
}

assert_not_matches() {
	output=$1
	pattern=$2
	label=$3

	pw=$(printf '%s' "$output" | sed 's/\x1b\[[0-9;]*m//g' | grep '^Generated password:' | sed 's/Generated password: //')
	if echo "$pw" | grep -Eqx "$pattern"; then
		printf '  FAIL  %s\n' "$label"
		printf '        password matches forbidden pattern: %s  [%s]\n' "$pattern" "$pw"
		FAIL=$((FAIL + 1))
	else
		printf '  PASS  %s  [%s]\n' "$label" "$pw"
		PASS=$((PASS + 1))
	fi
}

assert_error() {
	output=$1
	expected=$2
	label=$3

	if printf '%s' "$output" | grep -Fq "$expected"; then
		printf '  PASS  %s\n' "$label"
		PASS=$((PASS + 1))
	else
		printf '  FAIL  %s\n' "$label"
		printf '        expected error : %s\n' "$expected"
		printf '        actual output  : %s\n' "$output"
		FAIL=$((FAIL + 1))
	fi
}

assert_counts() {
	output=$1
	digits=$2
	alphabet=$3
	special=$4
	label=$5

	pw=$(printf '%s' "$output" | sed 's/\x1b\[[0-9;]*m//g' | grep '^Generated password:' | sed 's/Generated password: //')
	actual_digits=$(printf '%s' "$pw" | tr -cd '0-9' | wc -c | tr -d ' ')
	actual_alphabet=$(printf '%s' "$pw" | tr -cd 'A-Za-z' | wc -c | tr -d ' ')
	actual_special=$(printf '%s' "$pw" | sed 's/[A-Za-z0-9]//g' | wc -c | tr -d ' ')
	if [ "$actual_digits" -eq "$digits" ] && [ "$actual_alphabet" -eq "$alphabet" ] && [ "$actual_special" -eq "$special" ]; then
		printf '  PASS  %s  [%s]\n' "$label" "$pw"
		PASS=$((PASS + 1))
	else
		printf '  FAIL  %s\n' "$label"
		printf '        password: %s\n' "$pw"
		FAIL=$((FAIL + 1))
	fi
}

printf '=== pwmgr generate option tests ===\n\n'

echo '-- exact character counts --'
out=$("$PWMGR" generate -d 4 -a 12 -s 4 2>&1 <<'EOF'
n
EOF
)
assert_counts "$out" 4 12 4 "-d/-a/-s generate exact counts"

echo ''
echo '-- lowercase alphabet option --'
out=$("$PWMGR" generate -d 2 -a 8 -s 3 -l 2>&1 <<'EOF'
n
EOF
)
assert_counts "$out" 2 8 3 "-l preserves requested counts"
assert_not_matches "$out" '.*[A-Z].*' "-l excludes uppercase"

echo ''
echo '-- invalid options --'
out=$("$PWMGR" generate -d 2 -a 2 -s 2>&1) || true
assert_error "$out" "requires a count" "count options require a value"

out=$("$PWMGR" generate -d 2 -a 2 --lowercase 2>&1) || true
assert_error "$out" "Unknown option" "--lowercase is replaced by -l"

out=$("$PWMGR" generate -d 2 -s 2 2>&1 <<'EOF'
n
EOF
)
assert_counts "$out" 2 0 2 "zero-count alphabet group is allowed"

printf '\n=== Results: %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
