#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
PWMGR="$ROOT_DIR/pwmgr"

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

printf '=== pwmgr generate option tests ===\n\n'

# --- default (no flags): must contain upper, lower, digit, special ---
echo '-- default (all character groups) --'
for i in $(seq 5); do
	out=$("$PWMGR" generate 20 2>&1 <<'EOF'
n
EOF
)
	assert_matches     "$out" '.*[A-Z].*' "default: contains uppercase ($i)"
	assert_matches     "$out" '.*[a-z].*' "default: contains lowercase ($i)"
	assert_matches     "$out" '.*[0-9].*' "default: contains digit ($i)"
	assert_matches     "$out" '.*[^A-Za-z0-9].*' "default: contains special ($i)"
done

# --- --lowercase: only a-z ---
echo ''
echo '-- --lowercase --'
for i in $(seq 5); do
	out=$("$PWMGR" generate 20 --lowercase 2>&1 <<'EOF'
n
EOF
)
	assert_matches     "$out" '[a-z]+' "--lowercase: all lowercase ($i)"
	assert_not_matches "$out" '.*[A-Z].*' "--lowercase: no uppercase ($i)"
	assert_not_matches "$out" '.*[0-9].*' "--lowercase: no digit ($i)"
	assert_not_matches "$out" '.*[^A-Za-z0-9].*' "--lowercase: no special ($i)"
done

# --- --alpha: upper + lower, no digit, no special ---
echo ''
echo '-- --alpha --'
for i in $(seq 5); do
	out=$("$PWMGR" generate 20 --alpha 2>&1 <<'EOF'
n
EOF
)
	assert_matches     "$out" '[A-Za-z]+' "--alpha: only letters ($i)"
	assert_not_matches "$out" '.*[0-9].*' "--alpha: no digit ($i)"
	assert_not_matches "$out" '.*[^A-Za-z0-9].*' "--alpha: no special ($i)"
done

# --- --digits: only 0-9 ---
echo ''
echo '-- --digits --'
for i in $(seq 5); do
	out=$("$PWMGR" generate 20 --digits 2>&1 <<'EOF'
n
EOF
)
	assert_matches     "$out" '[0-9]+' "--digits: only digits ($i)"
	assert_not_matches "$out" '.*[A-Za-z].*' "--digits: no letter ($i)"
	assert_not_matches "$out" '.*[^A-Za-z0-9].*' "--digits: no special ($i)"
done

# --- --special: only special chars ---
echo ''
echo '-- --special --'
for i in $(seq 5); do
	out=$("$PWMGR" generate 20 --special 2>&1 <<'EOF'
n
EOF
)
	assert_matches     "$out" '[^A-Za-z0-9]+' "--special: only special ($i)"
	assert_not_matches "$out" '.*[A-Za-z0-9].*' "--special: no alnum ($i)"
done

# --- combining: --alpha --digits => upper + lower + digit, no special ---
echo ''
echo '-- --alpha --digits (combined) --'
for i in $(seq 5); do
	out=$("$PWMGR" generate 20 --alpha --digits 2>&1 <<'EOF'
n
EOF
)
	assert_matches     "$out" '[A-Za-z0-9]+' "--alpha --digits: only alphanum ($i)"
	assert_not_matches "$out" '.*[^A-Za-z0-9].*' "--alpha --digits: no special ($i)"
done

# --- combining: --lowercase --alpha => lowercase letters only ---
echo ''
echo '-- --lowercase --alpha (lowercase letters only) --'
for i in $(seq 5); do
	out=$("$PWMGR" generate 20 --lowercase --alpha 2>&1 <<'EOF'
n
EOF
)
	assert_matches     "$out" '[a-z]+' "--lowercase --alpha: all lowercase ($i)"
	assert_not_matches "$out" '.*[A-Z].*' "--lowercase --alpha: no uppercase ($i)"
	assert_not_matches "$out" '.*[0-9].*' "--lowercase --alpha: no digit ($i)"
done

# --- combining: --lowercase --digits => lowercase + digits ---
echo ''
echo '-- --lowercase --digits (lowercase + digits) --'
for i in $(seq 5); do
	out=$("$PWMGR" generate 20 --lowercase --digits 2>&1 <<'EOF'
n
EOF
)
	assert_matches     "$out" '[a-z0-9]+' "--lowercase --digits: only lower+digit ($i)"
	assert_not_matches "$out" '.*[A-Z].*' "--lowercase --digits: no uppercase ($i)"
	assert_not_matches "$out" '.*[^A-Za-z0-9].*' "--lowercase --digits: no special ($i)"
done

# --- combining: --lowercase --digits --special => lowercase + digits + special ---
echo ''
echo '-- --lowercase --digits --special (lowercase + digits + special) --'
for i in $(seq 5); do
	out=$("$PWMGR" generate 20 --lowercase --digits --special 2>&1 <<'EOF'
n
EOF
)
	assert_not_matches "$out" '.*[A-Z].*' "--lowercase --digits --special: no uppercase ($i)"
	assert_matches     "$out" '.*[0-9].*' "--lowercase --digits --special: contains digit ($i)"
	assert_matches     "$out" '.*[^A-Za-z0-9].*' "--lowercase --digits --special: contains special ($i)"
done

# --- minimum length ---
echo ''
echo '-- minimum length --'
out=$("$PWMGR" generate 1 --digits 2>&1 <<'EOF'
n
EOF
)
assert_matches "$out" '[0-9]' "--digits length 1: single digit"

out=$("$PWMGR" generate 1 --digits --alpha 2>&1 <<'EOF'
n
EOF
) || true
assert_error "$out" "at least" "--digits --alpha length 1: too short error"

printf '\n=== Results: %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
