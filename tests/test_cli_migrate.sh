#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DB_DIR=$(mktemp -d)
DB_PATH="$DB_DIR/vault.db"
MASTER_PASSWORD='MasterPass!2026'

cleanup() {
	rm -rf "$DB_DIR"
}

run_cli() {
	input=$1
	shift
	printf '%b' "$input" | script -qec "$*" /dev/null
}

assert_contains() {
	output=$1
	expected=$2
	label=$3

	if printf '%s' "$output" | grep -Fq "$expected"; then
		printf '  PASS  %s\n' "$label"
	else
		printf '  FAIL  %s\n' "$label"
		printf '        expected to find: %s\n' "$expected"
		printf '        actual output:\n%s\n' "$output"
		exit 1
	fi
}

assert_starts_with() {
	value=$1
	prefix=$2
	label=$3

	case "$value" in
		"$prefix"*)
			printf '  PASS  %s\n' "$label"
			;;
		*)
			printf '  FAIL  %s\n' "$label"
			printf '        expected prefix: %s\n' "$prefix"
			printf '        actual value: %s\n' "$value"
			exit 1
			;;
	esac
}

trap cleanup EXIT INT TERM

printf '=== CLI Migrate Integration Tests ===\n\n'

init_output=$(run_cli "$MASTER_PASSWORD\n$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr init '$DB_PATH'")
assert_contains "$init_output" 'Vault initialized:' 'init prepares vault for migrate test'

modern_add_output=$(run_cli 'modern-user\nModern!123\n' "$ROOT_DIR/pwmgr add modern '$DB_PATH'")
assert_contains "$modern_add_output" 'Saved: modern' 'add creates modern encrypted entry'

legacy_add_output=$(run_cli 'legacy-user\nLegacy!123\n' "$ROOT_DIR/pwmgr add legacy '$DB_PATH'")
assert_contains "$legacy_add_output" 'Saved: legacy' 'add creates legacy source entry'

sqlite3 "$DB_PATH" "UPDATE entries SET password = substr(password, 8) WHERE site = 'legacy';"
sqlite3 "$DB_PATH" "INSERT INTO entries (site, username, password) VALUES ('plain', 'plain-user', 'Plain!123');"

legacy_before=$(sqlite3 "$DB_PATH" "SELECT password FROM entries WHERE site = 'legacy';")
plain_before=$(sqlite3 "$DB_PATH" "SELECT password FROM entries WHERE site = 'plain';")
modern_before=$(sqlite3 "$DB_PATH" "SELECT password FROM entries WHERE site = 'modern';")

assert_contains "$legacy_before" ':' 'legacy row uses colon-delimited legacy format before migrate'
assert_contains "$plain_before" 'Plain!123' 'plain row is plaintext before migrate'
assert_starts_with "$modern_before" 'enc:v1:' 'modern row already uses enc:v1 before migrate'

migrate_output=$(run_cli "$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr migrate '$DB_PATH'")
assert_contains "$migrate_output" 'Migration complete. migrated=2, skipped=1' 'migrate reports converted and skipped rows'

modern_after=$(sqlite3 "$DB_PATH" "SELECT password FROM entries WHERE site = 'modern';")
legacy_after=$(sqlite3 "$DB_PATH" "SELECT password FROM entries WHERE site = 'legacy';")
plain_after=$(sqlite3 "$DB_PATH" "SELECT password FROM entries WHERE site = 'plain';")

assert_starts_with "$modern_after" 'enc:v1:' 'modern row remains enc:v1 after migrate'
assert_starts_with "$legacy_after" 'enc:v1:' 'legacy row converts to enc:v1 after migrate'
assert_starts_with "$plain_after" 'enc:v1:' 'plain row converts to enc:v1 after migrate'

legacy_get_output=$(run_cli "$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr get legacy '$DB_PATH'")
plain_get_output=$(run_cli "$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr get plain '$DB_PATH'")
modern_get_output=$(run_cli "$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr get modern '$DB_PATH'")

assert_contains "$legacy_get_output" 'Username : legacy-user' 'legacy username preserved after migrate'
assert_contains "$legacy_get_output" 'Password : Legacy!123' 'legacy password preserved after migrate'
assert_contains "$plain_get_output" 'Username : plain-user' 'plain username preserved after migrate'
assert_contains "$plain_get_output" 'Password : Plain!123' 'plain password encrypted then recovered after migrate'
assert_contains "$modern_get_output" 'Password : Modern!123' 'modern entry still decrypts after migrate'

printf '\nCLI migrate integration test passed.\n'
