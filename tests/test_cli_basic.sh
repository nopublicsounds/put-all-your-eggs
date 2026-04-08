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

trap cleanup EXIT INT TERM

printf '=== CLI 기본 통합 테스트 ===\n\n'

init_output=$(run_cli "$MASTER_PASSWORD\n$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr init '$DB_PATH'")
assert_contains "$init_output" 'Master password set successfully.' 'init sets master password'
assert_contains "$init_output" 'Vault initialized:' 'init creates vault'

add_output=$(run_cli 'octocat\nGhPass!123\n' "$ROOT_DIR/pwmgr add github '$DB_PATH'")
assert_contains "$add_output" 'Saved: github' 'add stores new entry'

stored_password=$(sqlite3 "$DB_PATH" "SELECT password FROM entries WHERE site = 'github';")
case "$stored_password" in
	enc:v1:*)
		printf '  PASS  add stores encrypted password\n'
		;;
	*)
		printf '  FAIL  add stores encrypted password\n'
		printf '        stored value: %s\n' "$stored_password"
		exit 1
		;;
esac

list_output=$("$ROOT_DIR/pwmgr" list "$DB_PATH")
assert_contains "$list_output" 'github' 'list shows stored site'
assert_contains "$list_output" 'Total 1 entries' 'list shows entry count'

get_output=$(run_cli "$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr get github '$DB_PATH'")
assert_contains "$get_output" 'Username : octocat' 'get shows username'
assert_contains "$get_output" 'Password : GhPass!123' 'get decrypts password'

delete_output=$(run_cli "$MASTER_PASSWORD\ny\n" "$ROOT_DIR/pwmgr delete github '$DB_PATH'")
assert_contains "$delete_output" 'Deleted entry: github' 'delete removes entry'

list_after_delete=$("$ROOT_DIR/pwmgr" list "$DB_PATH")
assert_contains "$list_after_delete" 'Total 0 entries' 'list shows zero entries after delete'

set +e
get_missing_output=$(run_cli "$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr get github '$DB_PATH'" 2>&1)
get_missing_status=$?
set -e

if [ "$get_missing_status" -eq 0 ]; then
	printf '  FAIL  get missing entry returns failure\n'
	exit 1
fi

assert_contains "$get_missing_output" 'No entry found: github' 'get missing entry reports not found'

printf '\nCLI basic integration test passed.\n'