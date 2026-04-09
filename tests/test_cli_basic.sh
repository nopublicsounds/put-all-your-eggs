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

printf '=== CLI Basic Integration Tests ===\n\n'

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

generate_no_output=$(run_cli 'n\n' "$ROOT_DIR/pwmgr generate 16 '$DB_PATH'")
assert_contains "$generate_no_output" 'Generated password:' 'generate prints password'
list_after_no_save=$("$ROOT_DIR/pwmgr" list "$DB_PATH")
assert_contains "$list_after_no_save" 'Total 0 entries' 'generate with n does not save entry'

generate_yes_output=$(run_cli "y\ngensite\ngenuser\n" "$ROOT_DIR/pwmgr generate 16 '$DB_PATH'")
assert_contains "$generate_yes_output" 'Generated password:' 'generate yes prints password'
assert_contains "$generate_yes_output" 'Saved: gensite' 'generate yes saves entry'

stored_gen=$(sqlite3 "$DB_PATH" "SELECT password FROM entries WHERE site = 'gensite';")
case "$stored_gen" in
	enc:v1:*)
		printf '  PASS  generate stores encrypted password\n'
		;;
	*)
		printf '  FAIL  generate stores encrypted password\n'
		printf '        stored value: %s\n' "$stored_gen"
		exit 1
		;;
esac

get_gen_output=$(run_cli "$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr get gensite '$DB_PATH'")
assert_contains "$get_gen_output" 'Username : genuser' 'generate entry username matches'

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