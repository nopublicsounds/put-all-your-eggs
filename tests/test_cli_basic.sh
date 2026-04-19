#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DB_DIR=$(mktemp -d)
DB_PATH="$DB_DIR/vault.db"
ALT_DB_PATH="$DB_DIR/alt.db"
ENV_DB_PATH="$DB_DIR/env.db"
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

set_config_output=$("$ROOT_DIR/pwmgr" config set db "$ALT_DB_PATH")
assert_contains "$set_config_output" 'Default DB set to:' 'config set db reports saved path'

config_get_output=$("$ROOT_DIR/pwmgr" config get db)
assert_contains "$config_get_output" "$ALT_DB_PATH" 'config get db returns configured path'

init_alt_output=$(run_cli "$MASTER_PASSWORD\n$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr init")
assert_contains "$init_alt_output" 'Vault initialized:' 'init without db_path uses configured default db'

if [ ! -f "$ALT_DB_PATH" ]; then
	printf '  FAIL  configured default db file is created\n'
	exit 1
else
	printf '  PASS  configured default db file is created\n'
fi

env_config_get_output=$(PWMGR_DB_PATH="$ENV_DB_PATH" "$ROOT_DIR/pwmgr" config get db)
assert_contains "$env_config_get_output" "$ENV_DB_PATH" 'env var overrides config for effective db'

init_env_output=$(run_cli "$MASTER_PASSWORD\n$MASTER_PASSWORD\n" "PWMGR_DB_PATH='$ENV_DB_PATH' $ROOT_DIR/pwmgr init")
assert_contains "$init_env_output" 'Vault initialized:' 'init without db_path uses env db override'

if [ ! -f "$ENV_DB_PATH" ]; then
	printf '  FAIL  env override db file is created\n'
	exit 1
else
	printf '  PASS  env override db file is created\n'
fi

explicit_cli_output=$(run_cli "$MASTER_PASSWORD\n$MASTER_PASSWORD\n" "PWMGR_DB_PATH='$ENV_DB_PATH' $ROOT_DIR/pwmgr init '$DB_PATH'")
assert_contains "$explicit_cli_output" 'Vault initialized:' 'explicit db_path overrides env/config'

if [ ! -f "$DB_PATH" ]; then
	printf '  FAIL  explicit db_path file is created\n'
	exit 1
else
	printf '  PASS  explicit db_path file is created\n'
fi

set +e
get_missing_output=$(run_cli "$MASTER_PASSWORD\n" "$ROOT_DIR/pwmgr get github '$DB_PATH'" 2>&1)
get_missing_status=$?
set -e

if [ "$get_missing_status" -eq 0 ]; then
	printf '  FAIL  get missing entry returns failure\n'
	exit 1
fi

assert_contains "$get_missing_output" 'No entry found: github' 'get missing entry reports not found'

set +e
init_extra_output=$("$ROOT_DIR/pwmgr" init "$DB_PATH" extra 2>&1)
init_extra_status=$?
list_extra_output=$("$ROOT_DIR/pwmgr" list "$DB_PATH" extra 2>&1)
list_extra_status=$?
change_extra_output=$("$ROOT_DIR/pwmgr" change-master "$DB_PATH" extra 2>&1)
change_extra_status=$?
migrate_extra_output=$("$ROOT_DIR/pwmgr" migrate "$DB_PATH" extra 2>&1)
migrate_extra_status=$?
set -e

if [ "$init_extra_status" -eq 0 ]; then
	printf '  FAIL  init rejects extra argument\n'
	exit 1
else
	printf '  PASS  init rejects extra argument\n'
fi
assert_contains "$init_extra_output" 'Usage:' 'init extra argument shows usage'

if [ "$list_extra_status" -eq 0 ]; then
	printf '  FAIL  list rejects extra argument\n'
	exit 1
else
	printf '  PASS  list rejects extra argument\n'
fi
assert_contains "$list_extra_output" 'Usage:' 'list extra argument shows usage'

if [ "$change_extra_status" -eq 0 ]; then
	printf '  FAIL  change-master rejects extra argument\n'
	exit 1
else
	printf '  PASS  change-master rejects extra argument\n'
fi
assert_contains "$change_extra_output" 'Usage:' 'change-master extra argument shows usage'

if [ "$migrate_extra_status" -eq 0 ]; then
	printf '  FAIL  migrate rejects extra argument\n'
	exit 1
else
	printf '  PASS  migrate rejects extra argument\n'
fi
assert_contains "$migrate_extra_output" 'Usage:' 'migrate extra argument shows usage'

printf '\nCLI basic integration test passed.\n'