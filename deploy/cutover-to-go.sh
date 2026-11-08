#!/bin/sh
# Moves Motehold on this machine from the Rust build to the Go build, once.
# Run it in your own terminal as the user the service runs as: it asks for
# the new local password (twice, not shown) and uses sudo for root steps.
#
#   deploy/cutover-to-go.sh                 do it
#   deploy/cutover-to-go.sh --dry-run       print every command, run nothing
#   deploy/cutover-to-go.sh --rollback PREVIOUS ENV_BACKUP [--dry-run]
#                                           back to the Rust build (the exact
#                                           command is printed at the end)
#
# Steps: check, new password, stop, write the hash (the environment file is
# copied to .bak-DATE first), copy the SQLite database read-only and import
# it, install the Go build as a new release and flip `current`, start, check.
# On a failure it stops, names the step and prints how to undo what was done.
# It reads nothing from the environment file but the MOTEHOLD_PASSWORD_HASH
# line it replaces, and prints no secret. PLUGROOT_STATE_ROOT moves every
# path (default /opt/plugroot-state).
set -u

APP=motehold
UNIT=motehold.service
KEY=MOTEHOLD_PASSWORD_HASH
LISTENING="Motehold listening on"
MODULE=github.com/mmdmcy/motehold
STATE=${PLUGROOT_STATE_ROOT:-/opt/plugroot-state}
ENV_FILE=$STATE/.env
DATA=$STATE/services/motehold
DB=$DATA/motehold.sqlite
STORE=$DATA/motehold.json
BLOBS=$DATA/motehold.blobs
REL=$STATE/releases/motehold
REPO=$(cd "$(dirname "$0")/.." && pwd)
SELF=$REPO/deploy/cutover-to-go.sh
NOW=$(date +%Y%m%d-%H%M%S)

# SWAP replaces the KEY= line of the second file with the first file's
# KEY= line, as awk running as root; the content never reaches the screen.
SWAP='NR == FNR { if (index($0, key "=") == 1 && line == "") line = $0; next }
index($0, key "=") == 1 { if (line == "") exit 3; print line; done = 1; next }
{ print }
END { if (!done) exit 4 }'

DRY=
MODE=cutover
STEP=start
DONE=
PREVIOUS=
ENV_BACKUP=-
WORK=
P1=
P2=

say() { printf '%s\n' "$*"; }

step() {
	STEP=$1
	printf '\n== %s\n' "$1"
}

# run prints a command line and runs it in this shell (with --dry-run it
# only prints it). Values set by an earlier command show as variables.
run() {
	printf '+ %s\n' "$1"
	[ -n "$DRY" ] && return 0
	eval "$1" || fail "${2:-the command above failed}"
}

undo_hint() {
	if [ "$MODE" = rollback ]; then
		say "Fix the cause and run the same rollback again: every step is safe to repeat."
		return
	fi
	case " $DONE " in
	*" env "* | *" flipped "*)
		say "To undo what was done: $SELF --rollback ${PREVIOUS:-PREVIOUS} $ENV_BACKUP"
		;;
	*" stopped "*)
		say "To undo what was done: sudo systemctl start $UNIT"
		;;
	*)
		say "Nothing was changed."
		;;
	esac
	case " $DONE " in
	*" imported "*)
		say "The Go store ($STORE and $BLOBS) stays; the Rust build ignores it. Before another cutover, move both aside: mv $STORE $STORE.bak-$NOW && mv $BLOBS $BLOBS.bak-$NOW"
		;;
	esac
}

fail() {
	printf '\nFAILED at step "%s": %s\n' "$STEP" "$1" >&2
	undo_hint >&2
	exit 1
}

cleanup() {
	stty echo 2>/dev/null
	if [ -n "$WORK" ] && [ -z "$DRY" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
trap 'printf "\nInterrupted.\n" >&2; undo_hint >&2; exit 130' INT TERM HUP

read_password() {
	[ -t 0 ] || fail "run it in a terminal: it asks for the new password"
	printf 'New %s password: ' "$APP"
	stty -echo
	IFS= read -r P1 || P1=
	stty echo
	printf '\nAgain: '
	stty -echo
	IFS= read -r P2 || P2=
	stty echo
	printf '\n'
	[ -n "$P1" ] || fail "the password is empty"
	[ "$P1" = "$P2" ] || fail "the two passwords differ"
}

# swap_line FILE: the KEY= line of FILE replaces the one in ENV_FILE, through
# a new owner-only file with the old file's owner and mode, renamed over it.
swap_line() {
	run "sudo install -m 600 /dev/null $ENV_FILE.new"
	run "sudo sh -c 'awk -v key=\"\$1\" \"\$2\" \"\$3\" \"\$4\" > \"\$5\"' sh $KEY \"\$SWAP\" $1 $ENV_FILE $ENV_FILE.new" \
		"the $KEY line could not be swapped"
	run "sudo chown --reference=$ENV_FILE $ENV_FILE.new && sudo chmod --reference=$ENV_FILE $ENV_FILE.new"
	run "sudo mv -f $ENV_FILE.new $ENV_FILE"
	run "test \"\$(sudo grep -c '^$KEY=' $ENV_FILE)\" = 1" "the environment file no longer has exactly one $KEY line"
}

check_started() {
	run "sleep 2"
	run "systemctl is-active --quiet $UNIT" "$UNIT is not running"
	run "sudo journalctl -u $UNIT --since @\"\$SINCE\" -o cat --no-pager > \"\$WORK/journal\""
	run "! grep -q 'Error:' \"\$WORK/journal\"" "the journal shows an Error: line (sudo journalctl -u $UNIT -n 20)"
	run "grep '$LISTENING' \"\$WORK/journal\"" "no '$LISTENING' line in the journal"
}

cutover() {
	step "check"
	run 'test "$(id -u)" -ne 0' "run it as the service's user, not as root (it uses sudo itself)"
	run "test \"\$(systemctl show -p User --value $UNIT)\" = \"\$(id -un)\"" "run it as the user $UNIT runs as"
	run '(for tool in go sqlite3 curl awk stty; do command -v $tool >/dev/null || exit 1; done)' \
		"one of go, sqlite3, curl, awk, stty is missing"
	run "systemctl cat $UNIT > /dev/null" "$UNIT does not exist"
	run "systemctl cat $UNIT | grep -qF '$REL/current/$APP serve'" "$UNIT does not run $REL/current/$APP"
	run "systemctl cat $UNIT | grep -qF 'MOTEHOLD_DB=\"$DB\"'" "$UNIT does not keep its data in $DB"
	run "systemctl cat $UNIT | grep -qF 'EnvironmentFile=$ENV_FILE'" "$UNIT does not read $ENV_FILE"
	run "test \"\$(cd $REPO && go list -m all)\" = $MODULE" "go list -m all names more than $MODULE"
	run "(cd $REPO && go vet ./... && go test ./...)" "the Go checks failed"
	run 'WORK=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/cutover-'$APP'.XXXXXX")'
	run "(cd $REPO && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o \"\$WORK/$APP\" .)" "the Go build failed"
	run "PREVIOUS=\$(readlink $REL/current) && test -x $REL/\"\$PREVIOUS\"/$APP" "$REL/current is not a release"
	run "test -f $DB" "$DB is missing"
	run "test ! -e $STORE && test ! -e $BLOBS" "a Go store is already there: move $STORE and $BLOBS aside first"
	run "sudo -v"
	run "sudo test -f $ENV_FILE && sudo test ! -L $ENV_FILE" "$ENV_FILE is missing or a symlink"
	run "test \"\$(sudo grep -c '^$KEY=' $ENV_FILE)\" = 1" "$ENV_FILE does not have exactly one $KEY line"

	step "new password"
	if [ -n "$DRY" ]; then
		say "(reads the new password twice from the terminal, not shown)"
	else
		read_password
	fi
	run 'printf "%s" "$P1" | "$WORK/'$APP'" hash-password --stdin > "$WORK/hash"; P1= P2='
	run 'grep -q "^[$]pbkdf2-sha256[$]i=600000,l=32[$]" "$WORK/hash"' "hash-password did not make a PBKDF2 hash"
	run "printf \"%s='%s'\\n\" $KEY \"\$(cat \"\$WORK/hash\")\" > \"\$WORK/line\""

	step "stop"
	run "sudo systemctl stop $UNIT"
	DONE="$DONE stopped"

	step "write the new hash"
	run "sudo cp -p $ENV_FILE $ENV_FILE.bak-$NOW-$APP"
	ENV_BACKUP=$ENV_FILE.bak-$NOW-$APP
	DONE="$DONE env"
	swap_line "\"\$WORK/line\""
	run "test \"\$(sudo grep -c \"^$KEY='[\$]pbkdf2-sha256[\$]i=\" $ENV_FILE)\" = 1" "the new hash is not in place"

	step "copy and import"
	run "sqlite3 -readonly $DB \".backup \$WORK/copy.sqlite\""
	run "MOTEHOLD_DB=$DB \"\$WORK/$APP\" import-sqlite --from \"\$WORK/copy.sqlite\""
	DONE="$DONE imported"
	run "test \"\$(stat -c %a $STORE)\" = 600 && test -d $BLOBS" "the store is not an owner-only file"

	step "install the Go release"
	run 'STAMP=$(date -u +%Y%m%d%H%M%S)'
	run "sudo install -d -m 755 $REL/\"\$STAMP\""
	run "sudo install -m 755 \"\$WORK/$APP\" $REL/\"\$STAMP\"/$APP"
	run "sudo ln -sfn \"\$STAMP\" $REL/current.new && sudo mv -T $REL/current.new $REL/current"
	DONE="$DONE flipped"

	step "start"
	run 'SINCE=$(date +%s)'
	run "sudo systemctl start $UNIT"
	DONE="$DONE started"

	step "check"
	check_started
	run "URL=\$(sed -n 's/^$LISTENING \\(http:[^ ]*\\)\$/\\1/p' \"\$WORK/journal\" | tail -n 1) && test -n \"\$URL\""
	run "curl -s -m 5 -A cutover \"\$URL/.well-known/linuxmice/component\" | grep -q '\"identity_mode\":\"local\"'" \
		"the status endpoint does not say identity_mode local"

	printf '\nDone: Motehold runs the Go build (%s/%s).\n' "$REL" "${STAMP:-STAMP}"
	say "Notes added from now on live only in $STORE; the Rust build does not see them."
	say "Back to the Rust build: $SELF --rollback ${PREVIOUS:-PREVIOUS} $ENV_BACKUP"
}

rollback() {
	MODE=rollback
	PREVIOUS=$1
	ENV_BACKUP=$2
	case "$PREVIOUS" in '' | *[!0-9]*) fail "PREVIOUS must be a release name such as 20261023094627" ;; esac
	step "check"
	run "test -x $REL/$PREVIOUS/$APP" "$REL/$PREVIOUS/$APP is missing"
	run 'WORK=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/rollback-'$APP'.XXXXXX")'
	run "sudo -v"
	if [ "$ENV_BACKUP" != - ]; then
		run "test \"\$(sudo grep -c '^$KEY=' $ENV_BACKUP)\" = 1" "$ENV_BACKUP does not have exactly one $KEY line"
	fi
	step "stop"
	run "sudo systemctl stop $UNIT"
	step "back to the Rust release"
	run "sudo ln -sfn $PREVIOUS $REL/current.new && sudo mv -T $REL/current.new $REL/current"
	if [ "$ENV_BACKUP" != - ]; then
		step "restore the old hash line"
		swap_line "$ENV_BACKUP"
	fi
	step "start"
	run 'SINCE=$(date +%s)'
	run "sudo systemctl start $UNIT"
	step "check"
	check_started
	printf '\nDone: Motehold runs the Rust build again (%s/%s). The Go store stays in %s.\n' "$REL" "$PREVIOUS" "$DATA"
}

ARGS=
for arg in "$@"; do
	case "$arg" in
	--dry-run) DRY=1 ;;
	*) ARGS="$ARGS $arg" ;;
	esac
done
# shellcheck disable=SC2086
set -- $ARGS
if [ -n "$DRY" ]; then
	say "Dry run: nothing is run. WORK, PREVIOUS, STAMP, SINCE and URL are set by the commands that print them."
fi
case "${1:-}" in
"") cutover ;;
--rollback)
	[ $# -eq 3 ] || fail "usage: $SELF --rollback PREVIOUS ENV_BACKUP|- [--dry-run]"
	rollback "$2" "$3"
	;;
*) fail "usage: $SELF [--dry-run] | --rollback PREVIOUS ENV_BACKUP|- [--dry-run]" ;;
esac
