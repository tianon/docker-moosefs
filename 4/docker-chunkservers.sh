#!/usr/bin/env bash
set -Eeuo pipefail

chunkservers="${MFS_CHUNKSERVERS:?set MFS_CHUNKSERVERS to the base directory of all chunkservers}"
cd "$chunkservers"

temp="$(mktemp -d)"
trap "$(printf 'rm -rf %q' "$temp")" EXIT

# if "ALLOW_STARTING_WITH_INVALID_DISKS" isn't set, let's change the default from 0 to 1
# (otherwise, a chunkserver with invalid disks stops ALL our chunkservers from starting)
: "${MFSCHUNKSERVER_ALLOW_STARTING_WITH_INVALID_DISKS:=1}"
export MFSCHUNKSERVER_ALLOW_STARTING_WITH_INVALID_DISKS

copy_etc() {
	local dir="$1"; shift
	cp -aT /etc/mfs "$dir"
	find "$dir" -type f -exec sed -ri "s!/etc/mfs!$dir!g" '{}' +
}

declare -A pids=() cfgs=()

all_still_up() {
	local name pid cfg
	for name in "${!pids[@]}"; do
		pid="${pids["$name"]}"
		if [ ! -d "/proc/$pid" ]; then
			if cfg="${cfgs["$name"]:-}" && [ -n "$cfg" ] && [ ! -s "$cfg" ]; then
				# if a process is dead, and we had a config file but it's now empty or gone, we should ignore this process (was probably a removed drive/server)
				unset pids["$name"] cfgs["$name"]
				continue
			fi
			return 1
		fi
	done
	if [ "${#pids[@]}" -eq 0 ]; then
		# if we've emptied the full list of processes, we're not "up" anymore :)
		return 1
	fi
	return 0
}
any_still_up() {
	local pid
	for pid in "${pids[@]}"; do
		if [ -d "/proc/$pid" ]; then
			return 0
		fi
	done
	return 1
}
kill_all() {
	local pid
	for pid in "${pids[@]}"; do
		if [ -d "/proc/$pid" ]; then
			# try to make sure the process is still running before signalling it to avoid "pid X doesn't exist" over and over again if one is hung and we're trying to stop
			kill "$@" "$pid"
		fi
	done
}
end_session() {
	while any_still_up; do
		kill_all
		sleep 1
		# TODO timeout?
	done
	exit "$@"
}
hup_all() {
	if any_still_up; then
		kill_all -HUP
	fi
}
trap 'end_session 0' ABRT ALRM INT KILL PIPE QUIT STOP TERM USR1 USR2
trap 'end_session 1' ERR
trap 'hup_all' HUP

# backwards compatibility
for cfg in */mfshdd.cfg; do
	[ -f "$cfg" ] || continue
	dir="$(dirname "$cfg")"
	new="$dir-mfshdd.cfg"
	if [ ! -f "$new" ]; then
		mv -vT "$cfg" "$new"
	fi
done

# auto-detect and prepare new chunkservers
for chunks in */chunks/; do
	chunks="${chunks%/}"
	[ -d "$chunks" ] || continue
	dir="$(dirname "$chunks")"
	cfg="$dir-mfshdd.cfg"
	if [ ! -s "$cfg" ]; then
		readlink -ve "$chunks" >> "$cfg"
	fi
done

port='9422'
for cfg in *-mfshdd.cfg; do
	[ -f "$cfg" ] || continue

	base="${cfg%-mfshdd.cfg}"
	name="$(basename "$base")"
	dir="$(dirname "$base")"

	var="$dir/.var-lib-mfs-$name"
	if [ ! -d "$var" ]; then
		if [ -d "$dir/$name/var-lib-mfs" ]; then
			# backwards compatibility
			mv -vT "$dir/$name/var-lib-mfs" "$var"
		else
			# pre-seed our new state directory with the standard "empty" contents
			cp -aT /var/lib/mfs "$var"
			chmod 755 "$var" || :
		fi
	fi

	copy_etc "$temp/$name"

	sed -r "s!/etc/mfs!$temp/$name!g" /usr/local/bin/docker-entrypoint.sh > "$temp/$name/entrypoint.sh"
	chmod +x "$temp/$name/entrypoint.sh"

	cfg="$(readlink -ve "$cfg")"
	var="$(readlink -ve "$var")"
	MFSCHUNKSERVER_CSSERV_LISTEN_PORT="$port" \
		MFSCHUNKSERVER_SYSLOG_IDENT="$name" \
		MFSCHUNKSERVER_HDD_CONF_FILENAME="$cfg" \
		MFSCHUNKSERVER_DATA_PATH="$var" \
		"$temp/$name/entrypoint.sh" \
		mfschunkserver -func "$temp/$name/mfschunkserver.cfg" &
	pid="$!"
	pids["$name"]="$pid"
	cfgs["$name"]="$cfg"

	(( port++ )) || :
	all_still_up || end_session 1
done

while any_still_up; do
	all_still_up || end_session 1
	sleep 5
done
