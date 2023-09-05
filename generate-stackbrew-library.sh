#!/usr/bin/env bash
set -Eeuo pipefail

declare -A aliases=(
	[3]='latest'
)

self="$(basename "$BASH_SOURCE")"
cd "$(dirname "$(readlink -f "$BASH_SOURCE")")"

versions=(
	[0-9]*/
	mfs-volume-driver/
)
versions=( "${versions[@]%/}" )

# get the most recent commit which modified any of "$@"
fileCommit() {
	git log -1 --format='format:%H' HEAD -- "$@"
}

# get the most recent commit which modified "$1/Dockerfile" or any file COPY'd from "$1/Dockerfile"
dirCommit() {
	local dir="$1"; shift
	(
		cd "$dir"
		fileCommit \
			Dockerfile \
			$(git show HEAD:./Dockerfile | awk '
				toupper($1) == "COPY" {
					for (i = 2; i < NF; i++) {
						if ($i ~ /^--from=/) {
							next
						}
						print $i
					}
				}
			')
	)
}

cat <<-EOH
# this file is generated via https://github.com/tianon/docker-moosefs/blob/$(fileCommit "$self")/$self

Maintainers: Tianon Gravi <admwiggin@gmail.com> (@tianon)
GitRepo: https://github.com/tianon/docker-moosefs.git
EOH

# prints "$2$1$3$1...$N"
join() {
	local sep="$1"; shift
	local out; printf -v out "${sep//%/%%}%s" "$@"
	echo "${out#$sep}"
}

for version in "${versions[@]}"; do
	commit="$(dirCommit "$version")"

	parents="$(git show "$commit":"$version/Dockerfile" | awk '$1 == "FROM"  { print $2 }')"
	parentsArches='[]'
	for parent in $parents; do
		parentArches="$(bashbrew remote arches --json "$parent" | jq -c '.arches | keys')"
		if [ "$parentsArches" = '[]' ]; then
			parentsArches="$parentArches"
		else
			parentsArches="$(jq <<<"$parentsArches" -c --argjson arches "$parentArches" '. - (. - $arches)')"
		fi
	done
	arches="$(jq <<<"$parentsArches" -r 'join(", ")')"

	case "$version" in
		mfs-volume-driver)
			echo
			cat <<-EOE
				Tags: volume-driver
				GitCommit: $commit
				Directory: $version
				Architectures: $arches
			EOE
			continue
			;;
	esac

	fullVersion="$(git show "$commit":"$version/Dockerfile" | awk '$1 == "ENV" && $2 == "MOOSEFS_VERSION" { print $3; exit }')"

	rcVersion="${version%-rc}"

	versionAliases=()
	if [ "$version" = "$rcVersion" ]; then
		while [ "$fullVersion" != "$rcVersion" -a "${fullVersion%[.-]*}" != "$fullVersion" ]; do
			versionAliases+=( $fullVersion )
			fullVersion="${fullVersion%[.-]*}"
		done
	else
		versionAliases+=( $fullVersion )
	fi
	versionAliases+=(
		$version
		${aliases[$version]:-}
	)

	echo
	cat <<-EOE
		Tags: $(join ', ' "${versionAliases[@]}")
		GitCommit: $commit
		Directory: $version
		Architectures: $arches
	EOE
done
