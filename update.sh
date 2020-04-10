#!/bin/bash
set -eo pipefail

cd "$(dirname "$(readlink -f "$BASH_SOURCE")")"

versions=( [0-9]*/ )
versions=( "${versions[@]%/}" )

tags="$(
	git ls-remote --tags https://github.com/moosefs/moosefs.git \
		| cut -d/ -f3 \
		| cut -d^ -f1 \
		| sort -ruV
)"

for version in "${versions[@]}"; do
	fullVersion="$(grep "^v$version[.]" <<<"$tags" | head -1)"
	if [ -z "$fullVersion" ]; then
		echo >&2 "warning: cannot find full version for $version"
		continue
	fi

	fullVersion="${fullVersion#v}"
	echo "$version: $fullVersion"

	sed -ri -e 's/^(ENV MOOSEFS_VERSION) .*/\1 '"$fullVersion"'/' "$version/Dockerfile"
done
