FROM debian:trixie-slim

RUN set -eux; \
	apt-get install --update -y --no-install-recommends \
# mfscli (and cgi) are Python-based
		python3 \
# mfsmount needs "fusermount"
		fuse \
	; \
	apt-get dist-clean; \
# allow running mfsmount as non-root
	grep '^#user_allow_other$' /etc/fuse.conf; \
	sed -ri 's/^#user_allow_other$/user_allow_other/' /etc/fuse.conf; \
	grep '^user_allow_other$' /etc/fuse.conf

RUN set -eux; \
	groupadd \
		--gid 9400 \
		--system \
		mfs \
	; \
	useradd \
		--comment 'MooseFS' \
		--gid mfs \
		--home-dir /var/lib/mfs \
		--no-create-home \
		--system \
		--uid 9400 \
		mfs \
	; \
	mkdir /var/lib/mfs; \
	chown mfs:mfs /var/lib/mfs; \
	id mfs

# https://github.com/moosefs/moosefs/releases
ENV MOOSEFS_VERSION 4.57.7

RUN set -eux; \
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get install --update -y --no-install-recommends \
		ca-certificates \
		wget \
		\
		dpkg-dev \
		file \
		gcc \
		libc6-dev \
		libfuse-dev \
		libpcap-dev \
		make \
		pkg-config \
		zlib1g-dev \
	; \
	\
	wget -O moosefs.tgz "https://github.com/moosefs/moosefs/archive/v${MOOSEFS_VERSION}.tar.gz"; \
	mkdir /usr/local/src/moosefs; \
	tar --extract \
		--file moosefs.tgz \
		--directory /usr/local/src/moosefs \
		--strip-components 1 \
	; \
	rm moosefs.tgz; \
	\
	( \
		cd /usr/local/src/moosefs; \
		gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \
		./configure \
			--build="$gnuArch" \
			--disable-static \
			--enable-option-checking=fatal \
			--localstatedir=/var/lib \
			--sysconfdir=/etc \
			--with-default-group=mfs \
			--with-default-user=mfs \
		; \
	); \
	make -C /usr/local/src/moosefs -j "$(nproc)"; \
	make -C /usr/local/src/moosefs install; \
	ldconfig; \
	rm -rf /usr/local/src/moosefs; \
	\
# prep the default configuration so things generally work Out-of-the-Box
	chown -R mfs:mfs /etc/mfs; \
	for sample in /etc/mfs/*.sample; do \
		cfg="${sample%.sample}"; \
		[ -s "$cfg" ] || cp -avT "$sample" "$cfg"; \
	done; \
	cp -avT /etc/mfs /etc/mfs.sample; \
	rm -v /etc/mfs.sample/*.sample; \
	cp -avT /var/lib/mfs /var/lib/mfs.sample; \
	cp -avT /var/lib/mfs/metadata.mfs.empty /var/lib/mfs/metadata.mfs; \
	\
# allow us to run as an arbitrary user but still modify configuration
	chmod 777 /etc/mfs; \
	chmod 1777 /var/lib/mfs; \
	\
	apt-mark auto '.*' > /dev/null; \
	apt-mark manual $savedAptMark > /dev/null; \
	find /usr/local -type f -executable -exec ldd '{}' ';' \
		| awk '/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); print so }' \
		| sort -u \
		| xargs -r dpkg-query --search 2>/dev/null \
		| cut -d: -f1 \
		| sort -u \
		| xargs -r apt-mark manual \
	; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	apt-get dist-clean; \
	\
	mfsmount --version; \
	mfscli -v; \
	mfschunkserver -v; \
	mfsmaster -v; \
	mfschunktool -v; \
	mfsmetalogger -v

RUN set -eux; \
# prep a scratch space with appropriate permissions to be able to do quick prototyping Out-of-the-Box
	mkdir /mnt/mfs; \
	chown mfs:mfs /mnt/mfs

# without this, the Python-based mfscli "-f" flag refuses to use UTF-8 box-drawing characters
ENV LANG=C.UTF-8

COPY docker-entrypoint.sh docker-chunkservers.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["bash"]
