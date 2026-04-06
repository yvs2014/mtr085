
# sample: set GIT_COMMIT_NUMBER and GIT_HASH

PORTNAME=	mtr085
PORTVERSION=	GIT_COMMIT_NUMBER
CATEGORIES=	freebsd-ports-wip net
MASTER_SITES=	https://github.com/${GITHUB_USER}/${PORTNAME}/tarball/${GITVERSION}/ \
		${MASTER_SITE_LOCAL}
DISTNAME=	${PORTNAME}-${GITVERSION}

MAINTAINER=	e@mail
COMMENT=	MTR-0.85 fork with whois info, IDN, NLS, unicode, etc.
WWW=	https://github.com/${GITHUB_USER}/${PORTNAME}

LICENSE=	GPLv2

CONFLICTS_INSTALL?=	mtr mtr-nox11

GITHUB_USER=	yvs2014
GITVERSION=	GIT_HASH
WRKSRC=		${WRKDIR}/${GITHUB_USER}-${PORTNAME}-${GITVERSION}
FETCH_ARGS=	-Fpr

OPTIONS_DEFINE=	SETUID IPINFO IDN NLS UNICODE IPV6
OPTIONS_DEFAULT=	IPINFO IDN UNICODE IPV6
IPINFO_DESC=	Extended information like ASN, etc.
SETUID_DESC=	Install with setuid root
NLS_DESC=	NLS locale LC_MESSAGES

USES+=	meson
USES+=	pkgconfig

.include <bsd.port.options.mk>

.if ${PORT_OPTIONS:MSETUID}
PLIST_FILES=	"@(,,4555) sbin/mtr"
.else
PLIST_FILES=	sbin/mtr
.endif
PLIST_FILES+=	share/man/man8/mtr.8.gz

MESON_ARGS+=	-DCAP=false
MESON_ARGS+=	-DSBIN=true

.if empty(PORT_OPTIONS:MIPINFO)
MESON_ARGS+=	-DIPINFO=false
.endif

.if !empty(PORT_OPTIONS:MIDN)
LIB_DEPENDS+=	libidn2.so:dns/libidn2
.endif

.if empty(PORT_OPTIONS:MUNICODE)
MESON_ARGS+=	-DUNICODE=false
.endif

.if empty(PORT_OPTIONS:MNLS)
MESON_ARGS+=	-DNLS=false
.else
USES+=	gettext-runtime
PLIST_FILES+=	share/locale/es/LC_MESSAGES/mtr085.mo
PLIST_FILES+=	share/locale/it/LC_MESSAGES/mtr085.mo
PLIST_FILES+=	share/locale/pt/LC_MESSAGES/mtr085.mo
PLIST_FILES+=	share/locale/uk/LC_MESSAGES/mtr085.mo
.endif

.if empty(PORT_OPTIONS:MIPV6)
MESON_ARGS+=	-DIPV6=false
.endif

.if ${PORT_OPTIONS:MSETUID}
warning-at-install:
	@${ECHO_MSG} "===>  SECURITY-REPORT"
	@${ECHO_MSG} "    This port has installed the following binaries which execute with"
	@${ECHO_MSG} "    increased privileges (setuid \"root\"): ${PREFIX}/sbin/mtr"
	@${ECHO_MSG} ""
	@${ECHO_MSG} "    If there are vulnerabilities in this program there may be a security"
	@${ECHO_MSG} "    risk to the system."
	@${ECHO_MSG} "    Please type 'make deinstall' to deinstall the port if this is a concern."
	@${ECHO_MSG} ""

post-install: warning-at-install
install-message: warning-at-install

.endif

.include <bsd.port.mk>
