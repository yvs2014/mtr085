
# sample: set GIT_COMMIT_NUMBER and GIT_HASH

PORTNAME=	mtr085
PORTVERSION=	GIT_COMMIT_NUMBER
PORTREVISION=	${GITVERSION}
PORTEPOCH=	1
CATEGORIES=	net
MASTER_SITES=	https://github.com/${GITHUB_USER}/${PORTNAME}/tarball/${GITVERSION}/ \
		${MASTER_SITE_LOCAL}
DISTNAME=	${PORTNAME}-${GITVERSION}

MAINTAINER=	e@mail
COMMENT=	MTR v0.85 fork with whois info, IDN, unicode
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
PLIST_FILES+=	share/locale/uk/LC_MESSAGES/mtr085.mo
.endif

.if empty(PORT_OPTIONS:MIPV6)
MESON_ARGS+=	-DIPV6=false
.endif

.if ${PORT_OPTIONS:MSETUID}
post-install:
	@${ECHO_MSG} ""
	@${ECHO_MSG} "${PREFIX}/sbin/mtr is setuid \"root\" "
	@${ECHO_MSG} "Please read about potential security issues"
	@${ECHO_MSG} ""
.endif

.include <bsd.port.mk>
