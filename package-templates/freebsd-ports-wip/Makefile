
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

OPTIONS_DEFINE=	SETUID IPINFO IDN UNICODE IPV6 GRAPH
OPTIONS_DEFAULT=	IPINFO IDN UNICODE IPV6
IPINFO_DESC=	Extended information like ASN, etc.
GRAPH_DESC=	Graphs with X11 XCB backend
SETUID_DESC=	Install with setuid root

USES+=	cmake:noninja
USES+=	pkgconfig

.include <bsd.port.options.mk>

.if ${PORT_OPTIONS:MSETUID}
PLIST_FILES=	"@(,,4555) sbin/mtr"
.else
PLIST_FILES=	sbin/mtr
.endif
PLIST_FILES+=	man/man8/mtr.8.gz

CMAKE_ARGS+=	-DCAP=OFF
CMAKE_ARGS+=	-DSBINDIR=ON
CMAKE_ARGS+=	-DCMAKE_INSTALL_MANDIR=man

.if empty(PORT_OPTIONS:MIPINFO)
CMAKE_ARGS+=	-DIPINFO=OFF
.endif

.if empty(PORT_OPTIONS:MIDN)
CMAKE_ARGS+=	-DIDN=OFF
.else
LIB_DEPENDS+=	libidn2.so:dns/libidn2
.endif

.if empty(PORT_OPTIONS:MUNICODE)
CMAKE_ARGS+=	-DUNICODE=OFF
.endif

.if empty(PORT_OPTIONS:MIPV6)
CMAKE_ARGS+=	-DIPV6=OFF
.endif

.if ${PORT_OPTIONS:MGRAPH}
USE_XORG=	xcb
CMAKE_ARGS+=	-DGRAPH=ON
GRAPH_LIB_DEPENDS+=	libcairo.so:graphics/cairo \
		libpango-1.0.so:x11-toolkits/pango \
		libxcb-keysyms.so:x11/xcb-util-keysyms
.endif

.if ${PORT_OPTIONS:MSETUID}
post-install:
	@${ECHO_MSG} ""
	@${ECHO_MSG} "${PREFIX}/sbin/mtr is setuid \"root\" "
	@${ECHO_MSG} "Please read about potential security issues"
	@${ECHO_MSG} ""
.endif

.include <bsd.port.mk>
