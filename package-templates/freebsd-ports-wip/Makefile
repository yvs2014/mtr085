# $FreeBSD$

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
COMMENT=	mtr v0.85 fork with IDN, Unicode, extra IP-address info

LICENSE=	GPLv2

CONFLICTS_INSTALL?=	mtr mtr-nox11

PATCH_DEPENDS=	${AUTOCONF_DEPENDS} ${AUTOMAKE_DEPENDS}

GITHUB_USER=	yvs2014
GITVERSION=	GIT_HASH
WRKSRC=		${WRKDIR}/${GITHUB_USER}-${PORTNAME}-${GITVERSION}
FETCH_ARGS=	-Fpr

OPTIONS_DEFINE=	IPINFO IDN UNICODE IPV6
OPTIONS_RADIO=	X11
OPTIONS_RADIO_X11=	GRAPHCAIRO_XCB GRAPHCAIRO_XLIB
OPTIONS_DEFAULT=UNICODE IPINFO
OPTIONS_UNSET=	IPV6
IPINFO_DESC=	Extended information like ASN, etc.
GRAPHCAIRO_XCB_DESC=	graphcairo X11 XCB backend
GRAPHCAIRO_XLIB_DESC=	graphcairo X11 Xlib backend

GNU_CONFIGURE=	yes
USES=		autoreconf
USES+=		gmake

PLIST_FILES=	sbin/mtr
PLIST_FILES+=	man/man8/mtr.8

.include <bsd.port.options.mk>
.include "${USESDIR}/autoreconf.mk"

CONFIGURE_ARGS+=--without-libcap
CONFIGURE_ARGS+=--enable-suid-last-resort

.if empty(PORT_OPTIONS:MIPINFO)
CONFIGURE_ARGS+=--without-ipinfo
.endif

.if ${PORT_OPTIONS:MIDN}
CONFIGURE_ARGS+=--with-libidn
LIB_DEPENDS+=	libidn2.so:dns/libidn2
.endif

.if empty(PORT_OPTIONS:MUNICODE)
CONFIGURE_ARGS+=--without-unicode
.endif

.if empty(PORT_OPTIONS:MIPV6)
CONFIGURE_ARGS+=--disable-ipv6
.endif

.if ${PORT_OPTIONS:MGRAPHCAIRO_XCB}
USE_XORG=	xcb
USES+=		pkgconfig
CONFIGURE_ARGS+=--with-graphcairo-xcb
GRAPHCAIRO_XCB_LIB_DEPENDS+=	libcairo.so:graphics/cairo \
		libpango-1.0.so:x11-toolkits/pango \
		libxcb-keysyms.so:x11/xcb-util-keysyms
.else
.if ${PORT_OPTIONS:MGRAPHCAIRO_XLIB}
USE_XORG=	x11
USES+=		pkgconfig
CONFIGURE_ARGS+=--with-graphcairo-xlib
LIB_DEPENDS+=	libcairo.so:graphics/cairo \
		libpango-1.0.so:x11-toolkits/pango
.endif
.endif

pre-configure:
	@${AUTORECONF} -fi ${WRKSRC}

post-install:
	@${ECHO_MSG} ""
	@${ECHO_MSG} "${PREFIX}/sbin/mtr is setuid \"root\" "
	@${ECHO_MSG} ""
	@${ECHO_MSG} "Please read about potential security issues"
	@${ECHO_MSG} "in file ${WRKSRC}/SECURITY (not installed)"
	@${ECHO_MSG} ""

.include <bsd.port.mk>
