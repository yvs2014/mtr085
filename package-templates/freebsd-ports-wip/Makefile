
# sample: replace <GIT_COMMIT_NUMBER> and <GIT_COMMIT_HASH> with their actual values

PORTNAME=	mtr085
DISTVERSION=	<GIT_COMMIT_NUMBER>
CATEGORIES=	wip net

MAINTAINER=	e@mail
COMMENT=	Work-in-progress: mtr v0.85 fork for testing extra features
WWW=	https://github.com/traviscross/mtr https://github.com/${GH_ACCOUNT}/${GH_PROJECT}
LICENSE=	GPLv2

CONFLICTS_INSTALL?=	mtr mtr-nox11

USES+=	meson
USES+=	pkgconfig

USE_GITHUB=	yes
GH_PROJECT=	mtr085
GH_ACCOUNT=	yvs2014
GH_TAGNAME=	<GIT_COMMIT_HASH>

OPTIONS_DEFINE=	SETUID IPINFO IDN NLS UNICODE IPV6
OPTIONS_DEFAULT=	IPINFO IDN UNICODE IPV6
IPINFO_DESC=	Extended information like ASN, etc.
SETUID_DESC=	Install with setuid root
NLS_DESC=	NLS locale LC_MESSAGES

MESON_ARGS+=	-DCAP=false
MESON_ARGS+=	-DSBIN=true

SUB_FILES=	pkg-message
PLIST_FILES=	${DOCSDIR_REL}/SECURITY

post-install:
	@${MKDIR} ${STAGEDIR}${DOCSDIR}
	${INSTALL_DATA} ${WRKSRC}/SECURITY ${STAGEDIR}${DOCSDIR}/

.include <bsd.port.options.mk>

PLIST_FILES+=	share/man/man8/mtr.8.gz

.if ${PORT_OPTIONS:MSETUID}
PLIST_FILES+=	"@(,,4555) sbin/mtr"
.else
PLIST_FILES+=	sbin/mtr
.endif

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
LOCALE_REL=	share/locale
MOFILE=		LC_MESSAGES/${PORTNAME}.mo
PLIST_FILES+=	${LOCALE_REL}/es/${MOFILE}
PLIST_FILES+=	${LOCALE_REL}/it/${MOFILE}
PLIST_FILES+=	${LOCALE_REL}/pt/${MOFILE}
PLIST_FILES+=	${LOCALE_REL}/uk/${MOFILE}
.endif

.if empty(PORT_OPTIONS:MIPV6)
MESON_ARGS+=	-DIPV6=false
.endif

.include <bsd.port.mk>
