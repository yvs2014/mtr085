# $NetBSD$

# sample: replace <GIT_COMMIT_NUMBER> and <GIT_COMMIT_HASH> with their actual values

CATEGORIES=	net
PKGBASE=	mtr085
PKGVERSION=	<GIT_COMMIT_NUMBER>
PKGREVISION=	1
DISTNAME=	${PKGBASE}-${PKGVERSION}

MASTER_SITES=	${MASTER_SITE_GITHUB:=yvs2014/}
GITHUB_TAG=	<GIT_COMMIT_HASH>

MAINTAINER=	pkgsrc-users@NetBSD.org
COMMENT=	Work-in-progress: mtr v0.85 fork for testing extra features
LICENSE=	gnu-gpl-v2
USE_LANGUAGES=	c

CONFLICTS=	mtr-[0-9]*

USE_TOOLS+=		pkg-config
INSTALLATION_DIRS=	${PKGMANDIR}/man8 sbin share/doc/mtr

MESON_ARGS+=	-DCAP=false
MESON_ARGS+=	-DSBIN=true

.include "options.mk"

## mtr085 is used for testing extra features only, see mtr SECURITY notes
#
#SPECIAL_PERMS=	sbin/mtr ${SETUID_ROOT_PERMS}

post-install:
	${INSTALL_DATA} ${WRKSRC}/SECURITY ${DESTDIR}${PREFIX}/share/doc/mtr

.include "../../devel/meson/build.mk"
.include "../../mk/curses.buildlink3.mk"
.include "../../mk/bsd.pkg.mk"
