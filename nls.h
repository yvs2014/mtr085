#ifndef NLS_H
#define NLS_H

#ifdef USE_NLS
#include <libintl.h>
#define _(text) gettext(text)
#else
#define _(text) (text)
#endif

// TUI
#define OPTS_STR    _("Keys")
#define FIELDS_STR  _("Custom keys")
#define PACKETS_STR _("Packets")
#define PINGS_STR   _("Pings")

// stats
#define LOSS_STR    _("Loss")

// hints
#define ANYKEY_STR  _("Press any key to continue")

#endif
