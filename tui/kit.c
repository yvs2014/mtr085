// part of mtr085: menu kit

#include <string.h>
#include <ctype.h>

#if defined(LOG_TUI) && !defined(LOGMOD)
#include <errno.h>
#define LOGMOD
#endif
#if !defined(LOG_TUI) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "log.h"

#include "kit.h"
#include "aux.h"
#include "nls.h"
#include "net.h"

#ifndef NCURSES_VERSION
#error Non-ncurses menus are not supported yet
#endif

#define ROUNDED_CORNERS    true
#define ON_MOUSE_DBL_CLICK C_SPACE

#define LOGWINSIZE(name, kind, win) LOGMSG("menu %s, %s: x0=%d y0=%d w=%d h=%d", \
 (name), (kind), getbegx(win), getbegy(win), getmaxx(win), getmaxy(win))

int posted_form = -1;

typedef enum {
  MI_TOOGLE,
  MI_INTFORM,
  MI_STRFORM,
  MI_SUBMENU,
} mi_type;

typedef enum {
#ifdef ENABLE_DNS
  MENU_MAIN_DNS,
#endif
#ifdef WITH_IPINFO
  MENU_MAIN_ASN,
#endif
  MENU_MAIN_JITTER,
  MENU_MAIN_FIELDS,
#ifdef WITH_MPLS
  MENU_MAIN_MPLS,
#endif
  SUBMENU_CYCLES,
  MENU_MAIN_MINTTL,
  MENU_MAIN_MAXTTL,
  SUBMENU_BPATT,
  MENU_MAIN_TIMEI,
#ifdef ENABLE_QOS
  MENU_MAIN_QOS,
#endif
  MENU_MAIN_PSIZE,
  SUBMENU_XCACHE,
  MENU_MAIN_LEN
} mi_inst;

enum {
  SUBMENU_CYCLES_INF,
  SUBMENU_CYCLES_NUM,
  SUBMENU_CYCLES_LEN
};
enum {
  SUBMENU_BPATT_RND,
  SUBMENU_BPATT_NUM,
  SUBMENU_BPATT_LEN,
};
enum {
  SUBMENU_XCACHE_NOT,
  SUBMENU_XCACHE_NUM,
  SUBMENU_XCACHE_LEN,
};

typedef struct winpan_s {
  WINDOW *win;
  WINDOW *sub;
  PANEL  *pan;
} winpan_s;

typedef struct mi_s {
  FORM  *form;
  FIELD *field[2]; // NULL terminated
  winpan_s wsp;
  bool posted;
  struct kitmenu_s *sub;
} mi_s;

typedef struct attr_s {
  short bg;
  int x0, y0;
} attr_s;

typedef enum {
  KIT_MENU,
  KIT_SUBMENU,
} kit_type_inst;

typedef struct menuico_t {int len; char *on, *off;} menuico_t;
static const menuico_t a_toogle = {.len = 3, .on = "[*]", .off = "[ ]"};
#if defined(TUIWIDE) && defined(WITH_UNICODE)
static const menuico_t u_toogle =
  {.len = 1, .on = "✓"/*"✔"*//*"🗹 "*//*"☑"*/, .off = "◻"/*"☐"*/};
#endif
static const menuico_t a_menuexp = {.len = 3, .on = "  |", .off = "..."};
#if defined(TUIWIDE) && defined(WITH_UNICODE)
static const menuico_t u_menuexp = {.len = 1, .on = "◀"/*▼▾▶▷*/, .off = "…"/*▶*/};
#endif

typedef void (*mi_init_fn)(const menuico_t *toogle, const menuico_t *menuexp) NONNULL(1, 2);

typedef struct kitmenu_s {
  menu_ndx_t ndx;
  kit_type_inst type;
  //
  uint len;
  ITEM **items; // items[len]
  mi_s *mis;    // mis[len]
  mi_init_fn mi_init;
  //
  MENU *menu;
  winpan_s wsp;
  bool posted, active;
  attr_s attr;
  int frame;
  int maxnamelen; // in utf8 characters
  int spacing;
  const int pad;  // 1 for ' menu-item-text '
  const int desc_width;
  const char *log;
  int nth; // index in parent menu
} kitmenu_s;

static ITEM*   main_items[MENU_MAIN_LEN + 1];
static mi_s       main_mi[MENU_MAIN_LEN];
static ITEM* cycles_items[SUBMENU_CYCLES_LEN + 1];
static mi_s     cycles_mi[SUBMENU_CYCLES_LEN];
static ITEM*  bpatt_items[SUBMENU_BPATT_LEN + 1];
static mi_s      bpatt_mi[SUBMENU_BPATT_LEN];
static ITEM* xcache_items[SUBMENU_XCACHE_LEN + 1];
static mi_s     xcache_mi[SUBMENU_XCACHE_LEN];

static void init_mi_bpatt (const menuico_t *toogle, const menuico_t *menuexp) NONNULL(1, 2);
static void init_mi_cycles(const menuico_t *toogle, const menuico_t *menuexp) NONNULL(1, 2);
static void init_mi_xcache(const menuico_t *toogle, const menuico_t *menuexp) NONNULL(1, 2);
static void init_mi_main  (const menuico_t *toogle, const menuico_t *menuexp) NONNULL(1, 2);

#define NAMEDESC_SPACING    1
#define BORDER_PAD          1
#define MAINMENU_DSC_WIDTH 10 /*looks enough*/
#define SUBMENU_DSC_WIDTH   5
static kitmenu_s kitmenu[] = {
  [KITMENU_MAIN]   = {.ndx = KITMENU_MAIN,   .type = KIT_MENU,    .log = "main",
    .len = MENU_MAIN_LEN,      .items = main_items,   .mis = main_mi,
    .spacing = NAMEDESC_SPACING, .pad = BORDER_PAD, .desc_width = MAINMENU_DSC_WIDTH,
    .mi_init = init_mi_main},
  [KITMENU_CYCLES] = {.ndx = KITMENU_CYCLES, .type = KIT_SUBMENU, .log = "cycles",
    .len = SUBMENU_CYCLES_LEN, .items = cycles_items, .mis = cycles_mi, .nth = SUBMENU_CYCLES,
    .spacing = NAMEDESC_SPACING, .pad = BORDER_PAD, .desc_width = SUBMENU_DSC_WIDTH,
    .mi_init = init_mi_cycles},
  [KITMENU_BPATT]  = {.ndx = KITMENU_BPATT,  .type = KIT_SUBMENU, .log = "bit-pattern",
    .len = SUBMENU_BPATT_LEN,  .items = bpatt_items,  .mis = bpatt_mi,  .nth = SUBMENU_BPATT,
    .spacing = NAMEDESC_SPACING, .pad = BORDER_PAD, .desc_width = SUBMENU_DSC_WIDTH,
    .mi_init = init_mi_bpatt},
  [KITMENU_XCACHE] = {.ndx = KITMENU_XCACHE, .type = KIT_SUBMENU, .log = "xcache",
    .len = SUBMENU_XCACHE_LEN, .items = xcache_items, .mis = xcache_mi, .nth = SUBMENU_XCACHE,
    .spacing = NAMEDESC_SPACING, .pad = BORDER_PAD, .desc_width = SUBMENU_DSC_WIDTH,
    .mi_init = init_mi_xcache},
};

#define LOGFNFAIL(title, fn)     LOGMSG("%s: %s() failed", (title), (fn))
#define LOGECFAIL(title, fn, ec) LOGMSG("%s: %s() failed: %d/%d", \
  (title), (fn), (ec), ((ec) == E_SYSTEM_ERROR) ? errno : 0)

#if defined(TUIWIDE) && defined (WITH_UNICODE)
#define MENUSTRW(str) utf_compat ? _(str) : (str)
#else
#define MENUSTRW(str) (str)
#endif

#define MI_DEF_FMT " %s"
#define MI_PAD_FMT "%*s"
#define MI_STR_FMT     MI_DEF_FMT " [%s]"
#define MI_MINMAX_FMT  MI_DEF_FMT " [%d..%d]"
#define MI_MININF_FMT  MI_DEF_FMT " [%d...]"
#define MI_MINMAX_UFMT MI_DEF_FMT " [%d … %d]"
#define MI_MININF_UFMT MI_DEF_FMT " [%d … ꝏ ]" /*∞*/

typedef struct menuitem_s {
  const mi_type type;
  const uint8_t ndx;
  char name[NAMELEN];
  char desc[NAMELEN];
  const key_action_t action;
  const struct {
    const bool  *flag;
    const char **pstr;
    int *num;
  } val;
  const int min, max, *pmin, *pmax;
  const char *patt;
  void (*setter)(const char *str);
  //
  kitmenu_s *submenu;
} menuitem_s;

typedef struct optname_s {
  int len; // name length in unicode characters
  const char* const name;
} optname_s;

//

static attr_s common_attr;

static struct subopts {
  char fields[20]; // enough for stat keys [stat_max]
  bool cycles_inf;
  int  cycles_val;
  bool xcache_nop;
  int  xcache_val;
  bool  bpatt_rnd;
  int   bpatt_val;
} subopts;

#define MI_NDX(menu_ndx, item_ndx) (((menu_ndx) << 8) | ((item_ndx) & 0xFF))
static void menu_posteditaction(int type, int opt) {
  switch MI_NDX(type, opt) {
    case MI_NDX(KITMENU_MAIN, MENU_MAIN_MINTTL):
      OPT_SUM(minttl);   break;
    case MI_NDX(KITMENU_MAIN, MENU_MAIN_MAXTTL):
      OPT_SUM(maxttl);   break;
    case MI_NDX(KITMENU_MAIN, MENU_MAIN_TIMEI):
      OPT_SUM(interval); break;
#ifdef ENABLE_QOS
    case MI_NDX(KITMENU_MAIN, MENU_MAIN_QOS):
      net_set_qos();
      OPT_SUM(qos);      break;
#endif
    case MI_NDX(KITMENU_MAIN, MENU_MAIN_PSIZE):
      OPT_SUM(size);     break;
    case MI_NDX(KITMENU_CYCLES, SUBMENU_CYCLES_INF):
    case MI_NDX(KITMENU_CYCLES, SUBMENU_CYCLES_NUM):
      OPT_SUM(cycles);   break;
    case MI_NDX(KITMENU_BPATT,  SUBMENU_BPATT_RND):
    case MI_NDX(KITMENU_BPATT,  SUBMENU_BPATT_NUM):
      reset_pattern = true;
      OPT_SUM(pattern);  break;
    case MI_NDX(KITMENU_XCACHE, SUBMENU_XCACHE_NOT):
    case MI_NDX(KITMENU_XCACHE, SUBMENU_XCACHE_NUM):
      OPT_SUM(cache);    break;
    default: break;
  }
}

static void mi_selectabale(int type, int opt, ITEM *item) NONNULL(3);
static void mi_selectabale(int type, int opt, ITEM *item) {
  bool dim = false;
  switch MI_NDX(type, opt) {
#if defined(ENABLE_QOS) && (!defined(ENABLE_QOS4) || !defined(ENABLE_QOS6))
    case MI_NDX(KITMENU_MAIN, MENU_MAIN_QOS):
#if   !defined(ENABLE_QOS4)
      dim = (af == AF_INET);
#elif !defined(ENABLE_QOS6)
      dim = (af == AF_INET6);
#endif
      break;
#endif
    case MI_NDX(KITMENU_CYCLES, SUBMENU_CYCLES_NUM):
      dim = (run_opts.cycles <= 0);
      break;
    case MI_NDX(KITMENU_BPATT,  SUBMENU_BPATT_NUM):
      dim = (run_opts.pattern < 0);
      break;
    case MI_NDX(KITMENU_XCACHE, SUBMENU_XCACHE_NUM):
      dim = (run_opts.cache  <= 0);
      break;
    default: break;
  }
  if (dim)
    item_opts_off(item, O_SELECTABLE);
}

static int fill_itemname(const menuitem_s *mi, const char *name,
  uint size, char buff[size], int pad) NONNULL(1, 2, 4);
static int fill_itemname(const menuitem_s *mi, const char *name,
  uint size, char buff[size], int pad)
{
  buff[0] = 0;
  int rc = 0;
  switch (mi->type) {
    case MI_SUBMENU:
    case MI_TOOGLE:
      rc = (pad > 0) ?
        snprinte(buff, size, MI_DEF_FMT "%*s", name, pad, "") :
        snprinte(buff, size, MI_DEF_FMT,       name);
      break;
    case MI_INTFORM: {
      int min = mi->pmin ? *mi->pmin : mi->min;
      int max = mi->pmax ? *mi->pmax : mi->max;
      const char *minmax_fmt =
#if defined(TUIWIDE) && defined(WITH_UNICODE)
        utf_compat ?
          ((pad > 0) ? MI_MINMAX_UFMT MI_PAD_FMT : MI_MINMAX_UFMT):
#endif
          ((pad > 0) ? MI_MINMAX_FMT  MI_PAD_FMT : MI_MINMAX_FMT );
      const char *mininf_fmt =
#if defined(TUIWIDE) && defined(WITH_UNICODE)
        utf_compat ?
          ((pad > 0) ? MI_MININF_UFMT MI_PAD_FMT : MI_MININF_UFMT):
#endif
          ((pad > 0) ? MI_MININF_FMT  MI_PAD_FMT : MI_MININF_FMT );
      rc = (pad > 0) ?
        (    (max < INT_MAX) ?
          snprinte(buff, size, minmax_fmt, name, min, max, pad, "") :
          snprinte(buff, size, mininf_fmt, name, min,      pad, "")
        ) : ((max < INT_MAX) ?
          snprinte(buff, size, minmax_fmt, name, min, max) :
          snprinte(buff, size, mininf_fmt, name, min));
    } break;
    case MI_STRFORM: {
      const char *patt = mi->patt ? mi->patt : "";
      rc = (pad > 0) ?
        snprinte(buff, size, MI_STR_FMT "%*s", name, patt, pad, "") :
        snprinte(buff, size, MI_STR_FMT,       name, patt);
    } break;
    default:
      LOGMSG("unknwon menuitem type: %d", mi->type);
      break;
  }
  return rc;
}

static int fill_itemdesc(const kitmenu_s *kit, menuitem_s *mitem,
  const menuico_t *toogle, const menuico_t *menuexp) NONNULL(1, 2, 3, 4);
static int fill_itemdesc(const kitmenu_s *kit, menuitem_s *mitem,
  const menuico_t *toogle, const menuico_t *menuexp)
{
  int rc = 0;
  switch (mitem->type) {
    case MI_TOOGLE: {
      const bool *flag = mitem->val.flag;
      if (flag) {
        const char *icon = *flag ? toogle->on : toogle->off;
        int blank = (kit->desc_width > 0) ? (kit->desc_width - toogle->len) : 0;
        rc = (blank > 0) ? // utf8-compat padding
          snprinte(mitem->desc, sizeof(mitem->desc), "%*s%s ", blank, "", icon) :
          snprinte(mitem->desc, sizeof(mitem->desc), "%s ", icon);
      }
    } break;
    case MI_INTFORM: {
      int *num = mitem->val.num;
      if (num) {
        rc = (kit->desc_width > 0) ?
          snprinte(mitem->desc, sizeof(mitem->desc), "%*d ", kit->desc_width, *num) :
          snprinte(mitem->desc, sizeof(mitem->desc), "%d ", *num);
      }
    }  break;
    case MI_STRFORM: {
      const char *str = mitem->val.pstr ? *mitem->val.pstr : NULL;
      if (str) {
        rc = (kit->desc_width > 0) ?
          snprinte(mitem->desc, sizeof(mitem->desc), "%*s ", kit->desc_width, str) :
          snprinte(mitem->desc, sizeof(mitem->desc), "%s ", str);
      }
    }  break;
    case MI_SUBMENU: {
      const bool *flag = mitem->val.flag;
      const char *icon = (flag && *flag) ? menuexp->on : menuexp->off;
      int blank = (kit->desc_width > 0) ? (kit->desc_width - menuexp->len) : 0;
      rc = (blank > 0) ? // utf8-compat padding
        snprinte(mitem->desc, sizeof(mitem->desc), "%*s%s ", blank, "", icon) :
        snprinte(mitem->desc, sizeof(mitem->desc), "%s ", icon);
    }  break;
    default:
      LOGMSG("menu %s: unknown menuitem type: %d", kit->log, mitem->type);
      break;
  }
  return rc;
}

static int calc_maxnamelen(uint len,
  const menuitem_s mi[len], optname_s opt[len]) NONNULL(2, 3);
static int calc_maxnamelen(uint len,
  const menuitem_s mi[len], optname_s opt[len])
{
  char buff[NAMELEN] = {0};
  int maxlen = 0;
  for (uint i = 0; (i < len) && opt->name; i++, opt++, mi++) {
    int rc = fill_itemname(mi, opt->name, sizeof(buff), buff, 0);
    if (rc > 0) {
      int len = ustrnlen(buff, NAMELEN);
      if (len > 0) {
        opt->len = len;
        if (len > maxlen)
          maxlen = len;
      }
    }
  }
  LOGMSG("maxnamelen=%d", maxlen);
  return maxlen;
}

static void set_stat_keys(uint len, char buff[len]) NONNULL(2);
static void set_stat_keys(uint len, char buff[len]) {
  for (uint i = 0; i < len; i++)
    buff[i] = ((int)i < stat_max) ? stats[i].key : 0;
}

static void init_kititems(kitmenu_s *kit,
  uint mlen, menuitem_s mi[mlen], optname_s opt[mlen],
  const menuico_t *toogle, const menuico_t *menuexp)
  NONNULL(1, 3, 4, 5, 6);
static void init_kititems(kitmenu_s *kit,
  uint mlen, menuitem_s mi[mlen], optname_s opt[mlen],
  const menuico_t *toogle, const menuico_t *menuexp)
{
  if (!kit->maxnamelen)
    kit->maxnamelen  = calc_maxnamelen(mlen, mi, opt);
  //
  if (kit->items[0]) {
    // disconnect and free previous menuitems
    // menu has to be unposted
    int ec = set_menu_items(kit->menu, NULL);
    if (ec == E_OK) {
      for (uint i = 0; i < kit->len; i++) {
        if (kit->items[i]) {
          int ec = free_item(kit->items[i]);
          if (ec != E_OK)
            LOGECFAIL(kit->log, "free_item", ec);
          kit->items[i] = NULL;
        }
      }
    } else
      LOGECFAIL(kit->log, "set_menu_items", ec);
  }
  //
  for (uint i = 0; (i < mlen) && opt->name; i++, opt++, mi++) {
    int pad = // utf8-compat padding
      (opt->len > 0) ? (kit->maxnamelen - opt->len) : 0;
    const char *name =
      (fill_itemname(mi, opt->name, sizeof(mi->name), mi->name, pad) > 0) && mi->name[0]
      ? mi->name : opt->name;
    const char *desc =
      (fill_itemdesc(kit, mi, toogle, menuexp) > 0) && mi->desc[0]
      ? mi->desc : NULL;
    ITEM *item = new_item(name, desc);
    if (item) {
      LOGMSG("menu %s, item[%u]: \"%s\"=\"%s\"", kit->log, i, item_name(item), item_description(item));
      set_item_userptr(item, mi);
      kit->items[i] = item;
      mi_selectabale(kit->ndx, i, item);
    } else {
      LOGMSG("menu %s, new_item(#%u, %s) failed: %d", kit->log, i, opt->name, errno);
      break;
    }
  }
}

static void submenu_attr(attr_s *attr, int nth, kitmenu_s *main) NONNULL(1, 3);
static void submenu_attr(attr_s *attr, int nth, kitmenu_s *main) {
  attr->y0 += nth;
  attr->x0 += main->maxnamelen;
  attr->x0 += main->spacing - 1;
  attr->x0 += main->desc_width;
  attr->x0 += (main->frame + main->pad) * 2;
}

static void set_menus_attr(void) {
  LOGMSG("common: bg=%d x0=%d y0=%d", common_attr.bg, common_attr.x0, common_attr.bg);
  kitmenu_s *kit = kitmenu, *main = &kitmenu[KITMENU_MAIN];
  for (uint i = 0; i < ARRAY_LEN(kitmenu); i++, kit++) if (kit) {
    kit->attr = common_attr;
    if (kit->type == KIT_SUBMENU)
      submenu_attr(&kit->attr, kit->nth, main);
  }
}

static void init_mi_cycles(const menuico_t *toogle, const menuico_t *menuexp) { // NONNULL(1, 2)
  static menuitem_s mi_cycles[] = {
    [SUBMENU_CYCLES_INF] = {.ndx = SUBMENU_CYCLES_INF, .type = MI_TOOGLE,
      .action = ActionMenuCyclesUnlim, .val.flag = &subopts.cycles_inf},
    [SUBMENU_CYCLES_NUM] = {.ndx = SUBMENU_CYCLES_NUM, .type = MI_INTFORM,
      .action = ActionNone,            .val.num  = &run_opts.cycles,
      .min = 1, .max = INT_MAX},
  };
  optname_s opt_cycles[ARRAY_LEN(mi_cycles)] = {
    [SUBMENU_CYCLES_INF] = {.name = MENUSTRW(_UNLIM_STR)},
    [SUBMENU_CYCLES_NUM] = {.name = MENUSTRW(_NCYCLES_STR)},
  };
  init_kititems(&kitmenu[KITMENU_CYCLES], ARRAY_LEN(mi_cycles), mi_cycles, opt_cycles, toogle, menuexp);
}

static void init_mi_bpatt(const menuico_t *toogle, const menuico_t *menuexp) { // NONNULL(1, 2)
  static menuitem_s mi_bpatt[] = {
    [SUBMENU_BPATT_RND] = {.ndx = SUBMENU_BPATT_RND, .type = MI_TOOGLE,
      .action = ActionMenuPattRnd, .val.flag = &subopts.bpatt_rnd},
    [SUBMENU_BPATT_NUM] = {.ndx = SUBMENU_BPATT_NUM, .type = MI_INTFORM,
      .action = ActionNone,        .val.num  = &run_opts.pattern,
      .min = 0, .max = UINT8_MAX},
  };
  optname_s opt_bpatt[ARRAY_LEN(mi_bpatt)] = {
    [SUBMENU_BPATT_RND] = {.name = MENUSTRW(_RANDOM_STR)},
    [SUBMENU_BPATT_NUM] = {.name = MENUSTRW(_BITPATT_STR)},
  };
  init_kititems(&kitmenu[KITMENU_BPATT], ARRAY_LEN(mi_bpatt), mi_bpatt, opt_bpatt, toogle, menuexp);
}

static void init_mi_xcache(const menuico_t *toogle, const menuico_t *menuexp) { // NONNULL(1, 2)
  static menuitem_s mi_xcache[] = {
    [SUBMENU_XCACHE_NOT] = {.ndx = SUBMENU_XCACHE_NOT, .type = MI_TOOGLE,
      .action = ActionMenuNoCache, .val.flag = &subopts.xcache_nop},
    [SUBMENU_XCACHE_NUM] = {.ndx = SUBMENU_XCACHE_NUM, .type = MI_INTFORM,
      .action = ActionNone,        .val.num  = &run_opts.cache,
      .min = 1, .max = INT_MAX},
  };
  optname_s opt_xcache[ARRAY_LEN(mi_xcache)] = {
    [SUBMENU_XCACHE_NOT] = {.name = MENUSTRW(_NOCACHE_STR)},
    [SUBMENU_XCACHE_NUM] = {.name = MENUSTRW(_CACHETM_STR)},
  };
  init_kititems(&kitmenu[KITMENU_XCACHE], ARRAY_LEN(mi_xcache), mi_xcache, opt_xcache, toogle, menuexp);
}

#define PSIZEMM (MAXPACKET - MINPACKET)
static void init_mi_main(const menuico_t *toogle, const menuico_t *menuexp) { // NONNULL(1, 2)
  static menuitem_s mi_main[] = {
#ifdef ENABLE_DNS
    [MENU_MAIN_DNS]      = {.ndx = MENU_MAIN_DNS,     .type = MI_TOOGLE,
      .action = ActionDNS,   .val.flag = &run_opts.dns},
#endif
#ifdef WITH_IPINFO
    [MENU_MAIN_ASN]      = {.ndx = MENU_MAIN_ASN,     .type = MI_TOOGLE,
      .action = ActionASN,   .val.flag = &run_opts.asn},
#endif
    [MENU_MAIN_JITTER]   = {.ndx = MENU_MAIN_JITTER,  .type = MI_TOOGLE,
      .action = ActionJttr,  .val.flag = &run_opts.jitter},
    [MENU_MAIN_FIELDS]   = {.ndx = MENU_MAIN_FIELDS,  .type = MI_STRFORM,
      .action = ActionNone,  .val.pstr = &fld_active, .setter = set_fld_active,
      .patt = subopts.fields},
#ifdef WITH_MPLS
    [MENU_MAIN_MPLS]     = {.ndx = MENU_MAIN_MPLS,    .type = MI_TOOGLE,
      .action = ActionMPLS,  .val.flag = &run_opts.mpls},
#endif
    [SUBMENU_CYCLES]     = {.ndx = SUBMENU_CYCLES,    .type = MI_SUBMENU,
      .action = ActionNone,  .val.flag = &kitmenu[KITMENU_CYCLES].active,
      .submenu = &kitmenu[KITMENU_CYCLES]},
    [MENU_MAIN_MINTTL]   = {.ndx = MENU_MAIN_MINTTL,  .type = MI_INTFORM,
      .action = ActionNone,  .val.num  = &run_opts.minttl,
      .min =  1, .max = MAXHOST, .pmax = &run_opts.maxttl},
    [MENU_MAIN_MAXTTL]   = {.ndx = MENU_MAIN_MAXTTL,  .type = MI_INTFORM,
      .action = ActionNone,  .val.num  = &run_opts.maxttl,
      .min =  1, .max = MAXHOST, .pmin = &run_opts.minttl},
    [SUBMENU_BPATT]      = {.ndx = SUBMENU_BPATT,     .type = MI_SUBMENU,
      .action = ActionNone,  .val.flag = &kitmenu[KITMENU_BPATT].active,
      .submenu = &kitmenu[KITMENU_BPATT]},
    [MENU_MAIN_TIMEI]    = {.ndx = MENU_MAIN_TIMEI,   .type = MI_INTFORM,
      .action = ActionNone,  .val.num  = &run_opts.interval,
      .min =  1, .max = INT_MAX},
#ifdef ENABLE_QOS
    [MENU_MAIN_QOS]      = {.ndx = MENU_MAIN_QOS,     .type = MI_INTFORM,
      .action = ActionNone,  .val.num  = &run_opts.qos,
      .min =  0, .max = UINT8_MAX},
#endif
    [MENU_MAIN_PSIZE]    = {.ndx = MENU_MAIN_PSIZE,   .type = MI_INTFORM,
      .action = ActionNone,  .val.num  = &run_opts.size,
      .min = -PSIZEMM, .max = PSIZEMM},
    [SUBMENU_XCACHE]     = {.ndx = SUBMENU_XCACHE,    .type = MI_SUBMENU,
      .action = ActionNone,  .val.flag = &kitmenu[KITMENU_XCACHE].active,
      .submenu = &kitmenu[KITMENU_XCACHE]},
  };
  //
  optname_s opt_main[ARRAY_LEN(mi_main)] = {
#ifdef ENABLE_DNS
    [MENU_MAIN_DNS]     = {.name = MENUSTRW(_DNS_STR)},
#endif
#ifdef WITH_IPINFO
    [MENU_MAIN_ASN]     = {.name = MENUSTRW(_ASN_STR)},
#endif
    [MENU_MAIN_JITTER]  = {.name = MENUSTRW(_JITTER_STR)},
    [MENU_MAIN_FIELDS]  = {.name = MENUSTRW(_FIELDS_STR)},
#ifdef WITH_MPLS
    [MENU_MAIN_MPLS]    = {.name = MENUSTRW(_MPLS_STR)},
#endif
    [SUBMENU_CYCLES]    = {.name = MENUSTRW(_NCYCLES_STR)},
    [MENU_MAIN_MINTTL]  = {.name = MENUSTRW(_MINTTL_STR)},
    [MENU_MAIN_MAXTTL]  = {.name = MENUSTRW(_MAXTTL_STR)},
    [SUBMENU_BPATT]     = {.name = MENUSTRW(_BITPATT_STR)},
    [MENU_MAIN_TIMEI]   = {.name = MENUSTRW(_GAPINSEC_STR)},
#ifdef ENABLE_QOS
    [MENU_MAIN_QOS]     = {.name = MENUSTRW(_QOSTOS_STR)},
#endif
    [MENU_MAIN_PSIZE]   = {.name = MENUSTRW(_PSIZE_STR)},
    [SUBMENU_XCACHE]    = {.name = MENUSTRW(_CACHETM_STR)},
  };
  //
  init_kititems(&kitmenu[KITMENU_MAIN], ARRAY_LEN(mi_main), mi_main, opt_main, toogle, menuexp);
}

static const menuico_t *toogle  = &a_toogle;
static const menuico_t *menuexp = &a_menuexp;

static void set_item_icons(void) {
  toogle =
#if defined(TUIWIDE) && defined(WITH_UNICODE)
    utf_compat ? &u_toogle :
#endif
    &a_toogle;
  menuexp =
#if defined(TUIWIDE) && defined(WITH_UNICODE)
    utf_compat ? &u_menuexp :
#endif
    &a_menuexp;
}

static inline bool is_value_cycles(void) { return run_opts.cycles  >  0; }
static inline bool is_value_bpatt (void) { return run_opts.pattern >= 0; }
static inline bool is_value_xcache(void) { return run_opts.cache   >  0; }

static void set_subopt_values(void) {
  subopts.cycles_val = is_value_cycles() ? run_opts.cycles  : REPORT_PINGS;
  subopts.cycles_inf = !is_value_cycles();
  //
  subopts.bpatt_val  = is_value_bpatt()  ? run_opts.pattern : BITPATTERN;
  subopts.bpatt_rnd  = !is_value_bpatt();
  //
  subopts.xcache_val = is_value_xcache() ? run_opts.cache   : CACHE_TIMEOUT;
  subopts.xcache_nop = !is_value_xcache();
  //
  set_stat_keys(ARRAY_LEN(subopts.fields) - 1, subopts.fields);
}

static void init_all_menuitems(void) { // supposed to call once
  set_subopt_values();
  set_item_icons();
  init_mi_cycles(toogle, menuexp);
  init_mi_bpatt (toogle, menuexp);
  init_mi_xcache(toogle, menuexp);
  init_mi_main  (toogle, menuexp);
  set_menus_attr();
}

static void prepare_menu_kit(kitmenu_s *kit) NONNULL(1);
static void prepare_menu_kit(kitmenu_s *kit) {
  if (!kit->menu) {
    kit->menu = new_menu(kit->items);
    if (!kit->menu) {
      LOGECFAIL(kit->log, "new_menu", errno);
      return;
    }
    { int ec = set_menu_mark(kit->menu, NULL);
      if (ec != E_OK)
        LOGFNFAIL(kit->log, "set_menu_mark"); }
    if (kit->attr.bg > 0) {
      int ec = set_menu_back(kit->menu, COLOR_PAIR(kit->attr.bg));
      if (ec != E_OK)
        LOGECFAIL(kit->log, "set_menu_back", ec);
    }
    { int ec = set_menu_grey(kit->menu, COLOR_PAIR(kit->attr.bg > 0 ? kit->attr.bg : 0) | A_DIM);
      if (ec != E_OK)
        LOGECFAIL(kit->log, "set_menu_grey", ec); }
  }
#ifdef HAVE_MENU_SPACING
  menu_spacing(kit->menu, &kit->spacing, NULL, NULL);
#endif
  kit->frame =
#ifdef WITH_UNICODE
    utf_compat ? 1 :
#endif
  0;
  LOGMSG("menu %s: frame=%d spacing=%d", kit->log, kit->frame, kit->spacing);
  int h = kit->len, w = (kit->maxnamelen > 0) ? kit->maxnamelen : 16;
  w += kit->spacing;
  w += kit->desc_width;
  w++;
  if (!kit->wsp.win) {
    kit->wsp.win = newwin(h + 2 * kit->frame, w + 2 * kit->frame, kit->attr.y0, kit->attr.x0);
    if (!kit->wsp.win) {
      LOGFNFAIL(kit->log, "newwin");
      return;
    }
    keypad(kit->wsp.win, TRUE);
    if (kit->attr.bg > 0)
      wbkgd(kit->wsp.win, COLOR_PAIR(kit->attr.bg));
    if (kit->frame) {
#ifdef ROUNDED_CORNERS
      cchar_t tl = {0}, tr = {0}, bl = {0}, br = {0};
      setcchar(&tl, L"╭", A_NORMAL, 0, NULL);
      setcchar(&tr, L"╮", A_NORMAL, 0, NULL);
      setcchar(&bl, L"╰", A_NORMAL, 0, NULL);
      setcchar(&br, L"╯", A_NORMAL, 0, NULL);
      wborder_set(kit->wsp.win, NULL, NULL, NULL, NULL, &tl, &tr, &bl, &br);
#else
      box(menuwin, 0, 0);
#endif
    }
    LOGWINSIZE(kit->log, "base", kit->wsp.win);
  }
  if (!kit->wsp.sub) {
    kit->wsp.sub = derwin(kit->wsp.win, h, w, kit->frame, kit->frame);
    if (!kit->wsp.sub) {
      LOGFNFAIL(kit->log, "derwin");
      return;
    }
    LOGWINSIZE(kit->log, "derived", kit->wsp.sub);
  }
  //
  if (menu_win(kit->menu) != kit->wsp.win) {
    int ec = set_menu_win(kit->menu, kit->wsp.win);
    if (ec != E_OK) {
      LOGECFAIL(kit->log, "set_menu_win", ec);
      free_menu(kit->menu);
      kit->menu = NULL;
      return;
    }
  }
  if (menu_sub(kit->menu) != kit->wsp.sub) {
    int ec = set_menu_sub(kit->menu, kit->wsp.sub);
    if (ec != E_OK) {
      LOGECFAIL(kit->log, "set_menu_sub", ec);
      free_menu(kit->menu);
      kit->menu = NULL;
      return;
    }
  }
  //
  if (!kit->wsp.pan) {
    kit->wsp.pan = new_panel(kit->wsp.win);
    if (!kit->wsp.pan) {
      LOGFNFAIL(kit->log, "new_panel");
      return;
    }
  }
  //
  if (!kit->posted)
    kit->posted = (post_menu(kit->menu) == E_OK);
  hide_panel(kit->wsp.pan);
  bottom_panel(kit->wsp.pan);
}

static void prepare_menus(void) {
  if (!kitmenu[KITMENU_MAIN].items[0]) {
    init_all_menuitems();
    if (!kitmenu[KITMENU_MAIN].items[0])
      LOGMSG("%s", "no items");
  }
  for (uint i = 0; i < ARRAY_LEN(kitmenu); i++)
    prepare_menu_kit(&kitmenu[i]);
}

static void menu_hide(kitmenu_s *kit) NONNULL(1);
static void menu_hide(kitmenu_s *kit) {
  LOGMSG("menu %s", kit->log);
  hide_panel(kit->wsp.pan);
  bottom_panel(kit->wsp.pan);
  update_panels();
  doupdate();
  kit->active = false;
}

static void menu_show(kitmenu_s *kit) NONNULL(1);
static void menu_show(kitmenu_s *kit) {
  LOGMSG("menu %s", kit->log);
  top_panel(kit->wsp.pan);
  show_panel(kit->wsp.pan);
  update_panels();
  doupdate();
  kit->active = true;
}

static void position_inside_menu(kitmenu_s *kit, int was) NONNULL(1);
static void position_inside_menu(kitmenu_s *kit, int was) {
  int count = (kit->menu && (was >= 0)) ? item_count(kit->menu) : -1;
  if (count > 0) {
    ITEM **list = menu_items(kit->menu);
    if (list) for (int i = 0; i < count; i++) {
      ITEM *item = list[i];
      int now = item ? item_index(item) : -1;
      if (now == was) {
        set_current_item(kit->menu, item);
        LOGMSG("menu %s: %d", kit->log, now);
        return;
      }
    }
  }
  LOGMSG("menu %s: %s", kit->log, "state isn't restored");
}

static void set_field_num(FIELD *field, int num, int width) NONNULL(1);
static void set_field_num(FIELD *field, int num, int width) {
  char buff[width + 1];
  memset(buff, 0, sizeof(buff));
  int rc = snprinte(buff, sizeof(buff), "%d", num);
  if (rc > 0) {
    int ec = set_field_buffer(field, 0, buff);
    if (ec != E_OK)
      LOGECFAIL("num", "set_field_buffer", ec);
  }
}

static void set_field_str(FIELD *field, const char *str, int width) NONNULL(1);
static void set_field_str(FIELD *field, const char *str, int width) {
  char buff[width + 1];
  memset(buff, 0, sizeof(buff));
  int rc = snprinte(buff, sizeof(buff), "%s", str ? str : "");
  if (rc > 0) {
    int ec = set_field_buffer(field, 0, buff);
    if (ec != E_OK)
      LOGECFAIL("str", "set_field_buffer", ec);
  }
}

static void prepare_form(kitmenu_s *kit, int ndx, menuitem_s *data) NONNULL(1, 3);
static void prepare_form(kitmenu_s *kit, int ndx, menuitem_s *data) {
  // menuitem types: INTFORM, STRFORM
  if ((ndx < 0) || (ndx >= (int)kit->len)) {
    LOGMSG("wrong index: %d", ndx);
    return;
  }
  int desc_x0 = kit->maxnamelen + kit->spacing;
  LOGMSG("menu %s: index=%d desc-offset=%d", kit->log, ndx, desc_x0);
  int x0 = getbegx(kit->wsp.sub) + desc_x0;
  int y0 = getbegy(kit->wsp.sub) + ndx;
  int w  = getmaxx(kit->wsp.sub) - (desc_x0 + 1);
  int h  = 1;
  //
  FIELD *field = kit->mis[ndx].field[0];
  if (!field) {
    field = new_field(h, w, 0, 0, 0, 0);
    if (!field) {
      LOGECFAIL(kit->log, "new_field", errno);
      return;
    }
    set_field_back(field, A_UNDERLINE);
    field_opts_off(field, O_AUTOSKIP);
    kit->mis[ndx].field[0] = field;
  }
  switch (data->type) {
    case MI_INTFORM:
      if (data->val.num)
        set_field_num(field, *data->val.num,  w);
      break;
    case MI_STRFORM:
      if (data->val.pstr)
        set_field_str(field, *data->val.pstr, w);
      break;
    default:
      set_field_str(field, "", w);
      break;
  }
  //
  FORM *form = kit->mis[ndx].form;
  if (!form) {
    form = new_form(kit->mis[ndx].field);
    if (!form) {
      LOGECFAIL(kit->log, "new_form", errno);
      return;
    }
    kit->mis[ndx].form = form;
  }
  WINDOW *win = kit->mis[ndx].wsp.win;
  if (!win) {
    win = newwin(h, w, y0, x0);
    if (!win) {
      LOGFNFAIL(kit->log, "newwin");
      return;
    }
    keypad(win, TRUE);
    kit->mis[ndx].wsp.win = win;
  }
  WINDOW *sub = kit->mis[ndx].wsp.sub;
  if (!sub) {
    sub = derwin(win, h, w, 0, 0);
    if (!sub) {
      LOGFNFAIL(kit->log, "derwin");
      return;
    }
    kit->mis[ndx].wsp.sub = sub;
  }
  //
  if (form_win(form) != win) {
    int ec = set_form_win(form, win);
    if (ec != E_OK) {
      LOGECFAIL(kit->log, "set_form_win", ec);
      free_form(form);
      kit->mis[ndx].form = NULL;
      return;
    }
  }
  if (form_sub(form) != sub) {
    int ec = set_form_sub(form, sub);
    if (ec != E_OK) {
      LOGECFAIL(kit->log, "set_form_sub", ec);
      free_form(form);
      kit->mis[ndx].form = NULL;
      return;
    }
  }
  //
  PANEL *pan = kit->mis[ndx].wsp.pan;
  if (!pan) {
    pan = new_panel(win);
    if (!pan) {
      LOGFNFAIL(kit->log, "new_panel");
      return;
    }
    kit->mis[ndx].wsp.pan = pan;
  }
}

static void close_form(mi_s *mi) NONNULL(1);
static void close_form(mi_s *mi) {
  bottom_panel(mi->wsp.pan);
  unpost_form(mi->form);
  mi->posted = false;
  posted_form = -1;
  LOGMSG("%s", "done");
}

static void activate_form(kitmenu_s *kit, ITEM *item, menuitem_s *data) NONNULL(1, 2, 3);
static void activate_form(kitmenu_s *kit, ITEM *item, menuitem_s *data) {
  // menuitem types: INTFORM, STRFORM
  int ndx = item_index(item);
  if ((ndx < 0) || (ndx >= (int)kit->len)) {
    LOGMSG("menu %s: %s", kit->log, "no item/data");
    return;
  }
  mi_s *curr = &kit->mis[ndx];
  if (!curr->form || !curr->field[0]) {
    prepare_form(kit, ndx, data);
    if (!curr->form || !curr->field[0])
      return;
  }
  LOGMSG("< menu=%s form[%d] posted=%d", kit->log, ndx, curr->posted);
  // unpost all other menuitem forms if there are posted ones
  { mi_s *mi = kit->mis;
    for (int i = 0; i < (int)kit->len; i++, mi++)
      if (mi->posted && (i != ndx)) {
        bottom_panel(mi->wsp.pan);
        unpost_form(mi->form);
        mi->posted = false;
      }
    posted_form = -1;
  }
  //
  curr->posted = !curr->posted;
  if (curr->posted) {
    top_panel(curr->wsp.pan);
    int ec = post_form(curr->form);
    if (ec == E_OK)
      posted_form = ndx;
    else {
      curr->posted = false;
      LOGECFAIL(kit->log, "post_form", ec);
    }
  } else {
    bottom_panel(curr->wsp.pan);
    int ec = unpost_form(curr->form);
    if (ec != E_OK)
      LOGECFAIL(kit->log, "unpost_form", ec);
  }
  LOGMSG("> menu=%s form[%d] posted=%d", kit->log, ndx, curr->posted);
  update_panels();
  doupdate();
}

static void free_wsp(winpan_s *wsp) NONNULL(1);
static void free_wsp(winpan_s *wsp) {
  if (wsp->pan) {
    del_panel(wsp->pan);
    wsp->pan = NULL;
  }
  if (wsp->sub) {
    delwin(wsp->sub);
    wsp->sub = NULL;
  }
  if (wsp->win) {
    delwin(wsp->win);
    wsp->win = NULL;
  }
}

static void process_form_input(kitmenu_s *kit, const char *got,
  ITEM *item, FIELD *field) NONNULL(1, 2, 3, 4);
static void process_form_input(kitmenu_s *kit, const char *got,
  ITEM *item, FIELD *field)
{
  menuitem_s *data = item_userptr(item);
  if (!data)
    return;
  LOGMSG("got: \"%s\"", got);
  char value[NAMELEN] = {0};
  int rc = snprinte(value, sizeof(value), "%s", got);
  const char *str = ((rc > 0) && value[0]) ? trim(value) : NULL;
  if (!str)
    str = got;
  switch (data->type) {
    case MI_INTFORM: {
      char error[NAMELEN] = {0};
      int min = data->pmin ? *data->pmin : data->min;
      int max = data->pmax ? *data->pmax : data->max;
      int num = arg2int(0, str, min, max, item_name(item), error, sizeof(error));
      int *val = data->val.num;
      if (error[0]) {
        LOGMSG("%s", trim(error));
        if (val) { // restore field buff
          int rc = snprinte(value, sizeof(value), "%d", *val);
          if (rc > 0)
            set_field_buffer(field, 0, value);
        }
      } else {
        LOGMSG("num: %d", num);
        if (val && (*val != num))
          *val = num;
      }
    } break;
    case MI_STRFORM: {
      bool valid = true;
      const char *patt = data->patt;
      if (patt) {
        const char *key = str;
        valid = key && key[0];
        if (valid) {
          for (int i = 0; (i < kit->desc_width) && *key; i++, key++)
            if (!strchr(patt, *key)) {
              LOGMSG("invalid key: %c", *key);
              valid = false;
              break;
            }
        }
      }
      const char *val = data->val.pstr ? *data->val.pstr : NULL;
      if (valid) {
        LOGMSG("str: %s", str);
        if (val && STR_NEQ(val, str, kit->desc_width)) {
          if (data->setter)
            data->setter(str);
          else // ? snprinte(val[len], len, "%s", str)
            LOGMSG("%s", "no setter for string form");
        }
      } else {
        LOGMSG("invalid input: %s", str);
        if (val) { // restore field buff
          int rc = snprinte(value, sizeof(value), "%s", val);
          if (rc > 0)
            set_field_buffer(field, 0, value);
        }
      }
    } break;
    default: break;
  }
}

static void fin_form(kitmenu_s *kit, mi_s *mi, ITEM *item) NONNULL(1, 2, 3);
static void fin_form(kitmenu_s *kit, mi_s *mi, ITEM *item) {
  FIELD *field = mi->field[0];
  if (field) {
    LOGMSG("%s", item_name(item));
    char *got = field_buffer(field, 0);
    if (got && got[0]) {
      LOGMSG("got: \"%s\"", got);
      char value[NAMELEN] = {0};
      int rc = snprinte(value, sizeof(value), "%s", got);
      char *arg = ((rc > 0) && value[0]) ? trim(value) : NULL;
      process_form_input(kit, arg ? arg : got, item, field);
    }
  }
}

static void free_menukit(kitmenu_s *kit) NONNULL(1);
static void free_menukit(kitmenu_s *kit) {
  LOGMSG("menu %s: %s", kit->log, "free menu stuff");
  // menu itself
  if (kit->menu) {
    if (kit->posted) {
      unpost_menu(kit->menu);
      kit->posted = false;
    }
    set_menu_items(kit->menu, NULL);
    free_menu(kit->menu);
    kit->menu = NULL;
  }
  // items
  ITEM **item = kit->items;
  for (uint i = 0; i < kit->len; i++, item++) {
    if (*item) {
      free_item(*item);
      *item = NULL;
    }
  }
  // forms-n-fields
  mi_s *mi = kit->mis;
  for (uint i = 0; i < kit->len; i++, mi++) {
    if (mi->form) {
      if (mi->posted) {
        unpost_form(mi->form);
        mi->posted = false;
      }
      free_form(mi->form);
      mi->form = NULL;
    }
    if (mi->field[0]) {
      free_field(mi->field[0]);
      mi->field[0] = NULL;
    }
    // menuitem's panel-n-windows
    free_wsp(&mi->wsp);
  }
  // panel-n-windows
  free_wsp(&kit->wsp);
}

static inline kitmenu_s *get_active_priokit(void) {
  // only one submenu should be active
  kitmenu_s *kit = kitmenu, *active_submenu = NULL;
  for (uint i = 0; i < ARRAY_LEN(kitmenu); i++, kit++) {
    if (kit && (kit->type == KIT_SUBMENU) && kit->active) {
      active_submenu = kit;
      break;
    }
  }
  return active_submenu ? active_submenu :
    kitmenu[KITMENU_MAIN].active ? &kitmenu[KITMENU_MAIN] : NULL;
}

static bool hide_all_submenus(void) {
  bool done = false;
  kitmenu_s *kit = kitmenu;
  for (uint i = 0; i < ARRAY_LEN(kitmenu); i++, kit++) {
    if (kit && (kit->type == KIT_SUBMENU) && kit->active) {
      menu_hide(kit);
      if (!done)
        done = true;
    }
  }
  return done;
}

static void menu_repost(kitmenu_s *kit) NONNULL(1);
static void menu_repost(kitmenu_s *kit) {
  if (kit->posted) {
    LOGMSG("%s", kit->log);
    ITEM *curr = current_item(kit->menu);
    int ndx = curr ? item_index(curr) : -1;
    unpost_menu(kit->menu);
    kit->posted = false;
    if (kit->mi_init)
      kit->mi_init(toogle, menuexp);
    if (kit->items[0]) {
      int ec = set_menu_items(kit->menu, kit->items);
      if (ec == E_OK) {
        position_inside_menu(kit, ndx);
        int ec = post_menu(kit->menu);
        if (ec == E_OK) {
          kit->posted = true;
          LOGMSG("menu %s: %s", kit->log, "reposted");
        } else
          LOGECFAIL(kit->log, "post_menu", ec);
      } else
        LOGECFAIL(kit->log, "set_menu_items", ec);
    } else
      LOGMSG("menu %s: %s", kit->log, "cannot reinit menu items");
  }
}

static void action_cycles_unlim(void) {
  bool last = is_value_cycles();
  if (last) // keep
    subopts.cycles_val = run_opts.cycles;
  int value = last ? 0 : subopts.cycles_val; // toggle
  LOGMSG("cycles: %d -> %d", run_opts.cycles, value);
  run_opts.cycles = value;
  subopts.cycles_inf = !is_value_cycles();
  menu_posteditaction(KITMENU_CYCLES, SUBMENU_CYCLES_INF);
  menu_toggle_look();
}

static void action_rnd_pattern(void) {
  bool last = is_value_bpatt();
  if (last) // keep
    subopts.bpatt_val = run_opts.pattern;
  int value = last ? -1 : subopts.bpatt_val; // toggle
  LOGMSG("bit-pattern: %d -> %d", run_opts.pattern, value);
  run_opts.pattern = value;
  subopts.bpatt_rnd = !is_value_bpatt();
  menu_posteditaction(KITMENU_BPATT, SUBMENU_BPATT_RND);
  menu_toggle_look();
}

static void action_no_xcache(void) {
  bool last = is_value_xcache();
  if (last) // keep
    subopts.xcache_val = run_opts.cache;
  int value = last ? 0 : subopts.xcache_val; // toggle
  LOGMSG("xcache: %d -> %d", run_opts.cache, value);
  run_opts.cache = value;
  subopts.xcache_nop = !is_value_xcache();
  menu_posteditaction(KITMENU_XCACHE, SUBMENU_XCACHE_NOT);
  menu_toggle_look();
}


//
// global

void free_menus(void) {
  for (uint i = 0; i < ARRAY_LEN(kitmenu); i++) {
    menu_hide(&kitmenu[i]);
    free_menukit(&kitmenu[i]);
  }
}

#ifdef LOGMOD
#define LOGKITMENUACTIVE do {                                        \
  for (uint i = 0; i < ARRAY_LEN(kitmenu); i++)                      \
    LOGMSG("menu %s: active=%d", kitmenu[i].log, kitmenu[i].active); \
} while (0)
#else
#define LOGKITMENUACTIVE
#endif

void menu_showup(WINDOW *_win UNUSED) {
  if (tuilook == NEWLOOK) {
    if (!kitmenu[KITMENU_MAIN].posted) {
      prepare_menus();
      if (!kitmenu[KITMENU_MAIN].posted)
        return;
    }
    LOGKITMENUACTIVE;
    if (!hide_all_submenus()) {
      if (kitmenu[KITMENU_MAIN].active)
        menu_hide(&kitmenu[KITMENU_MAIN]);
      else
        menu_show(&kitmenu[KITMENU_MAIN]);
    }
    menu_toggle_look();
    update_panels();
    doupdate();
  }
}

void menu_inout(int key) {
  bool dosmth = false;
  kitmenu_s *kit = get_active_priokit();
  if (kit) {
    LOGKITMENUACTIVE;
    if        (key == KEY_LEFT) {
      dosmth = (kit->type == KIT_SUBMENU);
      if (dosmth)
        menu_hide(kit);
    } else if (key == KEY_RIGHT) {
      ITEM *item = kit->menu ? current_item(kit->menu) : NULL;
      menuitem_s *menuitem = (item && (item_opts(item) & O_SELECTABLE)) ? item_userptr(item) : NULL;
      dosmth = (menuitem && (menuitem->type == MI_SUBMENU) && menuitem->submenu);
      if (dosmth)
        menu_show(menuitem->submenu);
    }
  }
  if (dosmth) {
    menu_toggle_look();
    update_panels();
    doupdate();
  }
}

void menu_line_updown(bool up) {
  kitmenu_s *kit = get_active_priokit();
  if (kit)
    menu_driver(kit->menu, up ? REQ_UP_ITEM : REQ_DOWN_ITEM);
}

void menu_page_updown(int lines) {
  bool up = (lines > 0);
  if (lines < 0)
    lines = -lines;
  for (int i = 0; i < lines; i++)
    menu_line_updown(up);
}

key_action_t menu_action(void) {
  LOGKITMENUACTIVE;
  kitmenu_s *kit = get_active_priokit();
  ITEM *item = (kit && kit->posted && kit->menu) ? current_item(kit->menu) : NULL;
  key_action_t action = ActionNone;
  if (item && (item_opts(item) & O_SELECTABLE)) {
    menuitem_s *data = item_userptr(item);
    if (data) {
      action = data->action;
      switch (data->type) {
        case MI_TOOGLE:
          LOGMSG("menu %s: %d", kit->log, data->action);
          switch (action) {
            case ActionMenuCyclesUnlim:
              action_cycles_unlim();
              action = ActionNone;
              break;
            case ActionMenuPattRnd:
              action_rnd_pattern();
              action = ActionNone;
              break;
            case ActionMenuNoCache:
              action_no_xcache();
              action = ActionNone;
              break;
            default: break;
          } break;
        case MI_INTFORM:
        case MI_STRFORM:
          activate_form(kit, item, data);
          break;
        case MI_SUBMENU: {
          kitmenu_s *sub = data->submenu;
          if (sub) {
            sub->active ? menu_hide(sub) : menu_show(sub);
            menu_toggle_look();
          }
        }  break;
        default: break;
      }
    }
  }
  return action;
}

void menu_toggle_look(void) {
  for (uint i = 0; i < ARRAY_LEN(kitmenu); i++)
    if (kitmenu[i].active)
      menu_repost(&kitmenu[i]);
}

inline static bool enclose_kit(kitmenu_s *kit, int x, int y) NONNULL(1);
inline static bool enclose_kit(kitmenu_s *kit, int x, int y) {
  return (kit->active && kit->wsp.win) ? wenclose(kit->wsp.win, y, x) : false;
}

menu_ndx_t inside_curr_menu(int x, int y) {
  kitmenu_s *kit = get_active_priokit();
  return (kit && enclose_kit(kit, x, y)) ? kit->ndx : KITMENU_NONE;
}

int mouse_select_n_toggle(menu_ndx_t ndx) {
  kitmenu_s *kit = ((ndx >= 0) && (ndx < (int)ARRAY_LEN(kitmenu)))
    ? &kitmenu[ndx] : NULL;
  int rc = kit ? menu_driver(kit->menu, KEY_MOUSE) : 0;
  LOGMSG("menu %s, driver(KEY_MOUSE): rc=%d", kit ? kit->log : "UNKN", rc);
  return (rc == E_UNKNOWN_COMMAND) ? ON_MOUSE_DBL_CLICK : 0;
}

void set_kit_attr(const short *bg, const int *x0, const int *y0) {
  if (bg)
    common_attr.bg = *bg;
  if (x0)
    common_attr.x0 = *x0;
  if (y0)
    common_attr.y0 = *y0;
}

int menu_form_key(int key) {
  kitmenu_s *kit = get_active_priokit();
  if (!kit)
    return key;
  int ndx = posted_form;
  if ((ndx < 0) || (ndx >= (int)kit->len))
    return key;
  FORM *form = kit->mis[ndx].form;
  if (!form)
    return key;
  int rc = 0;
  switch (key) {
    case KEY_LEFT:
      form_driver(form, REQ_PREV_CHAR);
      break;
    case KEY_RIGHT:
      form_driver(form, REQ_NEXT_CHAR);
      break;
    case KEY_BACKSPACE:
//  case 127:
      form_driver(form, REQ_DEL_PREV);
      break;
    case KEY_DC:
      form_driver(form, REQ_DEL_CHAR);
      break;
    case C_SPACE:
    case KEY_ENTER:
    case '\r':
    case '\n': {
      form_driver(form, REQ_VALIDATION);
      ITEM *item = kit->items[ndx];
      mi_s *mi = &kit->mis[ndx];
      if (item)
        fin_form(kit, mi, item);
      close_form(mi);
      menuitem_s *data = item ? item_userptr(item) : NULL;
      if (data && (data->action == ActionNone))
        menu_posteditaction(kit->ndx, data->ndx);
      menu_toggle_look();
    } break;
    default:
      if (isprint(key))
        form_driver(form, key);
      else {
        rc = key;
        close_form(&kit->mis[ndx]);
      }
      break;
  }
  return rc;
}

bool menu_active(void) {
  for (uint i = 0; i < ARRAY_LEN(kitmenu); i++)
    if (kitmenu[i].active)
      return true;
  return false;
}

