// part of mtr085: menu kit

#include <string.h>
#include <ctype.h>

#if defined(LOG_TUI) && !defined(LOGMOD)
#define LOGMOD
#include <errno.h>
#endif
#if !defined(LOG_TUI) && defined(LOGMOD)
#undef LOGMOD
#endif

#include "kit.h"
#include "aux.h"
#include "nls.h"
#include "net.h"

#define ROUNDED_CORNERS    true
#define ON_MOUSE_DBL_CLICK C_SPACE

#define LOGWINSIZE(title, win) LOGMSG("%s: x0=%d y0=%d w=%d h=%d", \
 (title), getbegx(win), getbegy(win), getmaxx(win), getmaxy(win))

bool menuactive;
int posted_form = -1;

typedef enum {
  MI_TOOGLE,
  MI_INTFORM,
  MI_STRFORM,
} mi_type;

typedef enum {
#ifdef ENABLE_DNS
  MENU_ITEM_DNS,
#endif
#ifdef WITH_IPINFO
  MENU_ITEM_ASN,
#endif
  MENU_ITEM_JITTER,
  MENU_ITEM_FIELDS,
#ifdef WITH_MPLS
  MENU_ITEM_MPLS,
#endif
  MENU_ITEM_COUNT,
  MENU_ITEM_MINTTL,
  MENU_ITEM_MAXTTL,
  MENU_ITEM_PATTERN,
  MENU_ITEM_TIMEI,
#ifdef ENABLE_QOS
  MENU_ITEM_QOS,
#endif
  MENU_ITEM_PSIZE,
  MENU_ITEMS
} mi_inst;

typedef struct wsp_s {
  WINDOW *win;
  WINDOW *sub;
  PANEL  *pan;
} wsp_s;

typedef struct miff_s {
  FORM  *form;
  FIELD *field[2]; // NULL terminated
  wsp_s wsp;
  bool posted;
} miff_s;

typedef struct kit_s {
  ITEM *item[MENU_ITEMS + 1];
  miff_s ff[MENU_ITEMS];
  MENU *menu;
  wsp_s wsp;
  bool posted;
  int x0, y0;
  short bg;       // background
  int frame;
  int maxnamelen; // in utf8 characters
  int spacing;
  const int desc_width;
} kit_s;

static kit_s kit = {.spacing = 1/*default*/, .desc_width = 10/*looks enough*/};

#define LOGFNFAIL(fn)     LOGMSG("%s() failed" ,    (fn))
#define LOGECFAIL(fn, ec) LOGMSG("%s() failed: %d/%d", (fn), (ec), ((ec) == E_SYSTEM_ERROR) ? errno : 0)

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
  const mi_inst ndx;
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
} menuitem_s;

typedef struct optname_s {
  int len; // name length in unicode characters
  const char* const name;
} optname_s;

//

static void menu_posteditaction(mi_inst inst) {
  switch (inst) {
    case MENU_ITEM_COUNT:   OPT_SUM(cycles);   break;
    case MENU_ITEM_MINTTL:  OPT_SUM(minttl);   break;
    case MENU_ITEM_MAXTTL:  OPT_SUM(maxttl);   break;
    case MENU_ITEM_PATTERN: OPT_SUM(pattern); reset_pattern = true; break;
    case MENU_ITEM_TIMEI:   OPT_SUM(interval); break;
#ifdef ENABLE_QOS
    case MENU_ITEM_QOS:     OPT_SUM(qos);      break;
#endif
    case MENU_ITEM_PSIZE:   OPT_SUM(size);     break;
    default: break;
  }
}

static void mi_selectabale(int ndx UNUSED, ITEM *item UNUSED) {
#if defined(ENABLE_QOS) && (!defined(ENABLE_QOS4) || !defined(ENABLE_QOS6))
#if   !defined(ENABLE_QOS4)
  if ((ndx == MENU_ITEM_QOS) && (af == AF_INET))
    item_opts_off(item, O_SELECTABLE);
#elif !defined(ENABLE_QOS6)
  if ((ndx == MENU_ITEM_QOS) && (af == AF_INET6))
    item_opts_off(item, O_SELECTABLE);
#endif
#endif
}

static int fill_itemname(const menuitem_s *mi, const char *name,
  uint size, char buff[size], int pad) NONNULL(1, 2, 4);
static int fill_itemname(const menuitem_s *mi, const char *name,
  uint size, char buff[size], int pad)
{
  buff[0] = 0;
  int rc = 0;
  switch (mi->type) {
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

static int fill_itemdesc(menuitem_s *mi) NONNULL(1);
static int fill_itemdesc(menuitem_s *mi) {
  int rc = 0;
  switch (mi->type) {
    case MI_TOOGLE: {
      const bool *flag = mi->val.flag;
      if (flag) {
        const char *toggle =
#if defined(TUIWIDE) && defined(WITH_UNICODE)
          utf_compat ? (*flag ? /*"☑"*//*"🗹 "*//*"✔"*/"✓" : /*"☐"*/"◻") :
#endif
                       (*flag ? "+" : "-");
        rc = (kit.desc_width > 0) ?
          snprinte(mi->desc, sizeof(mi->desc), // utf8-compat padding
            "%*s%s ", kit.desc_width - 1/*toggle_char*/, "", toggle) :
          snprinte(mi->desc, sizeof(mi->desc), "%s ", toggle);
      }
    } break;
    case MI_INTFORM: {
      int *num = mi->val.num;
      if (num) {
        rc = (kit.desc_width > 0) ?
          snprinte(mi->desc, sizeof(mi->desc), "%*d ", kit.desc_width, *num) :
          snprinte(mi->desc, sizeof(mi->desc), "%d ", *num);
      }
    }  break;
    case MI_STRFORM: {
      const char *str = mi->val.pstr ? *mi->val.pstr : NULL;
      if (str) {
        rc = (kit.desc_width > 0) ?
          snprinte(mi->desc, sizeof(mi->desc), "%*s ", kit.desc_width, str) :
          snprinte(mi->desc, sizeof(mi->desc), "%s ", str);
      }
    }  break;
    default:
      LOGMSG("unknwon menuitem type: %d", mi->type);
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

static void init_menuitems(void) {
#define PSIZEMM (MAXPACKET - MINPACKET)
  static menuitem_s menuitem[MENU_ITEMS] = {
#ifdef ENABLE_DNS
    [MENU_ITEM_DNS]      = {.ndx = MENU_ITEM_DNS,     .type = MI_TOOGLE,
      .action = ActionDNS,  .val.flag = &run_opts.dns},
#endif
#ifdef WITH_IPINFO
    [MENU_ITEM_ASN]      = {.ndx = MENU_ITEM_ASN,     .type = MI_TOOGLE,
      .action = ActionASN,  .val.flag = &run_opts.asn},
#endif
    [MENU_ITEM_JITTER]   = {.ndx = MENU_ITEM_JITTER,  .type = MI_TOOGLE,
      .action = ActionJttr, .val.flag = &run_opts.jitter},
    [MENU_ITEM_FIELDS]   = {.ndx = MENU_ITEM_FIELDS,  .type = MI_STRFORM,
      .action = ActionNone, .val.pstr = &fld_active, .setter = set_fld_active},
#ifdef WITH_MPLS
    [MENU_ITEM_MPLS]     = {.ndx = MENU_ITEM_MPLS,    .type = MI_TOOGLE,
      .action = ActionMPLS, .val.flag = &run_opts.mpls},
#endif
    [MENU_ITEM_COUNT]    = {.ndx = MENU_ITEM_COUNT,   .type = MI_INTFORM,
      .action = ActionNone, .val.num  = &run_opts.cycles,
      .min =  0, .max = INT_MAX},
    [MENU_ITEM_MINTTL]   = {.ndx = MENU_ITEM_MINTTL,  .type = MI_INTFORM,
      .action = ActionNone, .val.num  = &run_opts.minttl,
      .min =  1, .max = MAXHOST, .pmax = &run_opts.maxttl},
    [MENU_ITEM_MAXTTL]   = {.ndx = MENU_ITEM_MAXTTL,  .type = MI_INTFORM,
      .action = ActionNone, .val.num  = &run_opts.maxttl,
      .min =  1, .max = MAXHOST, .pmin = &run_opts.minttl},
    [MENU_ITEM_PATTERN]  = {.ndx = MENU_ITEM_PATTERN, .type = MI_INTFORM,
      .action = ActionNone, .val.num  = &run_opts.pattern,
      .min = -1, .max = UINT8_MAX},
    [MENU_ITEM_TIMEI]    = {.ndx = MENU_ITEM_TIMEI,   .type = MI_INTFORM,
      .action = ActionNone, .val.num  = &run_opts.interval,
      .min =  1, .max = INT_MAX},
#ifdef ENABLE_QOS
    [MENU_ITEM_QOS]      = {.ndx = MENU_ITEM_QOS,     .type = MI_INTFORM,
      .action = ActionNone, .val.num  = &run_opts.qos,
      .min =  0, .max = UINT8_MAX},
#endif
    [MENU_ITEM_PSIZE]    = {.ndx = MENU_ITEM_PSIZE,   .type = MI_INTFORM,
      .action = ActionNone, .val.num  = &run_opts.size,
      .min = -PSIZEMM, .max = PSIZEMM},
  };
  //
  static char field_patt[20] = {0}; // enough for stat keys [stat_max]
  if (!field_patt[0])
    stat_keys(ARRAY_LEN(field_patt) - 1, field_patt);
  if (!menuitem[MENU_ITEM_FIELDS].patt)
    menuitem[MENU_ITEM_FIELDS].patt = field_patt;
  //
  optname_s optname[ARRAY_LEN(menuitem)] = {
#ifdef ENABLE_DNS
    [MENU_ITEM_DNS]     = {.name = MENUSTRW(_DNS_STR)},
#endif
#ifdef WITH_IPINFO
    [MENU_ITEM_ASN]     = {.name = MENUSTRW(_ASN_STR)},
#endif
    [MENU_ITEM_JITTER]  = {.name = MENUSTRW(_JITTER_STR)},
    [MENU_ITEM_FIELDS]  = {.name = MENUSTRW(_FIELDS_STR)},
#ifdef WITH_MPLS
    [MENU_ITEM_MPLS]    = {.name = MENUSTRW(_MPLS_STR)},
#endif
    [MENU_ITEM_COUNT]   = {.name = MENUSTRW(_NCYCLES_STR)},
    [MENU_ITEM_MINTTL]  = {.name = MENUSTRW(_MINTTL_STR)},
    [MENU_ITEM_MAXTTL]  = {.name = MENUSTRW(_MAXTTL_STR)},
    [MENU_ITEM_PATTERN] = {.name = MENUSTRW(_BITPATT_STR)},
    [MENU_ITEM_TIMEI]   = {.name = MENUSTRW(_GAPINSEC_STR)},
#ifdef ENABLE_QOS
    [MENU_ITEM_QOS]     = {.name = MENUSTRW(_QOSTOS_STR)},
#endif
    [MENU_ITEM_PSIZE]   = {.name = MENUSTRW(_PSIZE_STR)},
  };
  //
  if (!kit.maxnamelen)
    kit.maxnamelen = calc_maxnamelen(ARRAY_LEN(menuitem), menuitem, optname);
  //
  if (kit.item[0]) {
    // disconnect and free previous menuitems
    // menu has to be unposted
    int ec = set_menu_items(kit.menu, NULL);
    if (ec == E_OK) {
      for (uint i = 0; i < ARRAY_LEN(kit.item); i++) if (kit.item[i]) {
        int ec = free_item(kit.item[i]);
        if (ec != E_OK)
          LOGECFAIL("free_item", ec);
        kit.item[i] = NULL;
      }
    } else
      LOGECFAIL("set_menu_items", ec);
  }
  //
  menuitem_s *mi = menuitem;
  const optname_s *opt = optname;
  for (uint i = 0; (i < ARRAY_LEN(optname)) && opt->name; i++, opt++, mi++) {
    int pad = // utf8-compat padding
      (opt->len > 0) ? (kit.maxnamelen - opt->len) : 0;
    const char *name =
      (fill_itemname(mi, opt->name, sizeof(mi->name), mi->name, pad) > 0) && mi->name[0]
      ? mi->name : opt->name;
    const char *desc =
      (fill_itemdesc(mi) > 0) && mi->desc[0]
      ? mi->desc : NULL;
    ITEM *item = new_item(name, desc);
    if (item) {
      LOGMSG("menuitem[%u]: \"%s\"=\"%s\"", i, item_name(item), item_description(item));
      set_item_userptr(item, mi);
      kit.item[i] = item;
      mi_selectabale(i, item);
    } else {
      LOGMSG("new_item(#%u, %s) failed: %d", i, opt->name, errno);
      break;
    }
  }
}

static void prepare_menu(void) {
  if (!kit.item[0]) {
    init_menuitems();
    if (!kit.item[0]) {
      LOGMSG("%s", "no items");
      return;
    }
  }
  if (!kit.menu) {
    kit.menu = new_menu(kit.item);
    if (!kit.menu) {
      LOGECFAIL("new_menu", errno);
      return;
    }
    { int ec = set_menu_mark(kit.menu, NULL);
      if (ec != E_OK)
        LOGFNFAIL("set_menu_mark"); }
    if (kit.bg > 0) {
      int ec = set_menu_back(kit.menu, COLOR_PAIR(kit.bg));
      if (ec != E_OK)
        LOGECFAIL("set_menu_back", ec);
    }
    { int ec = set_menu_grey(kit.menu, COLOR_PAIR(kit.bg > 0 ? kit.bg : 0) | A_DIM);
      if (ec != E_OK)
        LOGECFAIL("set_menu_grey", ec); }
  }
  menu_spacing(kit.menu, &kit.spacing, NULL, NULL);
  kit.frame =
#ifdef WITH_UNICODE
    utf_compat ? 1 :
#endif
  0;
  LOGMSG("frame=%d spacing=%d", kit.frame, kit.spacing);
  int h = MENU_ITEMS, w = (kit.maxnamelen > 0) ? kit.maxnamelen : 16;
  w += kit.spacing;
  w += kit.desc_width;
  w++;
  if (!kit.wsp.win) {
    kit.wsp.win = newwin(h + 2 * kit.frame, w + 2 * kit.frame, kit.y0, kit.x0);
    if (!kit.wsp.win) {
      LOGFNFAIL("newwin");
      return;
    }
    keypad(kit.wsp.win, TRUE);
    if (kit.bg > 0)
      wbkgd(kit.wsp.win, COLOR_PAIR(kit.bg));
    if (kit.frame) {
#ifdef ROUNDED_CORNERS
      cchar_t tl = {0}, tr = {0}, bl = {0}, br = {0};
      setcchar(&tl, L"╭", A_NORMAL, 0, NULL);
      setcchar(&tr, L"╮", A_NORMAL, 0, NULL);
      setcchar(&bl, L"╰", A_NORMAL, 0, NULL);
      setcchar(&br, L"╯", A_NORMAL, 0, NULL);
      wborder_set(kit.wsp.win, NULL, NULL, NULL, NULL, &tl, &tr, &bl, &br);
#else
      box(menuwin, 0, 0);
#endif
    }
    LOGWINSIZE("menuwin", kit.wsp.win);
  }
  if (!kit.wsp.sub) {
    kit.wsp.sub = derwin(kit.wsp.win, h, w, kit.frame, kit.frame);
    if (!kit.wsp.sub) {
      LOGFNFAIL("derwin");
      return;
    }
    LOGWINSIZE("menusub", kit.wsp.sub);
  }
  //
  if (menu_win(kit.menu) != kit.wsp.win) {
    int ec = set_menu_win(kit.menu, kit.wsp.win);
    if (ec != E_OK) {
      LOGECFAIL("set_menu_win", ec);
      free_menu(kit.menu);
      kit.menu = NULL;
      return;
    }
  }
  if (menu_sub(kit.menu) != kit.wsp.sub) {
    int ec = set_menu_sub(kit.menu, kit.wsp.sub);
    if (ec != E_OK) {
      LOGECFAIL("set_menu_sub", ec);
      free_menu(kit.menu);
      kit.menu = NULL;
      return;
    }
  }
  //
  if (!kit.wsp.pan) {
    kit.wsp.pan = new_panel(kit.wsp.win);
    if (!kit.wsp.pan) {
      LOGFNFAIL("new_panel");
      return;
    }
  }
  //
  if (!kit.posted)
    kit.posted = (post_menu(kit.menu) == E_OK);
}

static void menu_showhide(void) {
  LOGMSG("%s", menuactive ? "hide" : "show");
  if (menuactive) {
    hide_panel(kit.wsp.pan);
    bottom_panel(kit.wsp.pan);
  } else {
    top_panel(kit.wsp.pan);
    show_panel(kit.wsp.pan);
  }
  menuactive = !menuactive;
  update_panels();
  doupdate();
}

static void position_inside_menu(int was) {
  int count = (kit.menu && (was >= 0)) ? item_count(kit.menu) : -1;
  if (count > 0) {
    ITEM **list = menu_items(kit.menu);
    if (list) for (int i = 0; i < count; i++) {
      ITEM *item = list[i];
      int now = item ? item_index(item) : -1;
      if (now == was) {
        set_current_item(kit.menu, item);
        LOGMSG("%d", now);
        return;
      }
    }
  }
  LOGMSG("%s", "state isn't restored");
}

static void set_field_num(FIELD *field, int num, int width) NONNULL(1);
static void set_field_num(FIELD *field, int num, int width) {
  char buff[width + 1];
  memset(buff, 0, sizeof(buff));
  int rc = snprinte(buff, sizeof(buff), "%d", num);
  if (rc > 0) {
    int ec = set_field_buffer(field, 0, buff);
    if (ec != E_OK)
      LOGECFAIL("set_field_buffer", ec);
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
      LOGECFAIL("set_field_buffer", ec);
  }
}

static void prepare_form(int ndx, menuitem_s *data) NONNULL(2);
static void prepare_form(int ndx, menuitem_s *data) {
  // menuitem types: INTFORM, STRFORM
  if ((ndx < 0) || (ndx >= (int)ARRAY_LEN(kit.ff))) {
    LOGMSG("wrong index: %d", ndx);
    return;
  }
  int desc_x0 = kit.maxnamelen + kit.spacing;
  LOGMSG("index=%d desc-offset=%d", ndx, desc_x0);
  int x0 = getbegx(kit.wsp.sub) + desc_x0;
  int y0 = getbegy(kit.wsp.sub) + ndx;
  int w  = getmaxx(kit.wsp.sub) - (desc_x0 + 1);
  int h  = 1;
  //
  FIELD *field = kit.ff[ndx].field[0];
  if (!field) {
    field = new_field(h, w, 0, 0, 0, 0);
    if (!field) {
      LOGECFAIL("new_field", errno);
      return;
    }
    set_field_back(field, A_UNDERLINE);
    field_opts_off(field, O_AUTOSKIP);
    kit.ff[ndx].field[0] = field;
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
  FORM *form = kit.ff[ndx].form;
  if (!form) {
    form = new_form(kit.ff[ndx].field);
    if (!form) {
      LOGECFAIL("new_form", errno);
      return;
    }
    kit.ff[ndx].form = form;
  }
  WINDOW *win = kit.ff[ndx].wsp.win;
  if (!win) {
    win = newwin(h, w, y0, x0);
    if (!win) {
      LOGFNFAIL("newwin");
      return;
    }
    keypad(win, TRUE);
    kit.ff[ndx].wsp.win = win;
  }
  WINDOW *sub = kit.ff[ndx].wsp.sub;
  if (!sub) {
    sub = derwin(win, h, w, 0, 0);
    if (!sub) {
      LOGFNFAIL("derwin");
      return;
    }
    kit.ff[ndx].wsp.sub = sub;
  }
  //
  if (form_win(form) != win) {
    int ec = set_form_win(form, win);
    if (ec != E_OK) {
      LOGECFAIL("set_form_win", ec);
      free_form(form);
      kit.ff[ndx].form = NULL;
      return;
    }
  }
  if (form_sub(form) != sub) {
    int ec = set_form_sub(form, sub);
    if (ec != E_OK) {
      LOGECFAIL("set_form_sub", ec);
      free_form(form);
      kit.ff[ndx].form = NULL;
      return;
    }
  }
  //
  PANEL *pan = kit.ff[ndx].wsp.pan;
  if (!pan) {
    pan = new_panel(win);
    if (!pan) {
      LOGFNFAIL("new_panel");
      return;
    }
    kit.ff[ndx].wsp.pan = pan;
  }
}

static void close_form(miff_s *ff) NONNULL(1);
static void close_form(miff_s *ff) {
  bottom_panel(ff->wsp.pan);
  unpost_form(ff->form);
  ff->posted = false;
  posted_form = -1;
  LOGMSG("%s", "done");
}

static void activate_form(ITEM *item, menuitem_s *data) NONNULL(1, 2);
static void activate_form(ITEM *item, menuitem_s *data) {
  // menuitem types: INTFORM, STRFORM
  int ndx = item_index(item);
  if ((ndx < 0) || (ndx >= (int)ARRAY_LEN(kit.ff))) {
    LOGMSG("%s", "no item/data");
    return;
  }
  miff_s *curr = &kit.ff[ndx];
  if (!curr->form || !curr->field[0]) {
    prepare_form(ndx, data);
    if (!curr->form || !curr->field[0])
      return;
  }
  LOGMSG("< form[%d] posted=%d", ndx, curr->posted);
  // unpost all other menuitem forms if there are posted ones
  { miff_s *ff = kit.ff;
    for (int i = 0; i < (int)ARRAY_LEN(kit.ff); i++, ff++)
      if (ff->posted && (i != ndx)) {
        bottom_panel(ff->wsp.pan);
        unpost_form(ff->form);
        ff->posted = false;
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
      LOGECFAIL("post_form", ec);
    }
  } else {
    bottom_panel(curr->wsp.pan);
    int ec = unpost_form(curr->form);
    if (ec != E_OK)
      LOGECFAIL("unpost_form", ec);
  }
  LOGMSG("> form[%d] posted=%d", ndx, curr->posted);
  update_panels();
  doupdate();
}

static void free_wsp(wsp_s *wsp) NONNULL(1);
static void free_wsp(wsp_s *wsp) {
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

static void process_form_input(const char *got, ITEM *item, FIELD *field) NONNULL(1, 2, 3);
static void process_form_input(const char *got, ITEM *item, FIELD *field) {
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
          for (int i = 0; (i < kit.desc_width) && *key; i++, key++)
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
        if (val && STR_NEQ(val, str, kit.desc_width)) {
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

static void fin_form(miff_s *ff, ITEM *item) NONNULL(1, 2);
static void fin_form(miff_s *ff, ITEM *item) {
  FIELD *field = ff->field[0];
  if (field) {
    LOGMSG("%s", item_name(item));
    char *got = field_buffer(field, 0);
    if (got && got[0]) {
      LOGMSG("got: \"%s\"", got);
      char value[NAMELEN] = {0};
      int rc = snprinte(value, sizeof(value), "%s", got);
      char *arg = ((rc > 0) && value[0]) ? trim(value) : NULL;
      process_form_input(arg ? arg : got, item, field);
    }
  }
}


//
// global

void free_menukit(void) {
  LOGMSG("%s", "free menu stuff");
  // menu itself
  if (kit.menu) {
    if (kit.posted) {
      unpost_menu(kit.menu);
      kit.posted = false;
    }
    set_menu_items(kit.menu, NULL);
    free_menu(kit.menu);
    kit.menu = NULL;
  }
  // items
  ITEM **item = kit.item;
  for (uint i = 0; i < ARRAY_LEN(kit.item); i++, item++) {
    if (*item) {
      free_item(*item);
      *item = NULL;
    }
  }
  // forms-n-fields
  miff_s *ff = kit.ff;
  for (uint i = 0; i < ARRAY_LEN(kit.ff); i++, ff++) {
    if (ff->form) {
      if (ff->posted) {
        unpost_form(ff->form);
        ff->posted = false;
      }
      free_form(ff->form);
      ff->form = NULL;
    }
    if (ff->field[0]) {
      free_field(ff->field[0]);
      ff->field[0] = NULL;
    }
    // ff's panel-n-windows
    free_wsp(&ff->wsp);
  }
  // panel-n-windows
  free_wsp(&kit.wsp);
  //
  menuactive = false;
}

void menu_handler(WINDOW *_win UNUSED) {
  if (tuilook != NEWLOOK)
    return;
  if (kit.posted)
    menu_showhide();
  else {
    prepare_menu();
    if (kit.posted)
      menu_showhide();
  }
}

void menuline_updown(bool up) {
  menu_driver(kit.menu, up ? REQ_UP_ITEM : REQ_DOWN_ITEM);
}

void menupage_updown(int lines) {
  bool up = (lines > 0);
  if (lines < 0)
    lines = -lines;
  for (int i = 0; i < lines; i++)
    menuline_updown(up);
}

key_action_t menu_action(void) {
  ITEM *item = (kit.posted && kit.menu) ? current_item(kit.menu) : NULL;
  menuitem_s *data = item ? item_userptr(item) : NULL;
  if (!data)
    return ActionNone;
  switch (data->type) {
    case MI_TOOGLE:
      LOGMSG("%d", data->action);
      break;
    case MI_INTFORM:
    case MI_STRFORM:
      activate_form(item, data);
      break;
    default: break;
  }
  return data->action;
}

void menu_toggle_look(void) {
  if (kit.posted) {
    ITEM *curr = current_item(kit.menu);
    int ndx = curr ? item_index(curr) : -1;
    unpost_menu(kit.menu);
    kit.posted = false;
    init_menuitems();
    if (kit.item[0]) {
      int ec = set_menu_items(kit.menu, kit.item);
      if (ec == E_OK) {
        position_inside_menu(ndx);
        int ec = post_menu(kit.menu);
        if (ec == E_OK) {
          kit.posted = true;
          LOGMSG("%s", "menu reposted");
        } else
          LOGECFAIL("post_menu", ec);
      } else
        LOGECFAIL("set_menu_items", ec);
    } else
      LOGMSG("%s", "cannot reinit menu items");
  }
}

bool inside_menu(int x, int y) {
  return kit.wsp.win ? wenclose(kit.wsp.win, y, x) : false;
}

int mouse_select_n_toggle(void) {
  int rc = menu_driver(kit.menu, KEY_MOUSE);
  LOGMSG("menu_driver(KEY_MOUSE): rc=%d", rc);
  return (rc == E_UNKNOWN_COMMAND) ? ON_MOUSE_DBL_CLICK : 0;
}

void set_kit_attr(const short *bg, const int *x0, const int *y0) {
  if (bg)
    kit.bg = *bg;
  if (x0)
    kit.x0 = *x0;
  if (y0)
    kit.y0 = *y0;
}

int menu_form_key(int key) {
  int ndx = posted_form;
  if ((ndx < 0) || (ndx >= (int)ARRAY_LEN(kit.ff)))
    return key;
  FORM *form = kit.ff[ndx].form;
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
      ITEM *item = kit.item[ndx];
      miff_s *ff = &kit.ff[ndx];
      if (item)
        fin_form(ff, item);
      close_form(ff);
      menuitem_s *data = item ? item_userptr(item) : NULL;
      if (data && (data->action == ActionNone))
        menu_posteditaction(data->ndx);
      menu_toggle_look();
    } break;
    default:
      if (isprint(key))
        form_driver(form, key);
      else {
        rc = key;
        close_form(&kit.ff[ndx]);
      }
      break;
  }
  return rc;
}

//void cursor_at_form(void) {
//  int ndx = posted_form;
//  if ((ndx >= 0) && (ndx < (int)ARRAY_LEN(kit.ff))) {
//    FORM *form = kit.ff[ndx].form;
//    if (form)
//      pos_form_cursor(form);
//  }
//}

