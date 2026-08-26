/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <string.h>

#if defined(LOG_TUI) && !defined(LOGMOD)
#define LOGMOD
#include <errno.h>
#endif
#if !defined(LOG_TUI) && defined(LOGMOD)
#undef LOGMOD
#endif

#include "menupan.h"
#include "aux.h"
#include "nls.h"

#define ROUNDED_CORNERS true

bool menuactive;
short menu_bg = -1;

enum {
#ifdef ENABLE_DNS
  MENU_ITEM_DNS,
#endif
  MENU_ITEM_JTTR,
#ifdef WITH_IPINFO
  MENU_ITEM_ASN,
#endif
#ifdef WITH_MPLS
  MENU_ITEM_MPLS,
#endif
  MENU_ITEMS
};

static ITEM* menuitem[MENU_ITEMS + 1];
static int   menuitem_maxlen;
static MENU   *menuset;
static PANEL  *menupan;
static WINDOW *menuwin;
static WINDOW *menusub;
static bool menu_posted;
static int menu_x0 = 0, menu_y0 = 1;

#define LOG_FAILED_ERRNO ": failed with errno="
#define LOG_FAILED_FN(fn) LOGMSG("%s(): failed", (fn));

#if defined(TUIWIDE) && defined (WITH_UNICODE)
#define MENUSTRW(str) utf_compat ? _(str) : (str)
#else
#define MENUSTRW(str) (str)
#endif

typedef struct menuline_s {
  key_action_t action;
  char buff[NAMELEN];
} menuline_s;

typedef struct optname_s {
  const char *name;
  int len; // name length in unicode characters
  bool value;
} optname_s;

static void init_menuitems(void) {
  static menuline_s menuline[MENU_ITEMS] = {
#ifdef ENABLE_DNS
    [MENU_ITEM_DNS]  = {.action = ActionDNS },
#endif
    [MENU_ITEM_JTTR] = {.action = ActionJttr},
#ifdef WITH_IPINFO
    [MENU_ITEM_ASN]  = {.action = ActionASN },
#endif
#ifdef WITH_MPLS
    [MENU_ITEM_MPLS] = {.action = ActionMPLS},
#endif
  };
  //
  optname_s optname[ARRAY_LEN(menuline)] = {
#ifdef ENABLE_DNS
    [MENU_ITEM_DNS]  = {.name = MENUSTRW(_DNS_STR),    .value = run_opts.dns },
#endif
    [MENU_ITEM_JTTR] = {.name = MENUSTRW(_JITTER_STR), .value = run_opts.jttr},
#ifdef WITH_IPINFO
    [MENU_ITEM_ASN]  = {.name = MENUSTRW(_ASN_STR),    .value = run_opts.asn },
#endif
#ifdef WITH_MPLS
    [MENU_ITEM_MPLS] = {.name = MENUSTRW(_MPLS_STR),   .value = run_opts.mpls},
#endif
  };
  if (!menuitem_maxlen) // once
    for (uint i = 0; i < ARRAY_LEN(optname); i++)
      if (optname[i].name) {
       int len = ustrnlen(optname[i].name, NAMELEN);
       if (len > 0) {
         optname[i].len = len;
         if (len > menuitem_maxlen)
           menuitem_maxlen = len;
       }
     }
  //
  for (uint i = 0; i < ARRAY_LEN(optname); i++) {
    if (menuitem[i])
      free_item(menuitem[i]);
    const char *name = optname[i].name;
    if (name) {
      const bool val = optname[i].value;
      int pad = (optname[i].len > 0) ? (menuitem_maxlen - optname[i].len) : -1;
      const char *mark =
#if defined(TUIWIDE) && defined(WITH_UNICODE)
        utf_compat ? (val ? /*"☑"*//*"🗹 "*//*"✔"*/" ✓ " : /*"☐"*/" ◻ ") :
#endif
                     (val ? " + " : " - ");
      char *buff = menuline[i].buff;
      int rc = snprinte(buff, sizeof(menuline->buff),
        " %s%*s ", name, (pad > 0) ? pad : 0, ""); // utf8-compat padding
      menuitem[i] = new_item(((rc > 0) && *buff) ? buff : name, mark);
      if (menuitem[i] && menuline[i].action)
        set_item_userptr(menuitem[i], &menuline[i].action);
    }
    if (!menuitem[i]) {
      LOGMSG("new_item(#%u, %s)%s%d", i, name, LOG_FAILED_ERRNO, errno);
      break;
    }
    LOGMSG("menuitem[%u]: %s", i, name);
  }
}

static void prepare_menu(void) {
  if (!menuitem[0]) {
    init_menuitems();
    if (!menuitem[0]) {
      LOGMSG("%s", "no items");
      return;
    }
  }
  if (!menuset) {
    menuset = new_menu(menuitem);
    if (!menuset) {
      LOGMSG("new_menu()%s%d", LOG_FAILED_ERRNO, errno);
      return;
    }
    set_menu_mark(menuset, NULL);
    if ((menu_bg >=0) && (set_menu_back(menuset, COLOR_PAIR(menu_bg)) != E_OK))
      LOGMSG("set_menu_back(pair=%d)%s%d", menu_bg, LOG_FAILED_ERRNO, errno);
  }
  int h = MENU_ITEMS;
  int w = (menuitem_maxlen > 0) ? (menuitem_maxlen + 6/*pads+toggle*/) : 20;
  int frame =
#ifdef WITH_UNICODE
    utf_compat ? 1 :
#endif
  0;
  if (!menuwin) {
    menuwin = newwin(h + 2 * frame, w + 2 * frame, menu_y0, menu_x0);
    if (!menuwin) {
      LOG_FAILED_FN("newwin");
      return;
    }
    keypad(menuwin, TRUE);
    if (menu_bg >= 0)
      wbkgd(menuwin, COLOR_PAIR(menu_bg));
    if (frame) {
#ifdef ROUNDED_CORNERS
      cchar_t tl = {0}, tr = {0}, bl = {0}, br = {0};
      setcchar(&tl, L"╭", A_NORMAL, 0, NULL);
      setcchar(&tr, L"╮", A_NORMAL, 0, NULL);
      setcchar(&bl, L"╰", A_NORMAL, 0, NULL);
      setcchar(&br, L"╯", A_NORMAL, 0, NULL);
      wborder_set(menuwin, NULL, NULL, NULL, NULL, &tl, &tr, &bl, &br);
#else
      box(menuwin, 0, 0);
#endif
   }
  }
  if (!menusub) {
    menusub = derwin(menuwin, h, w, frame, frame);
    if (!menusub) {
      LOG_FAILED_FN("derwin");
      return;
    }
  }
  if (!menupan) {
    menupan = new_panel(menuwin);
    if (!menupan) {
      LOG_FAILED_FN("new_panel");
      return;
    }
    if (top_panel(menupan) != OK)
      LOG_FAILED_FN("top_panel");
  }
  if ((menu_win(menuset) != menuwin) && (set_menu_win(menuset, menuwin) != E_OK)) {
    LOG_FAILED_FN("set_menu_win");
    return;
  }
  if ((menu_sub(menuset) != menusub) && (set_menu_sub(menuset, menusub) != E_OK)) {
    LOG_FAILED_FN("set_menu_sub");
    return;
  }
  if ((menu_win(menuset) != menuwin) &&
     ((set_menu_win(menuset, menuwin) != E_OK) ||
      (set_menu_sub(menuset, menusub) != E_OK)))
  {
    LOG_FAILED_FN("set_menu_win/set_menu_sub");
    free_menu(menuset);
    menuset = NULL;
    return;
  }
  //
  if (!menu_posted)
    menu_posted = (post_menu(menuset) == E_OK);
}

static void menu_showhide(void) {
  LOGMSG("%s", menuactive ? "hide" : "show");
  menuactive ? hide_panel(menupan) : show_panel(menupan);
  menuactive = !menuactive;
  update_panels();
  doupdate();
}

static void restore_cursor_state(int was) {
  int count = (menuset && (was >= 0)) ? item_count(menuset) : -1;
  if (count > 0) {
    ITEM **list = menu_items(menuset);
    if (list) for (int i = 0; i < count; i++) {
      ITEM *item = list[i];
      int now = item ? item_index(item) : -1;
      if (now == was) {
        set_current_item(menuset, item);
        LOGMSG("restore cursor at position #%d", now);
        return;
      }
    }
  }
  LOGMSG("%s", "cursor state isn't restored");
}


//
// global

void free_menupan(void) {
  LOGMSG("%s", "free menu stuff");
  if (menuset) {
    if (menu_posted) {
      unpost_menu(menuset);
      menu_posted = false;
    }
    free_menu(menuset);
    menuset = NULL;
  }
  for (uint i = 0; i < ARRAY_LEN(menuitem); i++)
    if (menuitem[i]) {
      free_item(menuitem[i]);
      menuitem[i] = NULL;
    }
  if (menupan) {
    del_panel(menupan);
    menupan = NULL;
  }
  if (menusub) {
    delwin(menusub);
    menusub = NULL;
  }
  if (menuwin) {
    delwin(menuwin);
    menuwin = NULL;
  }
  menuactive = false;
}

void menu_handler(WINDOW *_win UNUSED) {
  if (menu_posted)
    menu_showhide();
  else {
    prepare_menu();
    if (menu_posted)
      menu_showhide();
  }
}

void menu_updown(bool up) {
  menu_driver(menuset, up ? REQ_UP_ITEM : REQ_DOWN_ITEM);
}

key_action_t menu_action(void) {
  ITEM *item = (menu_posted && menuset) ? current_item(menuset) : NULL;
  key_action_t *act = item ? item_userptr(item) : NULL;
  return act ? *act : ActionNone;
}

void menu_toggle_look(void) {
  if (menuactive && menu_posted) {
    ITEM* copy[ARRAY_LEN(menuitem)];
    memcpy(copy, menuitem, sizeof(copy));
    init_menuitems();
    if (menuitem[0]) {
      ITEM *curr = current_item(menuset);
      int ndx = curr ? item_index(curr) : -1;
      if (unpost_menu(menuset) == E_OK) {
        menu_posted = false;
        if (set_menu_items(menuset, menuitem) == E_OK) {
          restore_cursor_state(ndx);
          if (post_menu(menuset) == E_OK) {
            menu_posted = true;
            LOGMSG("%s", "menu reposted");
          } else
            LOGMSG("unpost_menu()%s%d", LOG_FAILED_ERRNO, errno);
        } else
          LOGMSG("set_menu_items()%s%d", LOG_FAILED_ERRNO, errno);
      } else
          LOGMSG("unpost_menu()%s%d", LOG_FAILED_ERRNO, errno);
    } else {
      memcpy(menuitem, copy, sizeof(menuitem));
      LOGMSG("%s", "cannot reinit menu items");
    }
  }
}

bool inside_menu(int x, int y) {
  return menuwin ? (
    (getbegx(menuwin) <= x) && (x <= (getmaxx(menuwin) - 1)) &&
    (getbegy(menuwin) <= y) && (y <= getmaxy(menuwin))
  ) : false;
}

