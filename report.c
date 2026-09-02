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

#include <stdio.h>
#include <string.h>
#include <assert.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "report.h"
#include "common.h"
#include "aux.h"
#include "net.h"
#include "nls.h"

#ifdef ENABLE_DNS
#include "dns.h"
#endif

#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

#ifndef MAXNAME
#define MAXNAME 1025
#endif

#define BLANK_INDICATOR UNDERSCORE

enum INDENTS_N_DIVIDERS {
  IND_REP     = 4,
#ifdef OUTPUT_FORMAT_CSV
  DIV_CSV     = SEMICOLON,
#endif
#ifdef OUTPUT_FORMAT_JSON
  DIV_JSON    = COMMA,
  IND_JSON    = 2,
#endif
#ifdef OUTPUT_FORMAT_TOON
  DIV_TOON    = COMMA,
  IND_TOON    = 2,
#endif
#ifdef OUTPUT_FORMAT_XML
  DIV_XML     = COMMA,
  IND_XML     = 2,
#endif
};

static bool is_numstr(const char *str) {
  return (str && str[0]) ? !str[strspn(str, "0123456789")] : false;
}

static time_t started_at;
void report_started_at(void) { started_at = time(NULL); }

#if (__GNUC__ >= 8) || (__clang_major__ >= 6) || (__STDC_VERSION__ >= 202311L)
#define PRINT_DATETIME(fmt, ...) do {                           \
  char str[64] = {0};                                           \
  const char *date = datetime_c(started_at, sizeof(str), str);  \
  if (date && date[0]) printf((fmt) __VA_OPT__(,) __VA_ARGS__); \
} while(0)
#else
#define PRINT_DATETIME(fmt, ...) do {                           \
  char str[64] = {0};                                           \
  const char *date = datetime_c(started_at, sizeof(str), str);  \
  if (date && date[0]) printf((fmt), ##__VA_ARGS__);            \
} while(0)
#endif

#define RFMT  "%s%s%s"
#define RFMTQ "%s\"%s\"%s"
#define RKEY(str) key, (str), norm
#define RVAL(str) val, (str), norm
#define RKV   RFMT  ": " RFMT
#define RKVQ  RFMT  ": " RFMTQ
#define RKQV  RFMTQ ": " RFMT
#define RKQVQ RFMTQ ": " RFMTQ

static inline int print_str_width(const char str[], int width) NONNULL(1);
static inline int print_str_width(const char str[], int width) {
  return (width > 0) ? printf("%-*s", width, str) : fputs(str, stdout);
}

static void print_nameaddr(int at, int ndx, int width) {
  if (!width)
    return;
  t_ipaddr *addr = &IP_AT_NDX(at, ndx);
  if (addr_exist(addr)) {
#ifdef ENABLE_DNS
    const char *name = run_opts.dns ? dns_ptr_cache(at, ndx) : NULL;
    if (name) {
      if (run_opts.both) {
        char both[MAXNAME] = {0}, str[MAX_ADDRSTRLEN] = {0};
        snprinte(both, sizeof(both), "%s (%s)", name, addr2str(addr, sizeof(str), str));
        print_str_width(both, width);
      } else
        print_str_width(name, width);
    } else
#endif
    { char str[MAX_ADDRSTRLEN] = {0};
      print_str_width(addr2str(addr, sizeof(str), str), width); }
  } else
    print_str_width(UNKN_ITEM, width);
}

static int snprint_addr(char buff[], size_t size, uint at, uint ndx) {
  if (!buff || !size)
    return 0;
  int len = 0;
  t_ipaddr *addr = &IP_AT_NDX(at, ndx);
  if (addr_exist(addr)) {
#ifdef ENABLE_DNS
    const char *name = run_opts.dns ? dns_ptr_cache(at, ndx) : NULL;
    if (name) {
      if (run_opts.both) {
        char str[MAX_ADDRSTRLEN] = {0};
        len = snprinte(buff, size, "%s (%s)", name, addr2str(addr, sizeof(str), str));
      } else
        len = snprinte(buff, size, "%s",      name);
    } else
#endif
    { char str[MAX_ADDRSTRLEN] = {0};
      len = snprinte(buff, size, "%s", addr2str(addr, sizeof(str), str)); }
  } else
    len = snprinte(buff, size, "%s", UNKN_ITEM);
  return (len < 0) ? 0 : len;
}

#ifdef WITH_MPLS
static void print_mpls(const mpls_data_t *mpls) NONNULL(1);
static void print_mpls(const mpls_data_t *mpls) {
  char buff[64] = {0};
  for (int i = 0; i < mpls->n; i++)
    puts(mpls2str(&mpls->label[i], sizeof(buff), buff, INDENT_NUMB));
}
#endif

static int longest_hopname(int longest) {
  char buff[MAXNAME] = {0};
  int nmax = net_max();
  for (int at = net_min(); at < nmax; at++) {
    for (uint i = 0; i < MAXPATH; i++) {
      int len = snprint_addr(buff, sizeof(buff), at, i);
      if (len > longest)
        longest = len;
    }
  }
  return longest;
}

#ifdef ENABLE_DNS
void backresolv_lookups(void) {
  if (run_opts.dns) {
    int max = net_max();
    for (int at = net_min(); at < max; at++) {
      if (addr_exist(&CURRENT_IP(at))) {
        dns_ptr_lookup(at, host[at].current);
        for (int ndx = 0; ndx < MAXPATH; ndx++) { // multipath
          if (ndx != host[at].current) { // not looked up yet
            if (!addr_exist(&IP_AT_NDX(at, ndx)))
              break;
            dns_ptr_lookup(at, ndx);
          }
        }
      }
    }
  }
}
#endif

static void foreach_stat(int at, void (*body)(int at, const t_stat *stat), char fin) NONNULL(2);
static void foreach_stat(int at, void (*body)(int at, const t_stat *stat), char fin) {
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (!stat)
      break;
    body(at, stat);
  }
  if (fin)
    putchar(fin);
}

#ifdef WITH_IPINFO
static void report_info(int infolen, const char info[]) NONNULL(2);
static void report_info(int infolen, const char info[]) {
  if (!infolen)
    return;
  if (info[0]) { // note: utf8 length
    int len = infolen - ustrnlen(info, infolen) + 1;
    printf("%s%*s", info, (len < 0) ? 0 : len, "");
  } else
    printf("%*s", infolen + 1, "");
}
#define REPORT_INFO(a, b) report_info(a, b)
#else
#define REPORT_INFO(a, b) NOOP
#endif

static void report_headstat(int at UNUSED, const t_stat *stat) {
  if (stat->name)
    printf("%*s%s", (stat->min > stat->len) ? (stat->min - stat->len) : 1, "", stat->name);
  else
    printf("%*s", stat->min, "");
}

static void report_print_header(int hostlen, int infolen) {
  printf("%*s", IND_REP, "");
  // left
  { char info[NAMELEN] = {0};
    ipinfo_head_fix(sizeof(info), info);
    REPORT_INFO(infolen, info); }
  fputs(HOST_STR, stdout);
  int len = hostlen - ustrnlen(HOST_STR, hostlen);
  if (len > 0)
    printf("%*s", len, "");
  // right
  foreach_stat(0, report_headstat, '\n');
}

static void report_bodystat(int at, const t_stat *stat) NONNULL(2);
static void report_bodystat(int at, const t_stat *stat) {
  const char *str = net_elem(at, stat->key);
  if (str) {
    uint len = strnlen(str, stat->min);
    printf("%*s%s", (stat->min > len) ? (stat->min - len) : 1, "", str);
  } else
    printf("%*s", stat->min, "");
}

static void report_print_rest(int at, int hostlen, int infolen) {
  for (int i = 0; i < MAXPATH; i++) {
    if (i == host[at].current)
      continue; // because already printed
    if (!addr_exist(&IP_AT_NDX(at, i)))
      break; // done
    printf("%*s", IND_REP, "");
    { char info[NAMELEN] = {0};
      ipinfo_data_fix(sizeof(info), info, at, i);
      REPORT_INFO(infolen, info); }
    print_nameaddr(at, i, hostlen);
    putchar('\n');
#ifdef WITH_MPLS
    if (run_opts.mpls)
      print_mpls(&MPLS_AT_NDX(at, i));
#endif
  }
}

static void report_print_body(int at, int hostlen, int infolen) {
  // body: left
  printf("%s" AT_FMT "%s ", TTY_BOLD, at + 1, TTY_NORM);
  int netcolor = istty ? net_color(at) : 0;
  const char *color = (netcolor > 0) ? ((netcolor > 1) ? ANSI_RED : ANSI_YELLOW) : NULL;
  if (color)
    fputs(color, stdout);
  { char info[NAMELEN] = {0};
    ipinfo_data_fix(sizeof(info), info, at, host[at].current);
    const char *keep = color;
    if (istty && (info[0] == '?'))
      fputs(ANSI_RED, stdout);
    REPORT_INFO(infolen, info);
    if (istty)
      fputs(keep ? keep : ANSI_NORM, stdout);
  }
  print_nameaddr(at, host[at].current, hostlen);
  // body: right
  foreach_stat(at, report_bodystat, '\n');
#ifdef WITH_MPLS
  if (run_opts.mpls)
    print_mpls(&CURRENT_MPLS(at));
#endif
  // multipath, mpls, etc.
  report_print_rest(at, hostlen, infolen);
  if (color)
    fputs(ANSI_NORM, stdout);
}

void report_close(bool next, bool with_header) {
  if (next)
    putchar('\n');
  if (with_header) {
    PRINT_DATETIME("[%s] ", date);
    printf("%s: %s", srchost, PACKAGE_NAME);
    if (mtr_args[0])
      printf(" %s", mtr_args);
    printf(" %s\n", dsthost);
  }
  int hostlen = longest_hopname(ustrnlen(HOST_STR, MAXNAME)) + 1;
  int infolen =
#ifdef WITH_IPINFO
    IPINFOED ? ipinfo_width() :
#endif
    0;
  fputs(TTY_BOLD, stdout);
  report_print_header(hostlen, infolen);
  fputs(TTY_NORM, stdout);
  int max = net_max();
  for (int at = net_min(); at < max; at++)
    report_print_body(at, hostlen, infolen);
  if (tgterr_txt[0])
    printf(RKV "\n", TTY_BLUE, ERROR_STR, TTY_NORM, TTY_RED, tgterr_txt, TTY_NORM);
}


#ifdef OUTPUT_FORMAT_XML
#define XTAG(str) tag, (str), norm
#define XKVQ RFMT "=" RFMTQ
void xml_head(void) {
  const char *tag  = TTY_BLUE;
  const char *key  = TTY_CYAN;
  const char *val  = TTY_GREEN;
  const char *norm = TTY_NORM;
  printf("<?" RFMT " " XKVQ "?>\n", XTAG("xml"), RKEY("version"), RVAL("1.0"));
  printf("<" RFMT " " XKVQ, XTAG(PACKAGE_NAME), RKEY(SOURCE_STR), RVAL(srchost));
  PRINT_DATETIME(" " XKVQ, RKEY(DATETIME_STR), RVAL(date));
  puts(">");
}
//
void xml_tail(void) {
  const char *tag  = TTY_BLUE;
  const char *norm = TTY_NORM;
  printf("</" RFMT ">\n", XTAG(PACKAGE_NAME));
}
//
static void xml_statline(int at, const t_stat *stat) {
  const char *str = net_elem(at, stat->key);
  if (str) {
    const char *tag  = TTY_BLUE;
    const char *norm = TTY_NORM;
    int netcolor = istty ? net_color(at) : 0;
    const char *val  = (netcolor > 0) ? ((netcolor > 1) ? TTY_RED : TTY_YELLOW) : "";
    printf("%*s<" RFMT ">" RFMT "</" RFMT ">\n", IND_XML * 3, "",
      XTAG(stat->name), RVAL(str), XTAG(stat->name));
  }
}
//
void xml_close(void) {
  const char *tag  = TTY_BLUE;
  const char *key  = TTY_CYAN;
  const char *val  = TTY_GREEN;
  const char *norm = TTY_NORM;
  if (mtr_optc > 0) {
    printf("%*s<" RFMT, IND_XML, "", XTAG(ARGS_STR));
    for (uint i = 0; i < mtr_optc; i++) {
      printf(" %s%s%d%s=" RFMTQ, key, "ARG", i + 1, norm, RVAL(mtr_optv[i]));
    }
    printf("></" RFMT ">\n", XTAG(ARGS_STR));
  }
  printf("%*s<" RFMT " " XKVQ ">\n", IND_XML, "", XTAG(TARGET_STR), RKEY(HOST_STR), RVAL(dsthost));
  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    int netcolor = istty ? net_color(at) : 0;
    const char *val = (netcolor > 0) ? ((netcolor > 1) ? TTY_RED : TTY_YELLOW) : TTY_GREEN;
    printf("%*s<" RFMT, IND_XML * 2, "", XTAG(HOP_STR));
    printf(" " RFMT "=" "%s\"%d\"%s", RKEY(PAR_TTL_STR), RVAL(at + 1));
    printf(" " RFMT "=%s\"", RKEY(HOST_STR), val);
    print_nameaddr(at, host[at].current, -1);
    printf("\"%s>\n", norm);
    foreach_stat(at, xml_statline, 0);
#ifdef WITH_IPINFO
    if (IPINFOED) {
      printf("%*s<" RFMT, IND_XML * 3, "", XTAG(IPINFO_STR));
      const char *jkey[II_REC_ARR_LEN] = {0};
      const char *jval[II_REC_ARR_LEN] = {0};
      uint n = ipinfo_datalist(II_REC_ARR_LEN, jkey, jval, at, host[at].current);
      const char *keep = val;
      for (uint i = 0; (i < n) && (i < II_REC_ARR_LEN) && jkey[i] && jval[i]; i++) {
        if (jval[i][0] == '?')
          val = TTY_RED;
        printf(" " XKVQ, RKEY(jkey[i]), RVAL(jval[i]));
        val = keep;
      }
      printf("></" RFMT ">\n", XTAG(IPINFO_STR));
    }
#endif
    printf("%*s</" RFMT ">\n", IND_XML * 2, "", XTAG(HOP_STR));
  }
  printf("%*s</" RFMT ">\n", IND_XML, "", XTAG(TARGET_STR));
  if (tgterr_txt[0])
    printf("%*s<" RFMT ">" RFMT "</" RFMT ">\n", IND_XML, "",
      XTAG(ERROR_STR), TTY_RED, tgterr_txt, TTY_NORM, XTAG(ERROR_STR));
}
#undef XTAG
#undef XKVQ
#endif /*OUTPUT_FORMAT_XML*/

// json
//
#ifdef OUTPUT_FORMAT_JSON
#define JDN printf("%c\n", DIV_JSON)
#define JIN printf("%*s", jindent, "")
#define JDNI do {JDN; JIN;} while (0)
//
static int jindent;
//
void json_head(void) {
  const char *key  = TTY_BLUE;
  const char *val  = TTY_GREEN;
  const char *norm = TTY_NORM;
  puts("{");
  jindent = IND_JSON;
  // source
  JIN; printf(RKQVQ, RKEY(SOURCE_STR), RVAL(srchost));
  // datetime
  JDNI; PRINT_DATETIME(RKQVQ, RKEY(_(DATETIME_STR)), RVAL(date));
  if (mtr_optc > 0) {
    // arguments in one line
    JDNI; printf(RFMTQ ": [", RKEY(ARGS_STR));
    for (uint i = 0; i < mtr_optc; i++) {
      if (i)
        printf("%c ", DIV_JSON);
      printf(RFMTQ, RVAL(mtr_optv[i]));
    }
    putchar(']');
  }
  // targets
  JDNI; printf(RFMTQ ": [\n", RKEY(TARGETS_STR));
  jindent += IND_JSON;
}
//
void json_tail(void) {
  putchar('\n');
  jindent -= IND_JSON;
  JIN; putchar(']');
  if (tgterr_txt[0]) {
    const char *key  = TTY_BLUE;
    const char *val  = TTY_RED;
    const char *norm = TTY_NORM;
    JDNI; printf(RKQVQ, RKEY(ERROR_STR), RVAL(tgterr_txt));
  }
  putchar('\n');
  jindent -= IND_JSON;
  JIN; puts("}");
}
//
static void json_statline(int at, const t_stat *stat) {
  const char *elem = net_elem(at, stat->key);
  int len = elem ? strnlen(elem, NETELEM_MAXLEN) : 0;
  if (len > 0) {
    const char *norm = TTY_NORM;
    const char *key  = TTY_BLUE;
    int netcolor = istty ? net_color(at) : 0;
    const char *val  = (netcolor > 0) ? ((netcolor > 1) ? TTY_RED : TTY_YELLOW) : TTY_GREEN;
    JDNI; printf(RFMTQ ": ", RKEY(stat->name));
    printf(is_numstr(elem) ? RFMT : RFMTQ, RVAL(elem));
  }
}
//
void json_close(bool next) {
  const char *key  = TTY_BLUE;
  const char *val  = TTY_GREEN;
  const char *norm = TTY_NORM;
  if (next)
    JDN;
  JIN; puts("{");
  jindent += IND_JSON;
  JIN;  printf(RKQVQ, RKEY(_(TARGET_STR)), RVAL(dsthost));
  JDNI; printf(RFMTQ ": [\n", RKEY(_(DATA_STR)));
  jindent += IND_JSON;
  int min = net_min(), max = net_max();
  if (min < max) {
    for (int at = min; at < max; at++) {
      int netcolor = istty ? net_color(at) : 0;
      const char *val = (netcolor > 0) ? ((netcolor > 1) ? TTY_RED : TTY_YELLOW) : TTY_GREEN;
      if (at != min)
        JDN;
      JIN; puts("{");
      jindent += IND_JSON;
      JIN;  printf(RFMTQ ": ", RKEY(_(HOP_STR)));
      printf("%s%d%s", RVAL(at + 1));
      JDNI; printf(RFMTQ ": ", RKEY(_(HOST_STR)));
      printf("%s\"", val);
      print_nameaddr(at, host[at].current, -1);
      printf("\"%s", norm);
      foreach_stat(at, json_statline, 0);
#ifdef WITH_IPINFO
      if (IPINFOED) {
        JDNI; printf(RFMTQ ": [", RKEY(_(IPINFO_STR)));
        const char *jkey[II_REC_ARR_LEN] = {0};
        const char *jval[II_REC_ARR_LEN] = {0};
        uint n = ipinfo_datalist(II_REC_ARR_LEN, jkey, jval, at, host[at].current);
        const char *keep = val;
        for (uint i = 0; (i < n) && (i < II_REC_ARR_LEN) && jkey[i] && jval[i]; i++) {
          if (i)
            printf("%c ", DIV_JSON);
          if (jval[i][0] == '?')
            val = TTY_RED;
          printf("{" RKQVQ "}", RKEY(jkey[i]), RVAL(jval[i]));
          val = keep;
        }
        putchar(']');
      }
#endif
      putchar('\n');
      jindent -= IND_JSON;
      JIN; putchar('}');
    }
    putchar('\n');
  }
  jindent -= IND_JSON;
  JIN; putchar(']');
  putchar('\n');
  jindent -= IND_JSON;
  JIN; putchar('}');
}
#undef JDN
#undef JIN
#undef JDNI
#endif /*OUTPUT_FORMAT_JSON*/

// toon
//
#ifdef OUTPUT_FORMAT_TOON
void toon_head(uint n_targets) {
  const char *key  = TTY_BLUE;
  const char *val  = TTY_GREEN;
  const char *norm = TTY_NORM;
  PRINT_DATETIME(RKVQ "\n", RKEY(_(DATETIME_STR)), RVAL(date));
  printf(RKVQ "\n", RKEY(SOURCE_STR), RVAL(srchost));
  if (mtr_optc > 0) {
    printf(RFMT "[%d]:", RKEY(ARGS_STR), mtr_optc);
    for (uint i = 0; i < mtr_optc; i++) {
      if (i)
        putchar(DIV_TOON);
      printf(" " RFMTQ, RVAL(mtr_optv[i]));
    }
    putchar('\n');
  }
  printf(RFMT "[%d]:\n", RKEY(TARGETS_STR), n_targets);
}
//
static void toon_headline(int at UNUSED, const t_stat *stat) {
  if (stat->key != BLANK_INDICATOR) {
    const char *val  = TTY_GREEN;
    const char *norm = TTY_NORM;
    printf("%c %s" RFMTQ, DIV_TOON, TTY_BOLD, RVAL(stat->name));
  }
}
//
static void toon_statline(int at, const t_stat *stat) {
  const char *elem = net_elem(at, stat->key);
  if (elem) {
    int len = strnlen(elem, NETELEM_MAXLEN);
    if (len > 0) {
      printf("%c ", DIV_TOON);
      int netcolor = istty ? net_color(at) : 0;
      const char *val = (netcolor > 0) ? ((netcolor > 1) ? TTY_RED : TTY_YELLOW) : TTY_GREEN;
      const char *norm = TTY_NORM;
      printf(is_numstr(elem) ? RFMT : RFMTQ, RVAL(elem));
    }
  }
}
//
void toon_close(void) {
  const char *key  = TTY_BLUE;
  const char *val  = TTY_GREEN;
  const char *norm = TTY_NORM;
  printf("%*s- " RKVQ "\n", IND_TOON, "", RKEY(_(TARGET_STR)), RVAL(dsthost));
  int min = net_min(), max = net_max();
  printf("%*s" RFMT "[%d]", IND_TOON * 2, "", RKEY(_(DATA_STR)), max - min);
  printf("{%s"   RFMTQ,           TTY_BOLD, RVAL(_(HOP_STR)));
  printf("%c %s" RFMTQ, DIV_TOON, TTY_BOLD, RVAL(_(HOST_STR)));
  foreach_stat(0, toon_headline, 0);
#ifdef WITH_IPINFO
  if (IPINFOED) {
    const char *nkey[II_REC_ARR_LEN] = {0};
    uint n = ipinfo_datalist(II_REC_ARR_LEN, nkey, NULL, 0, host[0].current);
    for (uint i = 0; (i < n) && (i < II_REC_ARR_LEN) && nkey[i]; i++)
      printf("%c %s" RFMTQ, DIV_TOON, TTY_BOLD, RVAL(nkey[i]));
  }
#endif
  puts("}:");
  for (int at = min; at < max; at++) {
    int netcolor = istty ? net_color(at) : 0;
    val = (netcolor > 0) ? ((netcolor > 1) ? TTY_RED : TTY_YELLOW) : TTY_GREEN;
    printf("%*s%s%d%s", IND_TOON * 3, "", RVAL(at + 1)); // hop
    printf("%c %s\"", DIV_TOON, val);
    print_nameaddr(at, host[at].current, -1);  // host
    printf("\"%s", norm);
    foreach_stat(at, toon_statline, 0);
#ifdef WITH_IPINFO
    if (IPINFOED) {
      const char *nval[II_REC_ARR_LEN] = {0};
      uint n = ipinfo_datalist(II_REC_ARR_LEN, NULL, nval, at, host[at].current);
      const char *keep = val;
      for (uint i = 0; (i < n) && (i < II_REC_ARR_LEN) && nval[i]; i++) {
        if (nval[i][0] == '?')
          val = TTY_RED;
        printf("%c " RFMTQ, DIV_TOON, RVAL(nval[i]));
        val = keep;
      }
    }
#endif
    putchar('\n');
  }
  if (tgterr_txt[0]) {
    const char *val = TTY_RED;
    printf("%*s" RKVQ "\n", IND_TOON * 2, "", RKEY(ERROR_STR), RVAL(tgterr_txt));
  }
}
#endif /*OUTPUT_FORMAT_TOON*/

#ifdef OUTPUT_FORMAT_CSV
#define CKVQ RFMT "%c" RFMTQ
#define CKEYVAL(k, v) RKEY(k), DIV_CSV, RVAL(v)
void csv_head(void) {
  const char *key  = TTY_BLUE;
  const char *val  = TTY_GREEN;
  const char *norm = TTY_NORM;
  PRINT_DATETIME(CKVQ "\n", CKEYVAL(_(DATETIME_STR), date));
  printf(CKVQ "\n", CKEYVAL(SOURCE_STR, srchost));
  if (mtr_optc > 0) {
    printf(RFMT, RKEY(ARGS_STR));
    for (uint i = 0; i < mtr_optc; i++) {
      printf("%c" RFMTQ, DIV_CSV, RVAL(mtr_optv[i]));
    }
    putchar('\n');
  }
}
//
static void csv_headline(int at UNUSED, const t_stat *stat) {
  if (stat->key != BLANK_INDICATOR) {
    const char *val  = TTY_GREEN;
    const char *norm = TTY_NORM;
    printf("%c%s" RFMTQ, DIV_CSV, TTY_BOLD, RVAL(stat->name ? stat->name : ""));
  }
}
//
static void csv_bodyline(int at, const t_stat *stat) {
  if (stat->key != BLANK_INDICATOR) {
    const char *str = net_elem(at, stat->key);
    int netcolor = istty ? net_color(at) : 0;
    const char *val = (netcolor > 0) ? ((netcolor > 1) ? TTY_RED : TTY_YELLOW) : "";
    const char *norm = TTY_NORM;
    printf("%c" RFMT, DIV_CSV, RVAL(str ? str : ""));
  }
}
//
static inline void csv_body(int at) {
  int netcolor = istty ? net_color(at) : 0;
  const char *val = (netcolor > 0) ? ((netcolor > 1) ? TTY_RED : TTY_YELLOW) : "";
  const char *norm = TTY_NORM;
  printf("%s%d%s%c%s\"", RVAL(at + 1), DIV_CSV, val);
  print_nameaddr(at, host[at].current, -1);
  printf("\"%s", norm);
  foreach_stat(at, csv_bodyline, DIV_CSV);
#ifdef WITH_IPINFO
  if (IPINFOED) {
    const char *nval[II_REC_ARR_LEN] = {0};
    uint n = ipinfo_datalist(II_REC_ARR_LEN, NULL, nval, at, host[at].current);
    const char *keep = val;
    for (uint i = 0; (i < n) && (i < II_REC_ARR_LEN) && nval[i]; i++) {
      if (i)
        putchar(DIV_CSV);
      if (nval[i][0] == '?')
        val = TTY_RED;
      printf(RFMTQ, RVAL(nval[i]));
      val = keep;
    }
  }
#endif
  putchar('\n');
}
//
void csv_close(void) {
  printf("%c\n", DIV_CSV);
  const char *key  = TTY_BLUE;
  const char *val  = TTY_GREEN;
  const char *norm = TTY_NORM;
  printf(CKVQ "\n", CKEYVAL(TARGET_STR, dsthost));
  printf(  "%s" RFMTQ,          TTY_BOLD, RVAL(HOP_STR));
  printf("%c%s" RFMTQ, DIV_CSV, TTY_BOLD, RVAL(HOST_STR));
  foreach_stat(0, csv_headline, 0);
#ifdef WITH_IPINFO
  if (IPINFOED) {
    const char *nkey[II_REC_ARR_LEN] = {0};
    uint n = ipinfo_datalist(II_REC_ARR_LEN, nkey, NULL, 0, host[0].current);
    for (uint i = 0; (i < n) && (i < II_REC_ARR_LEN) && nkey[i]; i++)
      printf("%c%s" RFMTQ, DIV_CSV, TTY_BOLD, RVAL(nkey[i]));
  }
#endif
  putchar('\n');
  int max = net_max();
  for (int at = net_min(); at < max; at++)
    csv_body(at);
  if (tgterr_txt[0]) {
    const char *val = TTY_RED;
    printf("%c\n" RFMT "%c" RFMTQ "\n", DIV_CSV, RVAL(ERROR_STR), DIV_CSV, RVAL(tgterr_txt));
  }
}
#undef CKVQ
#undef CKEYVAL
#endif /*OUTPUT_FORMAT_CSV*/

#ifdef OUTPUT_FORMAT_RAW
void raw_rawping(int at, int usec) {
#ifdef ENABLE_DNS
  static bool raw_printed_name[MAXHOST];
  if (!raw_printed_name[at]) {
    const char *name = dns_ptr_lookup(at, host[at].current);
    if (name) {
      printf("d %d %s\n", at, name);
      if (!raw_printed_name[at])
        raw_printed_name[at] = true;
    }
  }
#endif
  LENVALMIL((double)usec / MIL);
  printf("p %d %.*f\n", at, _l, _v); // ping in msec
  fflush(stdout);
}
//
void raw_rawhost(int at, int ndx) {
  char str[MAX_ADDRSTRLEN] = {0};
  printf("h %d %s\n", at, addr2str(&IP_AT_NDX(at, ndx), sizeof(str), str));
  fflush(stdout);
}
#endif /*OUTPUT_FORMAT_RAW*/

