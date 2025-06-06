
cmake_minimum_required(VERSION 3.12)
project(mtr085 C)
set(NAME "mtr")
set(VERSION "0.85")
string(REPLACE "." "" NAME_SUFFIX "${VERSION}")
set(PACKAGE_NAME "${NAME}${NAME_SUFFIX}")

if(EXISTS .git)
  find_package(Git)
  if(GIT_EXECUTABLE)
    execute_process(
      COMMAND ${GIT_EXECUTABLE} rev-list --count 97af563..HEAD
      OUTPUT_STRIP_TRAILING_WHITESPACE
      RESULT_VARIABLE ERROR_CODE
      OUTPUT_VARIABLE GITREV
    )
  endif()
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # compile_commands.json
include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)

set(MAN_PAGE "${NAME}.8")
set(MAN_PATH "${CMAKE_BINARY_DIR}/man8")
set(MANUAL "${MAN_PATH}/${MAN_PAGE}")

# set target
add_executable("${NAME}" "${NAME}.c" aux.c display.c net.c poll.c report.c)
target_include_directories("${NAME}" PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_options("${NAME}" PRIVATE -Wall -Wextra -Wpedantic)

# options
set(OPTION_LIST)
option(CAP     "With linux capabilities"  ON)
option(CURSES  "[N]Curses built version"  ON)
option(UNICODE "Unicode support"          ON)
option(NLS     "I18n support"             ON)
option(DNS     "DNS support"              ON)
option(IPINFO  "IPINFO support"           ON)
option(SPLIT   "SPLIT mode support"       ON)
option(IPV6    "IPv6 support"             ON)
option(MPLS    "MPLS decoding"            ON)
set(OPTION_OUTFMT)
option(OUTRAW  "Output raw format"       OFF)
option(OUTTXT  "Output text format"       ON)
option(OUTCSV  "Output csv format"        ON)
option(OUTJSON "Output json format"       ON)
option(OUTXML  "Output xml format"        ON)
set(OPTION_DEBLOG)
option(DEBPOLL   "Debug poll syslog"     OFF)
option(DEBNET    "Debug net syslog"      OFF)
option(DEBDNS    "Debug dns syslog"      OFF)
option(DEBIPINFO "Debug ipinfo syslog"   OFF)
set(MAN_EXCL)
option(SBIN "Install to sbin"            OFF)

if(CAP OR CURSES)
  find_package(PkgConfig REQUIRED)
endif()

if(CAP)
  pkg_check_modules(CAP REQUIRED IMPORTED_TARGET libcap)
  target_link_libraries("${NAME}" PRIVATE PkgConfig::CAP)
  list(APPEND OPTION_LIST "+CAP")
  set(LIBCAP ON)
else()
  list(APPEND OPTION_LIST "-CAP")
endif()

if(CURSES)
  set(_curses_fn use_default_colors)
  set(_curses_lib ncursesw)
  check_library_exists("${_curses_lib}" "${_curses_fn}" "${CMAKE_LIBRARY_PATH}" HAVE_CFN_IN_NCW)
  if(NOT HAVE_CFN_IN_NCW)
    set(_curses_lib curses)
    check_library_exists(${_curses_lib} "${_curses_fn}" "${CMAKE_LIBRARY_PATH}" HAVE_CFN_IN_SYS)
    if(NOT HAVE_CFN_IN_SYS)
      set(_curses_lib ncurses)
      check_library_exists(${_curses_lib} "${_curses_fn}" "${CMAKE_LIBRARY_PATH}" HAVE_CFN_IN_NC)
      if(NOT HAVE_CFN_IN_NC)
        message(FATAL_ERROR "CURSES is enabled, but no suitable library found")
      endif()
    endif()
  endif()
  set(HAVE_USE_DEFAULT_COLORS ON)
  target_link_libraries("${NAME}" PRIVATE -l${_curses_lib})
  check_include_file("ncursesw/ncurses.h" HAVE_NCURSESW_NCURSES_H)
  check_include_file("ncursesw/curses.h" HAVE_NCURSESW_CURSES_H)
  check_include_file("ncurses/ncurses.h" HAVE_NCURSES_NCURSES_H)
  check_include_file("ncurses/curses.h" HAVE_NCURSES_CURSES_H)
  check_include_file("ncurses.h" HAVE_NCURSES_H)
  check_include_file("curses.h" HAVE_CURSES_H)
  if(UNICODE)
    set(_curses_wfn add_wch)
    check_library_exists("${_curses_lib}" "${_curses_wfn}" "${CMAKE_LIBRARY_PATH}" HAVE_WCH_IN_CURSES)
    if(NOT HAVE_WCH_IN_CURSES)
      message(FATAL_ERROR "UNICODE is enabled, but no wchar library found")
    endif()
  endif()
  target_sources("${NAME}" PRIVATE curses.c)
  list(APPEND OPTION_LIST "+CURSES")
  set(CURSESMODE ON)
else()
  list(APPEND OPTION_LIST "-CURSES")
endif()

if(UNICODE)
  check_include_file("wchar.h" HAVE_WCHAR_H)
  check_include_file("wctype.h" HAVE_WCTYPE_H)
  check_include_file("locale.h" HAVE_LOCALE_H)
  check_include_file("langinfo.h" HAVE_LANGINFO_H)
  list(APPEND OPTION_LIST "+UNICODE")
  set(WITH_UNICODE ON)
else()
  list(APPEND OPTION_LIST "-UNICODE")
endif()

if(NLS)
  set(USE_NLS ON)
  find_package(Gettext REQUIRED)
  find_package(Intl REQUIRED)
  if (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
      CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR
      CMAKE_SYSTEM_NAME STREQUAL "Haiku")
    include_directories(${Intl_INCLUDE_DIRS})
    target_link_libraries("${NAME}" PRIVATE ${Intl_LIBRARIES})
  endif()
  set(LOCALEDIR "${CMAKE_INSTALL_FULL_LOCALEDIR}")
  set(LINGUAS es it pt uk)
  set(mo_files)
  foreach(lang ${LINGUAS})
#    GETTEXT_PROCESS_PO_FILES("${lang}" ALL INSTALL_DESTINATION "${LOCALEDIR}/"
#      PO_FILES "${CMAKE_CURRENT_SOURCE_DIR}/po/${lang}.po")
    set(_po "${CMAKE_CURRENT_SOURCE_DIR}/po/${lang}.po")
    set(_mo "${CMAKE_CURRENT_BINARY_DIR}/${lang}.mo")
    add_custom_command(OUTPUT "${_mo}"
      COMMAND "${GETTEXT_MSGFMT_EXECUTABLE}" -o "${_mo}" "${_po}"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      DEPENDS "${_po}"
    )
    install(FILES "${_mo}"
      DESTINATION "${CMAKE_INSTALL_LOCALEDIR}/${lang}/LC_MESSAGES/"
      RENAME "${PACKAGE_NAME}.mo")
    list(APPEND mo_files "${_mo}")
  endforeach()
  add_custom_target(pofiles ALL DEPENDS ${mo_files})
  list(APPEND OPTION_LIST "+NLS")
else()
  list(APPEND OPTION_LIST "-NLS")
endif()

if(DNS)
  set(_res_fn res_mkquery)
  set(_res_lib c)
  check_library_exists("${_res_lib}" "${_res_fn}" "${CMAKE_LIBRARY_PATH}" HAVE_RES_IN_C)
  if(NOT HAVE_RES_IN_C)
    set(_res_lib resolv)
    check_library_exists("${_res_lib}" "${_res_fn}" "${CMAKE_LIBRARY_PATH}" HAVE_RES_IN_RES)
    if(NOT HAVE_RES_IN_RES)
      check_library_exists("${_res_lib}" "__${_res_fn}" "${CMAKE_LIBRARY_PATH}" HAVE___RES_IN_C)
      if(NOT HAVE___RES_IN_C)
        set(_res_lib network)
        check_library_exists("${_res_lib}" "__${_res_fn}" "${CMAKE_LIBRARY_PATH}" HAVE___RES_IN_NET)
        if(NOT HAVE___RES_IN_NET)
          message(WARNING "DNS is enabled, but resolver is not detected: suppose it's present in libc")
          set(_res_lib c)
        endif()
      endif()
    endif()
    target_link_libraries("${NAME}" PRIVATE -l${_res_lib})
  endif()
  set(_res_fn res_nmkquery)
  check_function_exists("${_res_fn}" HAVE_RES_NMKQUERY)
  if(NOT HAVE_RES_NMKQUERY)
    check_library_exists("${_res_lib}" "__${_res_fn}" "${CMAKE_LIBRARY_PATH}" HAVE_RES___NMKQUERY)
    if(HAVE_RES___NMKQUERY)
      set(HAVE_RES_NMKQUERY ON)
    endif()
  endif()
  check_include_file("arpa/nameser.h" HAVE_ARPA_NAMESER_H)
  check_include_file("sys/types.h" HAVE_SYS_TYPES_H)
  target_sources("${NAME}" PRIVATE dns.c)
  list(APPEND OPTION_LIST "+DNS")
  set(ENABLE_DNS ON)
else()
  list(APPEND OPTION_LIST "-DNS")
  list(APPEND MAN_EXCL n)
  list(APPEND MAN_EXCL N)
endif()

list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_DARWIN_C_SOURCE)
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D__EXTENSIONS__)
check_symbol_exists(AI_IDN "netdb.h" HAVE_AI_IDN)
if(HAVE_AI_IDN)
  set(IDN ON)
else()
  pkg_check_modules(IDN IMPORTED_TARGET libidn2)
  if(IDN_FOUND)
    set(LIBIDN2 ON)
    set(IDN ON)
  else()
    pkg_check_modules(IDN REQUIRED IMPORTED_TARGET libidn)
    if(IDN_FOUND)
      set(LIBIDN ON)
      set(IDN ON)
    endif()
  endif()
  if(IDN)
    target_link_libraries("${NAME}" PRIVATE PkgConfig::IDN)
  endif()
endif()
if(IDN)
  list(APPEND OPTION_LIST "+IDN")
else()
  list(APPEND OPTION_LIST "-IDN")
endif()

if(IPINFO)
  target_sources("${NAME}" PRIVATE ipinfo.c)
  list(APPEND OPTION_LIST "+IPINFO")
  set(WITH_IPINFO ON)
else()
  list(APPEND OPTION_LIST "-IPINFO")
  list(APPEND MAN_EXCL l)
endif()

if(SPLIT)
  target_sources("${NAME}" PRIVATE split.c)
  list(APPEND OPTION_LIST "+SPLIT")
  set(SPLITMODE ON)
else()
  list(APPEND OPTION_LIST "-SPLIT")
  list(APPEND MAN_EXCL p)
endif()

if(IPV6)
  list(APPEND OPTION_LIST "+IPV6")
  set(ENABLE_IPV6 ON)
else()
  list(APPEND OPTION_LIST "-IPV6")
  list(APPEND MAN_EXCL 4 6)
endif()

if(MPLS)
  list(APPEND OPTION_LIST "+MPLS")
  set(WITH_MPLS ON)
else()
  list(APPEND OPTION_LIST "-MPLS")
  list(APPEND MAN_EXCL e)
endif()

if(OUTTXT)
  list(APPEND OPTION_OUTFMT "text")
  set(OUTPUT_FORMAT_TXT ON)
else()
  list(APPEND MAN_EXCL ot)
endif()
if(OUTCSV)
  list(APPEND OPTION_OUTFMT "csv")
  set(OUTPUT_FORMAT_CSV ON)
else()
  list(APPEND MAN_EXCL oc)
endif()
if(OUTJSON)
  list(APPEND OPTION_OUTFMT "json")
  set(OUTPUT_FORMAT_JSON ON)
else()
  list(APPEND MAN_EXCL oj)
endif()
if(OUTRAW)
  list(APPEND OPTION_OUTFMT "raw")
  set(OUTPUT_FORMAT_RAW ON)
else()
  list(APPEND MAN_EXCL or)
endif()
if(OUTXML)
  list(APPEND OPTION_OUTFMT "xml")
  set(OUTPUT_FORMAT_XML ON)
else()
  list(APPEND MAN_EXCL ox)
endif()
if(NOT OPTION_OUTFMT)
  list(APPEND MAN_EXCL o)
endif()

if(DEBPOLL)
  list(APPEND OPTION_DEBLOG "poll")
  set(LOG_POLL ON)
endif()
if(DEBNET)
  list(APPEND OPTION_DEBLOG "net")
  set(LOG_NET ON)
endif()
if(DEBDNS)
  list(APPEND OPTION_DEBLOG "dns")
  set(LOG_DNS ON)
endif()
if(DEBIPINFO)
  list(APPEND OPTION_DEBLOG "ipinfo")
  set(LOG_IPINFO ON)
endif()


# misc aux checkouts
#
check_include_file("netdb.h" HAVE_NETDB_H)
check_include_file("sys/param.h" HAVE_SYS_PARAM_H)
#
function(fn_checkout)
  foreach(fn IN LISTS FN_LIST)
    string(TOUPPER "HAVE_${fn}" FN_DEF)
    check_library_exists(c "${fn}" "${CMAKE_LIBRARY_PATH}" "${FN_DEF}")
    if(NOT "${${FN_DEF}}")
      foreach(lib IN LISTS FN_LIBS)
        string(TOUPPER "${lib}_${FN_DEF}" LIB_FN_DEF)
        check_library_exists("${lib}" "${fn}" "${CMAKE_LIBRARY_PATH}" "${LIB_FN_DEF}")
        if("${${LIB_FN_DEF}}")
          set("${FN_DEF}" ON)
          get_target_property(TGT_LIBS "${NAME}" LINK_LIBRARIES)
          if(NOT "-l${lib}" IN_LIST TGT_LIBS)
            target_link_libraries("${NAME}" PRIVATE "-l${lib}")
          endif()
          break()
        endif()
      endforeach()
      if("${fn}" IN_LIST FN_MUST AND NOT "${${FN_DEF}}")
        message(FATAL_ERROR "No library with ${fn}() found")
      endif()
    endif()
  endforeach()
endfunction()
#
set(FN_LIBS m)
set(FN_LIST pow)
set(FN_MUST pow)
fn_checkout()
#
set(FN_LIBS socket network)
set(FN_LIST socket)
set(FN_MUST socket)
fn_checkout()
#
set(FN_LIBS c)
set(FN_LIST warnx strlcpy arc4random_uniform)
set(FN_MUST warnx)
fn_checkout()
#
set(FN_LIBS c)
set(FN_LIST quick_exit strerror_r ctime_r localtime_r)
set(FN_MUST)
fn_checkout()
#
check_symbol_exists(IP_TOS "netinet/in.h" HAVE_IP_TOS)
if(NOT HAVE_IP_TOS)
  list(APPEND MAN_EXCL q)
endif()
#

# exclude unset options from man page
file(MAKE_DIRECTORY "${MAN_PATH}")
configure_file("${MAN_PAGE}.in" "${MANUAL}" COPYONLY)
if(MAN_EXCL)
  file(READ "${MANUAL}" MAN_CONTENT)
  foreach(excl IN LISTS MAN_EXCL)
    string(REGEX REPLACE "\(\.ds o${excl} \"\)[^\n]*" "\\1" MAN_CONTENT ${MAN_CONTENT})
  endforeach()
  file(WRITE "${MANUAL}" ${MAN_CONTENT})
endif()

# fin
if(OPTION_OUTFMT)
  list(JOIN OPTION_OUTFMT "," OPTION_OUTFMT)
  list(APPEND OPTION_LIST "OUTFMT=${OPTION_OUTFMT}")
else()
  list(APPEND OPTION_LIST "-OUTFMT")
  set(OPTION_OUTFMT OFF)
endif()
if(OPTION_DEBLOG)
  list(JOIN OPTION_DEBLOG "," OPTION_DEBLOG)
  list(APPEND OPTION_LIST "DEBLOG=${OPTION_DEBLOG}")
else()
  list(APPEND OPTION_LIST "-DEBLOG")
  set(OPTION_DEBLOG OFF)
endif()
list(JOIN OPTION_LIST " " OPTION_LIST)
set(BUILD_OPTIONS "${OPTION_LIST}")
set(CONFIG "config.h")
configure_file("${CONFIG}.cmake" "${CONFIG}" @ONLY)
target_compile_options("${NAME}" PRIVATE -include "${CONFIG}")

message("")
message(STATUS "CAP     ${CAP}\t: Linux capabilities")
message(STATUS "CURSES  ${CURSES}\t: Terminal interface")
message(STATUS "UNICODE ${UNICODE}\t: International encoding")
message(STATUS "NLS     ${NLS}\t: NLS messages")
message(STATUS "DNS     ${DNS}\t: Hostname / IP-address resolver")
message(STATUS "IDN     ${IDN}\t: International characters in domain names")
message(STATUS "IPINFO  ${IPINFO}\t: Extra information on IP-address")
message(STATUS "SPLIT   ${SPLIT}\t: Split-out format")
message(STATUS "IPV6    ${IPV6}\t: IPv6 support")
message(STATUS "MPLS    ${MPLS}\t: MPLS decoding")
message(STATUS "OUTFMT  ${OPTION_OUTFMT}\t: plain output formats")
message(STATUS "DEBLOG  ${OPTION_DEBLOG}\t: debug via syslog")
message("")


# install
set(EXECDIR "${CMAKE_INSTALL_BINDIR}") # with cap_net_raw
if(SBIN)
  set(EXECDIR "${CMAKE_INSTALL_SBINDIR}")
endif()
install(TARGETS "${NAME}" DESTINATION "${EXECDIR}")

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.14.0")
  install(DIRECTORY "${MAN_PATH}" TYPE MAN)
else()
  install(DIRECTORY "${MAN_PATH}" DESTINATION ${CMAKE_INSTALL_MANDIR})
endif()

if(CAP)
  find_program(SETCAP setcap)
  set(EXECCAPS "cap_net_raw+p")
  set(EXECFILE "${CMAKE_INSTALL_PREFIX}/${EXECDIR}/${NAME}")
  if(SETCAP)
    message(STATUS "Caps for '${EXECDIR}/${NAME}': ${EXECCAPS}")
    install(CODE "execute_process(COMMAND ${SETCAP} ${EXECCAPS} \$ENV{DESTDIR}${EXECFILE})")
  else()
    message(STATUS "NOTE: to run '${EXECFILE}' it needs raw socket permissions")
  endif()
  message("")
endif()

