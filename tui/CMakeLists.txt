
# TUI part of mtr085-CMakeLists

set(_libs ncursesw curses ncurses)
set(_fns curses_version use_default_colors)
if(MOUSE)
  list(APPEND _fns mousemask)
endif()

set(TUIKIND)
foreach(_fn ${_fns})
  string(TOUPPER ${_fn} _CFN)
  foreach(_lib ${_libs})
    check_library_exists("${_lib}" "${_fn}" "${CMAKE_LIBRARY_PATH}"
                         HAVE_${_lib}_${_CFN})
    if(HAVE_${_lib}_${_CFN})
      set(HAVE_${_CFN} ON PARENT_SCOPE)
      if(NOT TUIKIND)
        set(TUIKIND ${_lib})
      endif()
      break()
    endif()
  endforeach()
endforeach()
if(NOT TUIKIND)
  message(FATAL_ERROR "TUI is enabled, but no suitable library found")
endif()
set(TUIKIND "${TUIKIND}" PARENT_SCOPE)

target_link_libraries("${NAME}" PRIVATE -l${TUIKIND})
check_include_file("ncursesw/ncurses.h" HAVE_NCURSESW_NCURSES_H)
check_include_file("ncursesw/curses.h" HAVE_NCURSESW_CURSES_H)
check_include_file("ncurses/ncurses.h" HAVE_NCURSES_NCURSES_H)
check_include_file("ncurses/curses.h" HAVE_NCURSES_CURSES_H)
check_include_file("ncurses.h" HAVE_NCURSES_H)
check_include_file("curses.h" HAVE_CURSES_H)
if(UNICODE)
  set(_wide add_wch)
  check_library_exists("${TUIKIND}" "${_wide}" "${CMAKE_LIBRARY_PATH}"
                       HAVE_WIDE_CHARS)
  if(NOT HAVE_WIDE_CHARS)
    message(FATAL_ERROR "UNICODE is enabled, but no wchar library found")
  endif()
endif()

target_include_directories("${NAME}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")
target_sources("${NAME}" PRIVATE tui.c chart.c action.c)

