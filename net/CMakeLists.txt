
# NET part of mtr085-CMakeLists

if(RAW)
  set(USE_RAW ON PARENT_SCOPE)
  list(APPEND OPTION_LIST "+RAW")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # libcap: mandatory on linux
    pkg_check_modules(CAP REQUIRED IMPORTED_TARGET libcap)
  else()
    pkg_check_modules(CAP IMPORTED_TARGET libcap)
  endif()
  if(CAP_FOUND)
    target_link_libraries("${NAME}" PRIVATE PkgConfig::CAP)
    list(APPEND OPTION_LIST "+CAP")
    set(LIBCAP ON PARENT_SCOPE)
  else()
    list(APPEND OPTION_LIST "-CAP")
    set(LIBCAP OFF PARENT_SCOPE)
  endif()
  target_sources("${NAME}" PRIVATE raw.c)
else()
  list(APPEND OPTION_LIST "+USER")
  target_sources("${NAME}" PRIVATE user.c)
endif()

target_include_directories("${NAME}" PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")
target_sources("${NAME}" PRIVATE net.c gen.c)

