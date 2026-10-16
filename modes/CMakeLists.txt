cmake_minimum_required(VERSION 3.16)
project(AESModesLab VERSION 3.0.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

set(AES_LIBRARY_TYPE "STATIC" CACHE STRING "Library output: STATIC, SHARED or BOTH")
set_property(CACHE AES_LIBRARY_TYPE PROPERTY STRINGS STATIC SHARED BOTH)
option(AES_BUILD_EXECUTABLE "Build the AES known-answer test executable" ON)
option(AES_BUILD_TESTS "Register the executable as a CTest test" ON)
option(AES_STRICT_WARNINGS "Enable common compiler warnings" ON)
option(AES_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

string(TOUPPER "${AES_LIBRARY_TYPE}" AES_LIBRARY_TYPE)
if(NOT AES_LIBRARY_TYPE MATCHES "^(STATIC|SHARED|BOTH)$")
  message(FATAL_ERROR "AES_LIBRARY_TYPE must be STATIC, SHARED, or BOTH (received '${AES_LIBRARY_TYPE}')")
endif()
if(AES_BUILD_TESTS AND NOT AES_BUILD_EXECUTABLE)
  message(FATAL_ERROR "AES_BUILD_TESTS=ON requires AES_BUILD_EXECUTABLE=ON")
endif()

# Teacher's complete source layout: SP 800-38A..F and RFC 8452.
# tests/main.cpp checks the published vectors shown in the teacher's output.
set(AES_SOURCES
  src/aes.cpp
  src/aes_c.cpp
  src/sp800_38a.cpp
  src/sp800_38b.cpp
  src/sp800_38c.cpp
  src/sp800_38d.cpp
  src/sp800_38e.cpp
  src/sp800_38f.cpp
  src/rfc8452_gcm_siv.cpp
)
set(AES_HEADERS
  include/aes.hpp
  include/aes_c.h
  include/common.hpp
  include/sp800_38a.hpp
  include/sp800_38b.hpp
  include/sp800_38c.hpp
  include/sp800_38d.hpp
  include/sp800_38e.hpp
  include/sp800_38f.hpp
  include/rfc8452_gcm_siv.hpp
)

# Select the compiler at configure time; use a different build directory to change it.
function(aes_configure_target target)
  target_compile_features(${target} PUBLIC cxx_std_17)
  set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF)
  target_include_directories(${target} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )
  if(AES_STRICT_WARNINGS)
    if(MSVC)
      target_compile_options(${target} PRIVATE /W4)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
      target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
  endif()
  if(AES_WARNINGS_AS_ERRORS)
    if(MSVC)
      target_compile_options(${target} PRIVATE /WX)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

set(AES_INSTALL_TARGETS "")
if(AES_LIBRARY_TYPE STREQUAL "STATIC" OR AES_LIBRARY_TYPE STREQUAL "BOTH")
  add_library(aes_modes_static STATIC ${AES_SOURCES} ${AES_HEADERS})
  set_target_properties(aes_modes_static PROPERTIES OUTPUT_NAME aes_modes)
  if(WIN32 AND AES_LIBRARY_TYPE STREQUAL "BOTH")
    set_target_properties(aes_modes_static PROPERTIES OUTPUT_NAME aes_modes_static)
  endif()
  aes_configure_target(aes_modes_static)
  list(APPEND AES_INSTALL_TARGETS aes_modes_static)
  add_library(AESModes::static ALIAS aes_modes_static)
endif()

if(AES_LIBRARY_TYPE STREQUAL "SHARED" OR AES_LIBRARY_TYPE STREQUAL "BOTH")
  add_library(aes_modes_shared SHARED ${AES_SOURCES} ${AES_HEADERS})
  set_target_properties(aes_modes_shared PROPERTIES
    OUTPUT_NAME aes_modes
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    WINDOWS_EXPORT_ALL_SYMBOLS ON
  )
  aes_configure_target(aes_modes_shared)
  list(APPEND AES_INSTALL_TARGETS aes_modes_shared)
  add_library(AESModes::shared ALIAS aes_modes_shared)
endif()

if(TARGET aes_modes_static)
  add_library(AESModes::aes_modes ALIAS aes_modes_static)
  set(AES_LINK_TARGET aes_modes_static)
else()
  add_library(AESModes::aes_modes ALIAS aes_modes_shared)
  set(AES_LINK_TARGET aes_modes_shared)
endif()

if(AES_BUILD_EXECUTABLE)
  add_executable(aes_tests tests/main.cpp)
  aes_configure_target(aes_tests)
  target_link_libraries(aes_tests PRIVATE ${AES_LINK_TARGET})
  # The installed shared-only executable must find the sibling library without
  # LD_LIBRARY_PATH, including after the installation prefix is relocated.
  if(UNIX)
    file(RELATIVE_PATH AES_LIB_FROM_BIN
      "${CMAKE_INSTALL_FULL_BINDIR}" "${CMAKE_INSTALL_FULL_LIBDIR}")
    if(APPLE)
      set_target_properties(aes_tests PROPERTIES
        INSTALL_RPATH "@loader_path/${AES_LIB_FROM_BIN}")
    else()
      set_target_properties(aes_tests PROPERTIES
        INSTALL_RPATH "$ORIGIN/${AES_LIB_FROM_BIN}")
    endif()
  endif()
  if(AES_BUILD_TESTS)
    add_test(NAME aes_vectors COMMAND aes_tests)
    add_executable(aes_c_tests tests/c_api.cpp)
    aes_configure_target(aes_c_tests)
    target_link_libraries(aes_c_tests PRIVATE ${AES_LINK_TARGET})
    add_test(NAME aes_c_api_contract COMMAND aes_c_tests)
  endif()
endif()

install(TARGETS ${AES_INSTALL_TARGETS}
  EXPORT AESModesTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(FILES ${AES_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(AES_BUILD_EXECUTABLE)
  install(TARGETS aes_tests RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(EXPORT AESModesTargets
  FILE AESModesTargets.cmake
  NAMESPACE AESModes::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AESModes
)
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/AESModesConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/AESModesConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AESModes
)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/AESModesConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/AESModesConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/AESModesConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AESModes
)

message(STATUS "AES compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "AES outputs: ${AES_LIBRARY_TYPE}; executable: ${AES_BUILD_EXECUTABLE}; tests: ${AES_BUILD_TESTS}")
