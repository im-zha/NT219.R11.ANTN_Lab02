cmake_minimum_required(VERSION 3.16)
project(AESLab VERSION 3.0.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CTest)

# Task 3: one build entry point; the teacher's modes/ entry point still works.
# cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAES_LIBRARY_TYPE=BOTH
# cmake --build build && ctest --test-dir build --output-on-failure
# cmake --install build --prefix "$PWD/build/install"
add_subdirectory(modes)

if(AES_BUILD_EXECUTABLE)
  add_executable(AES AES.cpp)
  target_compile_features(AES PRIVATE cxx_std_17)
  set_target_properties(AES PROPERTIES CXX_EXTENSIONS OFF)
  if(AES_STRICT_WARNINGS)
    if(MSVC)
      target_compile_options(AES PRIVATE /W4)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
      target_compile_options(AES PRIVATE -Wall -Wextra -Wpedantic)
    endif()
  endif()
  if(AES_WARNINGS_AS_ERRORS)
    if(MSVC)
      target_compile_options(AES PRIVATE /WX)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
      target_compile_options(AES PRIVATE -Werror)
    endif()
  endif()
  install(TARGETS AES RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  if(AES_BUILD_TESTS)
    add_test(NAME aes_core_vectors COMMAND AES)
  endif()

  # Task 3: link the same client separately to the static and shared libraries.
  foreach(linkage IN ITEMS static shared)
    if(TARGET aes_modes_${linkage})
      add_executable(aes_consumer_${linkage} task3/main.cpp)
      target_link_libraries(aes_consumer_${linkage} PRIVATE aes_modes_${linkage})
      set_target_properties(aes_consumer_${linkage} PROPERTIES
        CXX_EXTENSIONS OFF
        OUTPUT_NAME aes_consumer
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/consumer-${linkage}"
      )
    endif()
  endforeach()
endif()

# Task 4: the Python client uses ctypes only and needs a shared library.
if(TARGET aes_modes_shared)
  install(FILES task4/aes_modes.py task4/main.py
    DESTINATION ${CMAKE_INSTALL_DATADIR}/AESModes/python
  )
endif()
