cmake_minimum_required(VERSION 3.16)
project(AESInstalledConsumer LANGUAGES CXX)

# From the repository root, after installing into build/install:
# cmake -S examples/cpp -B build/consumer-static -DCMAKE_PREFIX_PATH="$PWD/build/install"
# cmake -S examples/cpp -B build/consumer-shared -DCMAKE_PREFIX_PATH="$PWD/build/install" -DAES_EXAMPLE_SHARED=ON
# cmake --build build/consumer-static; ./build/consumer-static/aes_consumer
find_package(AESModes 3 CONFIG REQUIRED)
option(AES_EXAMPLE_SHARED "Link the installed shared library instead of the static library" OFF)

if(AES_EXAMPLE_SHARED)
  set(AES_EXAMPLE_TARGET AESModes::aes_modes_shared)
else()
  set(AES_EXAMPLE_TARGET AESModes::aes_modes_static)
endif()
if(NOT TARGET ${AES_EXAMPLE_TARGET})
  message(FATAL_ERROR
    "Requested installed target ${AES_EXAMPLE_TARGET} is unavailable. Install AESModes with AES_LIBRARY_TYPE=BOTH or the requested STATIC/SHARED variant.")
endif()

add_executable(aes_consumer main.cpp)
target_compile_features(aes_consumer PRIVATE cxx_std_17)
set_target_properties(aes_consumer PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(aes_consumer PRIVATE ${AES_EXAMPLE_TARGET})
