cmake_minimum_required(VERSION 3.28)
project(provider_server_tests LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Provider server tests require Windows x64.")
endif()

add_executable(provider-server-tests
  ../src/provider_server.cpp
  provider_server_tests.cpp
)
target_compile_features(provider-server-tests PRIVATE cxx_std_20)
target_compile_definitions(provider-server-tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
if(MSVC)
  target_compile_options(provider-server-tests PRIVATE /utf-8)
endif()
target_include_directories(provider-server-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src")
target_link_libraries(provider-server-tests PRIVATE bcrypt crypt32 winhttp ws2_32)

enable_testing()
add_test(NAME provider-server COMMAND provider-server-tests)
