cmake_minimum_required(VERSION 3.28)
project(donationalerts_obs_provider LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "The initial OBS plugin target is Windows x64 only.")
endif()

set(OBS_SDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.obs-sdk" CACHE PATH "OBS SDK prepared by tools/prepare-obs-sdk.ps1")
set(OBS_SOURCE_DIR "${OBS_SDK_ROOT}/source/obs-studio-32.2.2-sources")
set(OBS_BUILD_DIR "${OBS_SDK_ROOT}/build")

foreach(required_file IN ITEMS
    "${OBS_SOURCE_DIR}/libobs/obs-module.h"
    "${OBS_SOURCE_DIR}/frontend/api/obs-frontend-api.h"
    "${OBS_BUILD_DIR}/libobs/Release/obs.lib"
    "${OBS_BUILD_DIR}/frontend/api/Release/obs-frontend-api.lib")
  if(NOT EXISTS "${required_file}")
    message(FATAL_ERROR "OBS SDK is missing '${required_file}'. Run tools/prepare-obs-sdk.ps1 first.")
  endif()
endforeach()

add_library(donationalerts_obs_provider MODULE
  src/plugin.cpp
  src/provider_server.cpp
)

target_compile_features(donationalerts_obs_provider PRIVATE cxx_std_20)
target_compile_definitions(donationalerts_obs_provider PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_include_directories(donationalerts_obs_provider PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${OBS_SOURCE_DIR}/libobs"
  "${OBS_SOURCE_DIR}/libobs/util"
  "${OBS_BUILD_DIR}/config"
  "${OBS_SOURCE_DIR}/frontend/api"
)
target_link_directories(donationalerts_obs_provider PRIVATE
  "${OBS_BUILD_DIR}/libobs/Release"
  "${OBS_BUILD_DIR}/frontend/api/Release"
)
target_link_libraries(donationalerts_obs_provider PRIVATE
  obs
  obs-frontend-api
  bcrypt
  shell32
  ws2_32
)
set_target_properties(donationalerts_obs_provider PROPERTIES
  PREFIX ""
  OUTPUT_NAME "donationalerts-obs-provider"
)

include(CTest)
if(BUILD_TESTING)
  add_executable(provider-server-tests
    src/provider_server.cpp
    tests/provider_server_tests.cpp
  )
  target_compile_features(provider-server-tests PRIVATE cxx_std_20)
  target_compile_definitions(provider-server-tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_include_directories(provider-server-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_link_libraries(provider-server-tests PRIVATE bcrypt ws2_32)
  add_test(NAME provider-server COMMAND provider-server-tests)
endif()

include(GNUInstallDirs)
install(TARGETS donationalerts_obs_provider
  RUNTIME DESTINATION "plugins/donationalerts-obs-provider/bin/64bit"
  LIBRARY DESTINATION "plugins/donationalerts-obs-provider/bin/64bit"
)
