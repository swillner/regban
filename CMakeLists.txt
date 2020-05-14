cmake_minimum_required(VERSION 3.8)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)
include(cmake/helpers.cmake)
include(cmake/libraries.cmake)

set_default_build_type(Release)

project(regban)

add_executable(regban src/main.cpp)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_compile_options(regban PUBLIC -fno-math-errno -fno-rtti)
  add_custom_command(
    TARGET regban
    POST_BUILD
    COMMAND ${CMAKE_STRIP} regban
  )
endif()

target_include_directories(regban PRIVATE include lib/cpp-library lib/spdlog/include)
target_compile_features(regban PUBLIC cxx_std_14)

add_system_paths()

include(lib/settingsnode/settingsnode.cmake)
include_settingsnode(regban)
include_yaml_cpp(regban ON "yaml-cpp-0.6.3")

include_custom_library(mnl "libmnl/libmnl.h")
target_link_libraries(regban PRIVATE mnl)

include_custom_library(nftnl "libnftnl/set.h")
target_link_libraries(regban PRIVATE nftnl)

set_advanced_cpp_warnings(regban)
set_build_type_specifics(regban)
add_git_version(regban WITH_DIFF)
add_cpp_tools(regban STD c++14)


add_executable(benchmark_iptables EXCLUDE_FROM_ALL tests/benchmark_iptables.cpp)
target_include_directories(benchmark_iptables PRIVATE include lib/nanobench/src/include)
add_custom_target(benchmark
  COMMAND benchmark_iptables
  DEPENDS benchmark_iptables)

add_executable(test_iptables EXCLUDE_FROM_ALL tests/test_iptables.cpp)
target_include_directories(test_iptables PRIVATE include lib/doctest/doctest)
add_executable(test_ipvx EXCLUDE_FROM_ALL tests/test_ipvx.cpp)
target_include_directories(test_ipvx PRIVATE include lib/doctest/doctest)
add_custom_target(test
  COMMAND test_iptables
  COMMAND test_ipvx
  DEPENDS test_iptables test_ipvx)
