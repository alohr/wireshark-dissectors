cmake_minimum_required(VERSION 2.6)
project(beacon)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cmdline.h ${CMAKE_CURRENT_BINARY_DIR}/cmdline.c
  COMMAND /usr/local/bin/gengetopt < ${CMAKE_CURRENT_SOURCE_DIR}/beacon.ggo
  DEPENDS beacon.ggo
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(beacon beacon.c ${CMAKE_CURRENT_BINARY_DIR}/cmdline.c)
