cmake_minimum_required(VERSION 2.6)
project(transmogrify)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cmdline.h ${CMAKE_CURRENT_BINARY_DIR}/cmdline.c
  COMMAND /usr/local/bin/gengetopt < ${CMAKE_CURRENT_SOURCE_DIR}/transmogrify.ggo
  DEPENDS transmogrify.ggo
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(transmogrify transmogrify.c in_cksum.c ${CMAKE_CURRENT_BINARY_DIR}/cmdline.c)

target_link_libraries(transmogrify PUBLIC pcap)

