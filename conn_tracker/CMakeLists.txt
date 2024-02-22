# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(CMAKE_CXX_STANDARD 20)

include(CheckSymbolExists)
include(CheckStructHasMember)

set(CMAKE_REQUIRED_INCLUDES ${EBPF_INC_PATH})

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

add_executable(
  conn_tracker
  conn_tracker.cc
  conn_tracker.h
)

target_include_directories(conn_tracker PRIVATE ${EBPF_INC_PATH})
target_link_directories(conn_tracker PRIVATE ${EBPF_LIB_PATH})
target_link_libraries(conn_tracker PRIVATE ${EBPF_LIB})
