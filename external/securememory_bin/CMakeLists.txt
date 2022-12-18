cmake_minimum_required(VERSION 3.8)
find_library(SecureMemoryLib SecureMemory ${CMAKE_CURRENT_SOURCE_DIR}/bin)

set(SecureMemoryInclude
    ${CMAKE_CURRENT_SOURCE_DIR}/include/
    )
