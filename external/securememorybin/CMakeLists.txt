cmake_minimum_required(VERSION 3.8)
find_library(SecureMemoryLib SecureMemory ${CMAKE_CURRENT_SOURCE_DIR}/bin)

set(SecureMemoryInclude
    ${CMAKE_CURRENT_SOURCE_DIR}/include/
    )

# NOTE: If first time build on a system, build the cmake in securememory/ first,
#           then copy the libSecureMemory.a to securememory/bin