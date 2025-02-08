# Copyright (c) 2017-2021 The ViaDuck Project
#
# This file is part of cryptoSQLite.
#
# cryptoSQLite is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# cryptoSQLite is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with cryptoSQLite.  If not, see <http://www.gnu.org/licenses/>.
#

cmake_minimum_required(VERSION 3.18)
project(cryptoSQLite)

# add sqlite amalgamation subdirectory
add_subdirectory(sqlite)

# Add SecureMemory dependency
if(NOT TARGET secure_memory)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/securememory)
endif()

# glob files
file(GLOB_RECURSE CS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/*)
file(GLOB_RECURSE CS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*)

# Create cryptosqlite target with merged sources
add_library(cryptosqlite SHARED ${CS_SOURCES})

# require and enable c++14 support
set_target_properties(cryptosqlite PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED YES)

# compile options
target_compile_options(cryptosqlite PRIVATE -Wall)

target_include_directories(cryptosqlite
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/external/securememory/include
        ${SQLITE_INCLUDE_DIRS}
)

# Modern target-based linking
target_link_libraries(cryptosqlite PRIVATE
        secure_memory
        sqlite3
        ${CMAKE_DL_LIBS}
)
if(WIN32)
    target_link_libraries(cryptosqlite PRIVATE ws2_32)
endif()

# SQLite compile definitions
target_compile_definitions(cryptosqlite PUBLIC
        -DSQLITE_HAS_CODEC
        -DSQLITE_ENABLE_VFS
        -DSQLITE_THREADSAFE=1
        -DSQLITE_DEFAULT_MEMSTATUS=0
        -DSQLITE_TEMP_STORE=3
        -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1
        -DSQLITE_LIKE_DOESNT_MATCH_BLOBS=1
        -DSQLITE_MAX_EXPR_DEPTH=0
        -DSQLITE_OMIT_DEPRECATED=1
        -DSQLITE_OMIT_PROGRESS_CALLBACK=1
        -DHAVE_FDATASYNC
        -DHAVE_ISNAN
        -DHAVE_MALLOC_USABLE_SIZE
        -DSQLITE_DEFAULT_FILE_PERMISSIONS=0600
        -DSQLITE_ENABLE_API_ARMOR
        -DSQLITE_ENABLE_FTS4
        -DSQLITE_ENABLE_FTS5
        -DSQLITE_ENABLE_JSON1
)

if(WIN32)
    target_compile_definitions(cryptosqlite PUBLIC
            -DSQLITE_4_BYTE_ALIGNED_MALLOC=1
    )
else()
    target_compile_definitions(cryptosqlite PUBLIC
            -DHAVE_LOCALTIME_R
    )
endif()

# SQLite implementation definitions
target_compile_definitions(cryptosqlite PRIVATE
        SQLITE_ENABLE_BTREE
        SQLITE_CORE
        SQLITE_PRIVATE=
)

