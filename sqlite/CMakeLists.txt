# lib/cryptoSQLite/sqlite/CMakeLists.txt

cmake_minimum_required(VERSION 3.18)

# set up cache variables
set(SQLITE_BUILD_VERSION "3480000" CACHE STRING "SQLite version string as used in the URL")
set(SQLITE_BUILD_HASH "d9a15a42db7c78f88fe3d3c5945acce2f4bfe9e4da9f685cd19f6ea1d40aa884" CACHE STRING
        "SQLite amalgamation zip sha256 hash used to check the download")

# build url from cache variables
set(SQLITE_URL "https://mirror.viaduck.org/sqlite/sqlite-amalgamation-${SQLITE_BUILD_VERSION}.zip")
set(SQLITE_SUBDIR "${CMAKE_CURRENT_SOURCE_DIR}/sqlite-amalgamation-${SQLITE_BUILD_VERSION}")

# download amalgamation zip with hash check if needed
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/sqlite.zip")
        file(DOWNLOAD
                ${SQLITE_URL}
                ${CMAKE_CURRENT_SOURCE_DIR}/sqlite.zip
                EXPECTED_HASH SHA256=${SQLITE_BUILD_HASH}
                SHOW_PROGRESS
        )
endif()

# unpack zip only if needed
if(NOT EXISTS ${SQLITE_SUBDIR})
        file(ARCHIVE_EXTRACT
                INPUT ${CMAKE_CURRENT_SOURCE_DIR}/sqlite.zip
                DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}
        )
endif()

# Create SQLite library
add_library(sqlite3 STATIC "${SQLITE_SUBDIR}/sqlite3.c")

target_include_directories(sqlite3 PUBLIC
        $<BUILD_INTERFACE:${SQLITE_SUBDIR}>
        $<INSTALL_INTERFACE:include>
)

# Export variables to parent scope
set(SQLITE_INCLUDE_DIRS ${SQLITE_SUBDIR} PARENT_SCOPE)
set(SQLITE_SOURCE "${SQLITE_SUBDIR}/sqlite3.c" PARENT_SCOPE)
