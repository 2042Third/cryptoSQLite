/*
 * Copyright (C) 2020 The ViaDuck Project
 *
 * This file is part of cryptoSQLite.
 *
 * cryptoSQLite is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cryptoSQLite is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with cryptoSQLite.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CRYPTOSQLITE_VFS_H
#define CRYPTOSQLITE_VFS_H

#include "../file/File.h"
#include "../csqlite/SQLite3Mutex.h"

class VFS {
public:
    static VFS *instance() {
        return &sInstance;
    }

    /**
     * Call before opening main db to prepare reading the encrypted file header
     * Sets this VFS as default. Only one db can be prepared at a time
     *
     * @param zKey Optional key pointer
     * @param nKey Optional key size
     */
    void prepare(const void *zKey, int nKey);

    /**
     * Automatically called on opening any file (db, journal, wal, ...)
     *
     * @param zName Optional file name
     * @param pFile Pointer to preallocated file structure(s)
     * @param flags Opening flags
     * @param pOutFlags Return flags
     * @return Standard sqlite error code
     */
    int open(const char* zName, sqlite3_file* pFile, int flags, int* pOutFlags);

    /**
     * Call after opening the main db to finish setup and clean up resources
     * Removes this VFS as default.
     *
     * @param db Database pointer that was just opened
     * @param nDb Database number for attached databases
     */
    void finish();

    sqlite3_vfs *base() {
        return &mBase;
    }
    sqlite3_vfs *underlying() {
        return mUnderlying;
    }

    File *findMainDatabase(const char *name);
    void removeDatabase(File *db);

protected:
    VFS();
    ~VFS();
    void addDatabase(File *db);

    sqlite3_vfs mBase;
    /**/
    sqlite3_vfs *mUnderlying;
    SQLite3Mutex mMutex;
    std::vector<File *> *mDBs;
    const void *mFileKey;
    int mFileKeySize;

    static VFS sInstance;
};

namespace {
    #define VFS_REAL(x) reinterpret_cast<VFS *>(x)->underlying()

    int sVfsOpen(sqlite3_vfs* pVfs, const char* zName, sqlite3_file* pFile, int flags, int* pOutFlags) {
      return reinterpret_cast<VFS *>(pVfs)->open(zName,pFile,flags, pOutFlags);
    }
    int sVfsDelete(sqlite3_vfs* pVfs, const char* zName, int syncDir) {
      return VFS_REAL(pVfs)->xDelete(VFS_REAL(pVfs),zName,syncDir);
    }
    int sVfsAccess(sqlite3_vfs* pVfs, const char* zName, int flags, int* pResOut) {
      return VFS_REAL(pVfs)->xAccess(VFS_REAL(pVfs),zName,flags,pResOut);
    }
    int sVfsFullPathname(sqlite3_vfs* pVfs, const char* zName, int nOut, char* zOut) {
      return VFS_REAL(pVfs)->xFullPathname(VFS_REAL(pVfs),zName,nOut,zOut);
    }
    void* sVfsDlOpen(sqlite3_vfs* pVfs, const char* zFilename) {
      return VFS_REAL(pVfs)->xDlOpen(VFS_REAL(pVfs),zFilename);
    }
    void sVfsDlError(sqlite3_vfs* pVfs, int nByte, char* zErrMsg) {
      return VFS_REAL(pVfs)->xDlError(VFS_REAL(pVfs),nByte,zErrMsg);
    }
    void (*sVfsDlSym(sqlite3_vfs* pVfs, void* p, const char* zSymbol))(void) {
      return VFS_REAL(pVfs)->xDlSym(VFS_REAL(pVfs),p,zSymbol);
    }
    void sVfsDlClose(sqlite3_vfs* pVfs, void* p) {
      return VFS_REAL(pVfs)->xDlClose(VFS_REAL(pVfs),p);
    }
    int sVfsRandomness(sqlite3_vfs* pVfs, int nByte, char* zOut) {
      return VFS_REAL(pVfs)->xRandomness(VFS_REAL(pVfs),nByte,zOut);
    }
    int sVfsSleep(sqlite3_vfs* pVfs, int microseconds) {
      return VFS_REAL(pVfs)->xSleep(VFS_REAL(pVfs),microseconds);
    }
    int sVfsCurrentTime(sqlite3_vfs* pVfs, double* pOut) {
      return VFS_REAL(pVfs)->xCurrentTime(VFS_REAL(pVfs),pOut);
    }
    int sVfsGetLastError(sqlite3_vfs* pVfs, int nErr, char* zOut) {
      return VFS_REAL(pVfs)->xGetLastError(VFS_REAL(pVfs),nErr,zOut);
    }
    int sVfsCurrentTimeInt64(sqlite3_vfs* pVfs, sqlite3_int64* pOut) {
      return VFS_REAL(pVfs)->xCurrentTimeInt64(VFS_REAL(pVfs),pOut);
    }
    int sVfsSetSystemCall(sqlite3_vfs* pVfs, const char* zName, sqlite3_syscall_ptr pNewFunc) {
      return VFS_REAL(pVfs)->xSetSystemCall(VFS_REAL(pVfs),zName,pNewFunc);
    }
    sqlite3_syscall_ptr sVfsGetSystemCall(sqlite3_vfs* pVfs, const char* zName) {
      return VFS_REAL(pVfs)->xGetSystemCall(VFS_REAL(pVfs),zName);
    }
    const char* sVfsNextSystemCall(sqlite3_vfs* pVfs, const char* zName) {
      return VFS_REAL(pVfs)->xNextSystemCall(VFS_REAL(pVfs),zName);
    }
}

/* Assert that these classes can be used as derived structs with aligned first members */
static_assert(std::is_standard_layout<VFS>::value, "VFS: Invalid class layout.");

#endif //CRYPTOSQLITE_VFS_H
