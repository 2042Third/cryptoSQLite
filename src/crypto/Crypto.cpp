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
#include "Crypto.h"

#include "FileWrapper.h"
#include <cryptosqlite/cryptosqlite.h>

Crypto::Crypto(const std::string &dbFileName, const void *fileKey, int keylen, int exists)
        : mFileName(dbFileName + "-keyfile") {
    cryptosqlite::makeDataCrypt(mDataCrypt);

    if (!exists) {
        // generate new key and wrap it to buffer
        mDataCrypt->generateKey(mKey);
        wrapKey(fileKey, keylen);
    }
    else {
        // read existing keyfile and unwrap key
        readKeyFile();
        unwrapKey(fileKey, keylen);
    }
}

void Crypto::rekey(const void *newFileKey, int keylen) {
    wrapKey(newFileKey, keylen);
    writeKeyFile();
}

void Crypto::wrapKey(const void *fileKey, int keylen) {
    Buffer wrappingKey;
    wrappingKey.write(fileKey, keylen, 0);

    mWrappedKey.clear();
    mDataCrypt->wrapKey(mWrappedKey, mKey, wrappingKey);
}

void Crypto::unwrapKey(const void *fileKey, int keylen) {
    Buffer wrappingKey;
    wrappingKey.write(fileKey, keylen, 0);

    mKey.clear();
    mDataCrypt->unwrapKey(mKey, mWrappedKey, wrappingKey);
}

void Crypto::writeKeyFile() {
    // std::cout << "=== Writing Keyfile (Secure) ===" << std::endl;

    // Prepare temporary buffer with secure cleanup
    struct SecureBuffer {
        uint8_t* data;
        size_t size;

        explicit SecureBuffer(size_t s) : data(new uint8_t[s]), size(s) {}
        ~SecureBuffer() {
            if (data) {
                // Secure wipe
                for(size_t i = 0; i < size; i++)
                    data[i] = 0;
                delete[] data;
            }
        }
    };

    try {
        FILE* file = fopen(mFileName.c_str(), "wb");
        if (!file) throw std::runtime_error("Failed to open keyfile");

        // Write wrapped key with secure handling
        {
            uint32_t keySize = mWrappedKey.size();
            SecureBuffer tempBuf(keySize);
            memcpy(tempBuf.data, mWrappedKey.const_data(), keySize);

            fwrite(&keySize, sizeof(keySize), 1, file);
            fwrite(tempBuf.data, 1, keySize, file);
        }

        // Write first page with secure handling
        {
            uint32_t pageSize = mFirstPage.size();
            if (pageSize > 0) {
                SecureBuffer tempBuf(pageSize);
                memcpy(tempBuf.data, mFirstPage.const_data(), pageSize);

                fwrite(&pageSize, sizeof(pageSize), 1, file);
                fwrite(tempBuf.data, 1, pageSize, file);
            }
        }

        fflush(file);
        fclose(file);
        // std::cout << "Keyfile written successfully" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error writing keyfile: " << e.what() << std::endl;
        throw;
    }
}


void Crypto::readKeyFile() {
    // Prepare temporary buffer with secure cleanup
    struct SecureBuffer {
        uint8_t* data;
        size_t size;

        explicit SecureBuffer(size_t s) : data(new uint8_t[s]), size(s) {}
        ~SecureBuffer() {
            if (data) {
                // Secure wipe
                for(size_t i = 0; i < size; i++)
                    data[i] = 0;
                delete[] data;
            }
        }
    };

    // std::cout << "=== Reading Keyfile (Secure) ===" << std::endl;

    try {
        FILE* file = fopen(mFileName.c_str(), "rb");
        if (!file) throw std::runtime_error("Failed to open keyfile");

        // Read wrapped key
        uint32_t keySize;
        if (fread(&keySize, sizeof(keySize), 1, file) != 1)
            throw std::runtime_error("Failed to read key size");

        {
            SecureBuffer tempBuf(keySize);
            if (fread(tempBuf.data, 1, keySize, file) != keySize)
                throw std::runtime_error("Failed to read key data");

            mWrappedKey.clear();
            mWrappedKey.write(tempBuf.data, keySize, 0);
        }

        // Read first page
        uint32_t pageSize;
        if (fread(&pageSize, sizeof(pageSize), 1, file) != 1)
            throw std::runtime_error("Failed to read page size");

        if (pageSize > 0) {
            SecureBuffer tempBuf(pageSize);
            if (fread(tempBuf.data, 1, pageSize, file) != pageSize)
                throw std::runtime_error("Failed to read page data");

            mFirstPage.clear();
            mFirstPage.write(tempBuf.data, pageSize, 0);
        }

        fclose(file);
        // std::cout << "Keyfile read successfully" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error reading keyfile: " << e.what() << std::endl;
        throw;
    }
}


const void *Crypto::encryptPage(const void *page, uint32_t pageSize, int pageNo) {
    // copy plaintext to input buffer
    mPageBufferIn.write(page, pageSize, 0);
    // encrypt to output buffer
    mDataCrypt->encrypt(pageNo, mPageBufferIn, mPageBufferOut, mKey);
    // cache encrypted first page and write it to keyfile
    if (pageNo == 1) {
        mFirstPage.clear();
        mFirstPage.write(mPageBufferOut, 0);
        writeKeyFile();
    }
    // return pointer to point to ciphertext
    return pageBufferOut();
}

void Crypto::decryptPage(void *pageInOut, uint32_t pageSize, int pageNo) {
    // copy ciphertext to input buffer
    if (pageInOut) mPageBufferIn.write(pageInOut, pageSize, 0);
    // decrypt to output buffer
    mDataCrypt->decrypt(pageNo, mPageBufferIn, mPageBufferOut, mKey);
    // overwrite ciphertext with plaintext
    if (pageInOut) memcpy(pageInOut, pageBufferOut(), pageSize);
}

void Crypto::decryptFirstPageCache() {
    // fit page buffers to cache or minimum page size if cache empty
    resizePageBuffers((std::max)(mFirstPage.size(), 512u));
    // decrypt first page from cache or leave 0-bytes if cache empty
    if (mFirstPage.size() > 0) mDataCrypt->decrypt(1, mFirstPage, mPageBufferOut, mKey);
}

void Crypto::resizePageBuffers(uint32_t size) {
    mPageBufferIn.clear();
    mPageBufferIn.padd(size, 0);

    mPageBufferOut.clear();
    mPageBufferOut.padd(size, 0);
}

uint32_t Crypto::extraSize() {
    return mDataCrypt->extraSize();
}
