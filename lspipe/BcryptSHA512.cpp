#include "BcryptSHA512.h"


bool BcryptSHA512(std::vector<byte> vByteBuffer, std::vector<byte>& hashResult)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD cbData = 0;
    DWORD objectSize = 0;
    DWORD hashLength = 0;

    std::vector<byte> vHashObject;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, nullptr, 0))
    {
        return false;
    }

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objectSize, sizeof(DWORD), &cbData, 0))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    vHashObject.resize(objectSize);
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashLength, sizeof(DWORD), &cbData, 0))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    hashResult.resize(hashLength);

    if (BCryptCreateHash(hAlg, &hHash, vHashObject.data(), objectSize, NULL, 0, 0))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    if (BCryptHashData(hHash, (PUCHAR)vByteBuffer.data(), vByteBuffer.size(), 0))
    {
        BCryptDestroyKey(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }


    if (BCryptFinishHash(hHash, hashResult.data(), hashLength, 0))
    {
        return false;
    }

    return true;
}


