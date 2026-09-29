#include"BcryptHmac.h"


bool BcryptHmacMd5Hash(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key,std::vector<uint8_t>& hashResult)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status;
    DWORD cbData = 0, cbHashObject = 0, cbHash = 0;
    std::vector<uint8_t> hashObject;
    std::wstringstream logger;
    // 1. Open algorithm provider for HMAC-MD5
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_MD5_ALGORITHM,     // Use MD5
        nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG); // Enable HMAC mode

    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    // 2. Get hash object size
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 3. Allocate hash object buffer
    hashObject.resize(cbHashObject);

    // 4. Get hash length
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) 
    {

      
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    hashResult.resize(cbHash);

    // 5. Create hash
    status = BCryptCreateHash(
        hAlg,
        &hHash,
        hashObject.data(),
        cbHashObject,
        (PUCHAR)key.data(),
        (ULONG)key.size(),
        0);

    if (!BCRYPT_SUCCESS(status)) 
    {

        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 6. Hash data
    status = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    if (!BCRYPT_SUCCESS(status)) 
    {

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 7. Finalize hash
    status = BCryptFinishHash(hHash, hashResult.data(), cbHash, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        // Cleanup
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return true;
    }

   
}


bool BcryptMd4Hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hashResult)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status;
    DWORD hashObjectSize = 0;
    DWORD hashLength = 0;
    DWORD cbData = 0;

    // 1. Open algorithm provider for MD4
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_MD4_ALGORITHM,   // Use MD4
        nullptr,
        0);

    if (!BCRYPT_SUCCESS(status))
        return false;

    // 2. Get size of the hash object
    status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hashObjectSize),
        sizeof(DWORD),
        &cbData,
        0);

    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 3. Get length of the hash
    status = BCryptGetProperty(
        hAlg,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashLength),
        sizeof(DWORD),
        &cbData,
        0);

    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 4. Allocate buffers
    std::vector<uint8_t> hashObject(hashObjectSize);
    hashResult.resize(hashLength);

    // 5. Create hash handle
    status = BCryptCreateHash(
        hAlg,
        &hHash,
        hashObject.data(),
        hashObjectSize,
        nullptr,
        0,
        0);

    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 6. Hash the input data
    status = BCryptHashData(
        hHash,
        const_cast<PUCHAR>(data.data()),
        static_cast<ULONG>(data.size()),
        0);

    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 7. Finalize the hash
    status = BCryptFinishHash(
        hHash,
        hashResult.data(),
        hashLength,
        0);

    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 8. Clean up
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return true;
}





