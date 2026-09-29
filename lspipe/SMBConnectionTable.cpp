#include "SMBConnectionTable.h"


ConnectionTable::ConnectionTable()
{
	preHashAuth.assign(64, 0);
	RandomSessionKey = genRandomHexVector(16);
}




std::vector<uint8_t> ConnectionTable::signPacket(std::vector<uint8_t> packetBuffer)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::vector<uint8_t> mac;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_CMAC_ALGORITHM, nullptr, 0)))
    {
        return mac;
    }

    
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0,
        const_cast<uint8_t*>(this->signingKey.data()),
        static_cast<ULONG>(this->signingKey.size()), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return mac;
    }

    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, const_cast<uint8_t*>(packetBuffer.data()),
        static_cast<ULONG>(packetBuffer.size()), 0)))
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return mac;
    }

    ULONG macLength = 0;
    ULONG resultSize = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&macLength),
        sizeof(macLength), &resultSize, 0))) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return mac;
    }

    mac.resize(macLength);

    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, mac.data(), macLength, 0))) {
        mac.clear();
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return mac;
}

void ConnectionTable::UpdateConnectionPreAuthHash(std::vector<byte> vByteBuffer)
{
    this->preHashAuth.insert(preHashAuth.end(), vByteBuffer.begin(), vByteBuffer.end());

    BcryptSHA512(preHashAuth, preHashAuth);

}

bool ConnectionTable::DeriveKeyCounterMode( const std::vector<uint8_t>& label, const std::vector<uint8_t>& context, std::vector<uint8_t>& derivedKey, DWORD derivedKeyLengthBits)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    DWORD resultLength = 0;

    // Open HMAC algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SP800108_CTR_HMAC_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    // Generate key handle from key material
    status = BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        nullptr, 0,
        (PUCHAR)this->RandomSessionKey.data(),
        static_cast<ULONG>(this->RandomSessionKey.size()),
        0);
    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Prepare KDF parameters
    DWORD keyLengthBytes = derivedKeyLengthBits / 8;

    BCryptBuffer kdfBuffers[3];

    kdfBuffers[0].BufferType = KDF_LABEL;
    kdfBuffers[0].pvBuffer = (PVOID)label.data();
    kdfBuffers[0].cbBuffer = static_cast<ULONG>(label.size());

    kdfBuffers[1].BufferType = KDF_CONTEXT;
    kdfBuffers[1].pvBuffer = (PVOID)context.data();
    kdfBuffers[1].cbBuffer = static_cast<ULONG>(context.size());

    kdfBuffers[2].BufferType = KDF_TARGET_LENGTH;
    kdfBuffers[2].pvBuffer = &keyLengthBytes;
    kdfBuffers[2].cbBuffer = sizeof(DWORD);

    BCryptBufferDesc params = 
    {
        BCRYPTBUFFER_VERSION,
        3,
        kdfBuffers
    };

    derivedKey.resize(keyLengthBytes);

    // Perform key derivation
    status = BCryptKeyDerivation(
        hKey,
        &params,
        derivedKey.data(),
        keyLengthBytes,
        &resultLength,
        0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    return true;
}
