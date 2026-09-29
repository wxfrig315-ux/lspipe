#include "BcryptAES.h"

NTSTATUS AESCCM_Encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& aad, const std::vector<uint8_t>& plainText, std::vector<uint8_t>& cipherText, std::vector<uint8_t>& authTag)
{
    BCRYPT_ALG_HANDLE algorithmHandle = NULL;
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    NTSTATUS status;

    // Open AES algorithm provider with CCM chaining mode
    status = BCryptOpenAlgorithmProvider(
        &algorithmHandle,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = BCryptSetProperty(
        algorithmHandle,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CCM,
        (ULONG)sizeof(BCRYPT_CHAIN_MODE_CCM),
        0
    );
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(algorithmHandle, 0);
        return status;
    }

    // Generate symmetric key
    status = BCryptGenerateSymmetricKey(
        algorithmHandle,
        &keyHandle,
        NULL,
        0,
        (PUCHAR)key.data(),
        (ULONG)key.size(),
        0
    );
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(algorithmHandle, 0);
        return status;
    }

    // Set up CCM authentication information
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    authInfo.pbNonce = (PUCHAR)nonce.data();
    authInfo.cbNonce = (ULONG)nonce.size();
    authInfo.pbAuthData = (PUCHAR)aad.data();
    authInfo.cbAuthData = (ULONG)aad.size();
    authInfo.pbTag = (PUCHAR)authTag.data();
    authInfo.cbTag = (ULONG)authTag.size();
    authInfo.cbData = 0;

    // Prepare output buffer
    ULONG ciphertextSize = (ULONG)plainText.size();
    cipherText.resize(ciphertextSize);

    // Perform encryption
    status = BCryptEncrypt(
        keyHandle,
        (PUCHAR)plainText.data(),
        (ULONG)plainText.size(),
        &authInfo,
        NULL,
        0,
        (PUCHAR)cipherText.data(),
        ciphertextSize,
        &ciphertextSize,
        0
    );
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        BCryptCloseAlgorithmProvider(algorithmHandle, 0);
        return status;
    }

    // Cleanup
    BCryptDestroyKey(keyHandle);
    BCryptCloseAlgorithmProvider(algorithmHandle, 0);

    return STATUS_SUCCESS;
}

NTSTATUS AESCCM_Decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& aad, const std::vector<uint8_t>& cipherText, const std::vector<uint8_t>& authTag, std::vector<uint8_t>& decryptedText)

{
    BCRYPT_ALG_HANDLE algorithmHandle = NULL;
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    NTSTATUS status;

    // Open AES algorithm provider in CCM mode
    status = BCryptOpenAlgorithmProvider(
        &algorithmHandle,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BCryptSetProperty(
        algorithmHandle,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CCM,
        (ULONG)sizeof(BCRYPT_CHAIN_MODE_CCM),
        0
    );
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(algorithmHandle, 0);
        return status;
    }

    // Generate symmetric key
    status = BCryptGenerateSymmetricKey(
        algorithmHandle,
        &keyHandle,
        NULL,
        0,
        const_cast<PUCHAR>(key.data()),
        (ULONG)key.size(),
        0
    );
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(algorithmHandle, 0);
        return status;
    }

    // Set up authentication info for CCM
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    authInfo.pbNonce = const_cast<PUCHAR>(nonce.data());
    authInfo.cbNonce = (ULONG)nonce.size();
    authInfo.pbAuthData = const_cast<PUCHAR>(aad.data());
    authInfo.cbAuthData = (ULONG)aad.size();
    authInfo.pbTag = const_cast<PUCHAR>(authTag.data());
    authInfo.cbTag = (ULONG)authTag.size();
    authInfo.cbData = 0;

    // Prepare output buffer
    decryptedText.resize(cipherText.size());
    ULONG outputLen = 0;

    status = BCryptDecrypt(
        keyHandle,
        const_cast<PUCHAR>(cipherText.data()),
        (ULONG)cipherText.size(),
        &authInfo,
        NULL,
        0,
        decryptedText.data(),
        (ULONG)decryptedText.size(),
        &outputLen,
        0
    );

    if (!NT_SUCCESS(status)) {
        decryptedText.clear(); // Clear any partial data on failure
        BCryptDestroyKey(keyHandle);
        BCryptCloseAlgorithmProvider(algorithmHandle, 0);
        return status;
    }

    decryptedText.resize(outputLen); // Resize to actual decrypted length

    // Cleanup
    BCryptDestroyKey(keyHandle);
    BCryptCloseAlgorithmProvider(algorithmHandle, 0);

    return STATUS_SUCCESS;
}
