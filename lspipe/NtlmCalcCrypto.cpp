#include "NtlmCalcCrypto.h"

bool NTOWFv2(std::wstring user, std::wstring password, std::wstring domain, std::vector<uint8_t> nthash, std::vector<uint8_t>& hashResult)
{
    std::vector<uint8_t> vUser;
    std::vector<uint8_t> vNtHash;
    std::vector<uint8_t> vDomain;
    std::vector<uint8_t> vPassword = wstringToBytes(password);
    if (nthash.empty() == false)
    {
        vNtHash = nthash;
    }
    else
    {
        BcryptMd4Hash(vPassword, vNtHash);
    }

    std::transform(user.begin(), user.end(), user.begin(),
        [](auto c) { return std::toupper(c); });
   
    vDomain = wstringToBytes(domain);
    vUser = wstringToBytes(user);

    vUser = concat(vUser, vDomain);
    BcryptHmacMd5Hash(vUser, vNtHash, hashResult);
    return true;
}

std::vector<uint8_t> GenerateEncryptedSessionKey(std::vector<byte> RandomSessionKey, std::vector<byte> keyExchange)
{
    BCRYPT_ALG_HANDLE rc4Handle = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    DWORD cbKeyObject = 0, cbData = 0, cbCipherText = 0;
    std::vector<uint8_t> keyObject;
    std::vector<uint8_t> ciphertext(RandomSessionKey.size(), 0);
    status = BCryptOpenAlgorithmProvider(&rc4Handle, BCRYPT_RC4_ALGORITHM, nullptr, 0);


    status = BCryptGetProperty(rc4Handle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(ULONG), &cbData, 0);
    keyObject.resize(cbKeyObject);

    status = BCryptGenerateSymmetricKey(rc4Handle, &hKey, keyObject.data(), cbKeyObject, keyExchange.data(), keyExchange.size(), 0);

    if (status != 0)
    {
        return std::vector <uint8_t>();
    }

    status = BCryptEncrypt(hKey, RandomSessionKey.data(), RandomSessionKey.size(), nullptr, nullptr, 0, ciphertext.data(), ciphertext.size(), &cbCipherText, 0);

    if (status != 0)
    {
        return std::vector <uint8_t>();
    }
    if (hKey)
    {
        BCryptDestroyKey(hKey);
    }

    if (rc4Handle)
    {
        BCryptCloseAlgorithmProvider(rc4Handle, 0);
    }

    return ciphertext;
}

std::vector<uint8_t> DecryptSessionKey(std::vector<uint8_t> encryptedSessionKey, std::vector<uint8_t> keyExchange)
{
    BCRYPT_ALG_HANDLE rc4Handle = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    DWORD cbKeyObject = 0, cbData = 0, cbPlainText = 0;
    std::vector<uint8_t> keyObject;
    std::vector<uint8_t> plaintext(encryptedSessionKey.size(), 0);

    // Mở provider cho thuật toán RC4
    status = BCryptOpenAlgorithmProvider(&rc4Handle, BCRYPT_RC4_ALGORITHM, nullptr, 0);
    if (status != 0)
        return {};

    // Lấy kích thước vùng nhớ cho key object
    status = BCryptGetProperty(rc4Handle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(ULONG), &cbData, 0);
    if (status != 0)
    {
        BCryptCloseAlgorithmProvider(rc4Handle, 0);
        return {};
    }

    // Cấp phát vùng nhớ cho key object
    keyObject.resize(cbKeyObject);

    // Tạo symmetric key từ keyExchange
    status = BCryptGenerateSymmetricKey(rc4Handle, &hKey, keyObject.data(), cbKeyObject,
        keyExchange.data(), keyExchange.size(), 0);
    if (status != 0)
    {
        BCryptCloseAlgorithmProvider(rc4Handle, 0);
        return {};
    }

    // Giải mã dữ liệu
    status = BCryptDecrypt(hKey, encryptedSessionKey.data(), encryptedSessionKey.size(),
        nullptr, nullptr, 0, plaintext.data(), plaintext.size(), &cbPlainText, 0);
    if (status != 0)
    {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(rc4Handle, 0);
        return {};
    }

    // Dọn dẹp
    if (hKey)
        BCryptDestroyKey(hKey);
    if (rc4Handle)
        BCryptCloseAlgorithmProvider(rc4Handle, 0);

    // Trả về dữ liệu đã giải mã
    return plaintext;
}