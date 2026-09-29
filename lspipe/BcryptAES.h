#pragma once

#include<Windows.h>
#include<vector>
#include<bcrypt.h>
#include <iostream>
#include <sstream>

#include <ntstatus.h>

#pragma comment(lib, "bcrypt.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

NTSTATUS AESCCM_Encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& plainText,
    std::vector<uint8_t>& cipherText,
    std::vector<uint8_t>& authTag);

// Hàm giải mã
NTSTATUS AESCCM_Decrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& cipherText,
    const std::vector<uint8_t>& authTag,
    std::vector<uint8_t>& decryptedText);