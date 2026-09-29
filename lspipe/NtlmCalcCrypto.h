#pragma once

#include <vector>
#include <Windows.h>
#include "BcryptHmac.h"
#include "utils.h"
#include <bcrypt.h>

// NT Hash One-Way function version2 
bool NTOWFv2(std::wstring user,
	std::wstring password,
	std::wstring domain,
	std::vector<uint8_t> nthash,
	std::vector<uint8_t>& hashResult
	);

std::vector<uint8_t> GenerateEncryptedSessionKey(std::vector<byte> RandomSessionKey, std::vector<byte> keyExchange);

std::vector<uint8_t> DecryptSessionKey(std::vector<uint8_t> encryptedSessionKey, std::vector<uint8_t> keyExchange);
