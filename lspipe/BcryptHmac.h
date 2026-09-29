#pragma once

#include<Windows.h>
#include<vector>
#include<bcrypt.h>
#include <iostream>
#include <sstream>


#pragma comment(lib, "bcrypt.lib")

bool BcryptHmacMd5Hash(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, std::vector<uint8_t> &hashResult);

bool BcryptMd4Hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hashResult);


