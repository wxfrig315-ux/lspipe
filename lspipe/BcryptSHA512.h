#pragma once

#include<Windows.h>
#include <vector>
#include<bcrypt.h>
#include <iostream>
#include <sstream>
#include <ntstatus.h>

#pragma comment(lib, "bcrypt.lib")

bool BcryptSHA512(std::vector<byte> vByteBuffer, std::vector<byte>& hashResult);
