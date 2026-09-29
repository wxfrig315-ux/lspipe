#pragma once

#include <vector>
#include <Windows.h>
#include <objbase.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <random>
#include <map>

#pragma comment(lib, "ole32.lib")

template <typename T>
std::vector<T> concat(const std::vector<T>& a, const std::vector<T>& b)
{
    std::vector<T> result = a;
    result.insert(result.end(), b.begin(), b.end());
    return result;
}

GUID generateClientGuid();

void appendLE(std::vector<uint8_t>& buffer, uint8_t value);

void appendLE(std::vector<uint8_t>& buffer, uint16_t value);

void appendLE(std::vector<uint8_t>& buffer, uint32_t value);

void appendLE(std::vector<uint8_t>& buffer, uint64_t value);

std::vector<uint8_t> wstringToBytes(const std::wstring& wstr);

std::vector<uint8_t> genRandomHexVector(size_t length);


uint32_t calcCreditCharge(uint32_t SendPayloadSize, uint32_t ResponsePayloadSize = 1024);

std::vector<uint8_t> hexStringToBytes(const std::wstring& hex);

// UTF-8 <-> UTF-16 conversion helpers used for std::cout/std::cin interaction.
std::string wideToUtf8(const std::wstring& w);

std::wstring utf8ToWide(const std::string& s);

// Prints a wide string to std::cout as UTF-8 and flushes the stream.
void LogW(const std::wstring& msg);
