#include "utils.h"

GUID generateClientGuid()
{
    GUID guidOut{};
    if ((CoCreateGuid(&guidOut) == S_OK))
    {
        return guidOut;
    }
    guidOut.Data1 = 0x31bb91628fb9;
    guidOut.Data2 = 0x4b3e;
    guidOut.Data3 = 0x8f41;
    size_t data4 = 0x615c85b8979c;
    memcpy(guidOut.Data4, &data4, 8);
    return  guidOut;
}

void appendLE(std::vector<uint8_t>& buffer, uint8_t value)
{
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

void appendLE(std::vector<uint8_t>& buffer, uint16_t value)
{
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void appendLE(std::vector<uint8_t>& buffer, uint32_t value)
{
    for (int i = 0; i < 4; ++i)
    {
        buffer.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

void appendLE(std::vector<uint8_t>& buffer, uint64_t value)
{
    for (int i = 0; i < 8; ++i)
    {
        buffer.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

std::vector<uint8_t> wstringToBytes(const std::wstring& wstr)
{
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(wstr.data()),
        reinterpret_cast<const uint8_t*>(wstr.data()) + wstr.size() * sizeof(wchar_t)
    );
}

std::vector<uint8_t> genRandomHexVector(size_t length)
{
    // Random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15); // Hex digits range from 0 to 15 (0-F)

    std::vector<uint8_t> hexVec;

    // Generate random hex values and store them in the vector
    for (size_t i = 0; i < length; ++i) {
        uint8_t randHex = static_cast<uint8_t>(dis(gen));
        hexVec.push_back(randHex);
    }

    return hexVec;
}

uint32_t calcCreditCharge(uint32_t SendPayloadSize, uint32_t ResponsePayloadSize)
{
    return (max(SendPayloadSize, ResponsePayloadSize) - 1) / 65536 + 1;
}

std::vector<uint8_t> hexStringToBytes(const std::wstring& hex)
{
    std::vector<uint8_t> bytes;

    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::wstring byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

std::string wideToUtf8(const std::wstring& w)
{
    if (w.empty())
    {
        return std::string();
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0)
    {
        return std::string();
    }

    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &out[0], size, nullptr, nullptr);
    return out;
}

std::wstring utf8ToWide(const std::string& s)
{
    if (s.empty())
    {
        return std::wstring();
    }

    const int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (size <= 0)
    {
        return std::wstring();
    }

    std::wstring out(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], size);
    return out;
}

void LogW(const std::wstring& msg)
{
    std::cout << wideToUtf8(msg);
    std::cout.flush();
}
