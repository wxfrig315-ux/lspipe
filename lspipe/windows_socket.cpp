#include "windows_socket.h"



SocketClient::SocketClient(const std::wstring& target, int port)
    : host_(target), port_(port), sock_(INVALID_SOCKET)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

SocketClient::SocketClient()
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

SocketClient::~SocketClient()
{
    if (sock_ != INVALID_SOCKET)
    {
        closesocket(sock_);
    }
    WSACleanup();
}

bool SocketClient::connectToServer()
{
    ADDRINFOW hints = {};
    hints.ai_family = AF_INET;        // IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /*wchar_t portStr[6];
    _snwprintf_s(portStr, _countof(portStr), _TRUNCATE, L"%d",this->port_);*/

    std::wstring portStr = std::to_wstring(this->port_);

    ADDRINFOW* result = nullptr;
    int res = GetAddrInfoW(host_.c_str(), portStr.c_str(), &hints, &result);
    if (res != 0 || !result)
    {
        std::cout << "GetAddrInfoW failed: " << res << std::endl;
        return false;
    }

    sock_ = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock_ == INVALID_SOCKET)
    {
        std::cout << "Socket creation failed" << std::endl;
        FreeAddrInfoW(result);
        return false;
    }

    if (connect(sock_, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR)
    {
        std::cout << "Connection failed" << std::endl;
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
        FreeAddrInfoW(result);
        return false;
    }

    FreeAddrInfoW(result);
    return true;
}

bool SocketClient::sendData()
{
    if (sock_ == INVALID_SOCKET || send_buf.empty()) 
    {
        return false;
    }

    size_t totalSent = 0;
    while (totalSent < send_buf.size())
    {
        int sent = send(sock_, reinterpret_cast<const char*>(send_buf.data() + totalSent), (int)(send_buf.size() - totalSent), 0);
        if (sent == SOCKET_ERROR) return false;
        totalSent += sent;
    }
    return true;
}

bool SocketClient::receiveData(size_t size)
{
    recv_buf.clear();
    if (size == 0)
    {
        return true;
    }

    recv_buf.resize(size);
    size_t totalReceived = 0;
    while (totalReceived < size)
    {
        int chunk = recv(sock_, reinterpret_cast<char*>(recv_buf.data() + totalReceived), static_cast<int>(size - totalReceived), 0);
        if (chunk <= 0)
        {
            return false;
        }
        totalReceived += static_cast<size_t>(chunk);
    }
    return true;
}
