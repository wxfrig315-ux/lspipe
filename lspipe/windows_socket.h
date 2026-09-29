#pragma once
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <string>
#include<vector>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

class SocketClient
{
public:
    SocketClient(const std::wstring& target, int port);
    SocketClient();
    ~SocketClient();

    bool connectToServer();
    bool sendData();
    bool receiveData(size_t size=1024);
    std::vector<uint8_t> send_buf;
    std::vector<uint8_t> recv_buf;
    std::wstring host_;
    int port_;
private:
    SOCKET sock_;
};


