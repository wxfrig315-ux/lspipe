#pragma once
#include "windows_socket.h"
#include "SMB2Header.h"
#include "SMB2BasePacket.h"
#include "SMB2Negotiate.h"
#include "utils.h"
#include "SMB2SessionSetup.h"
#include "NtlmCalcCrypto.h"
#include "SmbClient.h"

bool SMB2Login(SmbClient &s_client, std::wstring username,std::wstring domain = L"", std::wstring password = L"", std::wstring NTLMHash = L"");
