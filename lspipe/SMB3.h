#pragma once
#include "windows_socket.h"
#include <vector>
#include "utils.h"
#include "SMBConnectionTable.h"
#include "SMB3Negotiate.h"
#include "SMB2SessionSetup.h"
#include "SMB3TranformPacket.h"
#include "SMB2TreeConnect.h"
#include "SMB2QueryDirectory.h"
#include "SMB2CreateRequest.h"
#include "SMB2QueryDirectoryResponse.h"
#include "SMB2CloseRequest.h"
#include "SMB2Logoff.h"
#include "SmbClient.h"

class SMB3
{
public:
	ConnectionTable SessionInfo;

	SMB3();
	~SMB3() = default;
	bool SMB3Login(SmbClient& s_client,
		std::wstring username, 
		std::wstring domain, 
		std::wstring password, 
		std::wstring NtHash);

	bool SMB3ListTree(SmbClient& s_client,
		std::wstring treeConnect, 
		std::wstring pattern);
private:

};


