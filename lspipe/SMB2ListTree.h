#include "windows_socket.h"
#include "SMB2BasePacket.h"
#include "SMB2QueryDirectory.h"
#include "SMB2QueryDirectoryResponse.h"
#include "SMB2TreeConnect.h"
#include "SMB2CreateRequest.h"
#include <sstream>
#include "SmbClient.h"

bool SMB2ListTree(std::wstring treeConnect, std::wstring pattern, SmbClient &s_client);