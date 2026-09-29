
#include "lspipe.h"
#include "SMB2Login.h"
#include "SMB2ListTree.h"
#include "utils.h"


void pipe_list()
{
    std::wstringstream logger;
    std::vector<BYTE> buffer(4096);
    IO_STATUS_BLOCK iosb{};
    BOOLEAN restartScan = TRUE;
    HANDLE hPipeDir = nullptr;
    NtQueryDirectoryFile_t NtQueryDirectoryFile;

    // Load ntdll.dll to get native API
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (!hNtdll)
    {
        LogW(L"[-] Failed to load ntdll.dll\n");
        return;
    }

    NtQueryDirectoryFile = reinterpret_cast<NtQueryDirectoryFile_t>(GetProcAddress(hNtdll, "NtQueryDirectoryFile"));

    if (!NtQueryDirectoryFile)
    {
        LogW(L"[-] Failed to get NtQueryDirectoryFile address\n");
        FreeLibrary(hNtdll);
        return;
    }


    // Open a handle to the Named Pipe root directory
    hPipeDir = CreateFileW(
        L"\\\\.\\pipe\\",
        FILE_LIST_DIRECTORY | GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );

    if (hPipeDir == INVALID_HANDLE_VALUE)
    {
        LogW(L"[-] Failed to open \\\\.\\pipe\\ directory. Error: " + std::to_wstring(GetLastError()) + L"\n");
        FreeLibrary(hNtdll);
        return;
    }



    logger << std::left << std::setw(100) << L"Pipe Name"
        << std::setw(20) << L"Instances"
        << std::setw(20) << L"Max Instances"
        << std::setw(10) << L"ProcessID" << std::endl;

    logger << std::left << std::setw(100) << std::wstring(10, L'-')
        << std::setw(20) << std::wstring(10, L'-')
        << std::setw(20) << std::wstring(13, L'-')
        << std::setw(10) << std::wstring(10, L'-')
        << std::endl;

    while (true)
    {
        NTSTATUS status = NtQueryDirectoryFile(
            hPipeDir,
            nullptr,
            nullptr,
            nullptr,
            &iosb,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            FileDirectoryInformation,
            FALSE,
            nullptr,
            restartScan
        );

        if (status != STATUS_SUCCESS)
        {
            break; // Done listing
        }

        restartScan = FALSE;
        PFILE_DIRECTORY_INFORMATION pInfo = reinterpret_cast<PFILE_DIRECTORY_INFORMATION>(buffer.data());
        while (true)
        {
            std::wstring pipeName(pInfo->FileName, pInfo->FileNameLength / sizeof(WCHAR));
            std::wstring defaultPath = L"\\\\.\\pipe\\" + pipeName;
            int pid = find_server_namepipe_pid(defaultPath);

            LONG_PTR value = pInfo->AllocationSize.LowPart;
            if (value == MAXDWORD)
            {
                value = -1;
            }

            logger << std::left << std::setw(100) << pipeName << L"\t"
                << std::setw(10) << std::to_wstring(pInfo->EndOfFile.LowPart) << L"\t"
                << std::right << std::setw(10) << value
                << std::right << std::setw(20) << pid << std::endl;

            if (pInfo->NextEntryOffset == 0)
            {
                break;
            }
            pInfo = reinterpret_cast<PFILE_DIRECTORY_INFORMATION>(reinterpret_cast<BYTE*>(pInfo) + pInfo->NextEntryOffset);
        }
    }

    LogW(logger.str());

    CloseHandle(hPipeDir);
    FreeLibrary(hNtdll);

    LogW(L"[+] Final Pipelist\n");
}

void pipe_list_remote(
    const std::wstring& host,
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& nthash,
    const std::wstring& domain,
    bool useSMB2,
    const std::wstring& filter)
{
    SmbClient smbConn;
    std::wstring treeConnect = LR"(\\)" + host + LR"(\IPC$)";
    std::wstring searchPattern = filter.empty() ? L"*" : filter;

    smbConn.host_ = host;
    smbConn.port_ = 445;

    // connect server
    if (smbConn.connectToServer() == FALSE)
    {
        LogW(L"[-] Failed to connect Server\n");
        return;
    }

    SMB3 smb3client;

    if (useSMB2 == false)
    {
        if (smb3client.SMB3Login(smbConn, username, domain, password, nthash))
        {
            smb3client.SMB3ListTree(smbConn, treeConnect, searchPattern);
        }
    }
    else
    {
        if (SMB2Login(smbConn, username, domain, password, nthash))
        {
            SMB2ListTree(treeConnect, searchPattern, smbConn);
        }
    }

    LogW(L"[+] Final Pipelist\n");
}

int find_server_namepipe_pid(std::wstring pipeName)
{
    HANDLE hPipe = CreateFileW(
        pipeName.c_str(),            // pipe name
        GENERIC_READ | GENERIC_WRITE, // read and write access
        0,                   // no sharing
        NULL,                // default security attributes
        OPEN_EXISTING,       // opens existing pipe
        0,                   // default attributes
        NULL);               // no template file

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    ULONG serverPid = 0;
    int result = -1;
    if (GetNamedPipeServerProcessId(hPipe, &serverPid))
    {
        result = static_cast<int>(serverPid);
    }

    CloseHandle(hPipe);
    return result;
}
