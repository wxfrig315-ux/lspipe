#include "SMB3.h"
#include <windows.h>
#include <winternl.h>     // For NTSTATUS and LARGE_INTEGER
#include <iostream>
#include <vector>
#include <cstddef>        // For std::BYTE
#include <string>
#include <sstream>
#include <iomanip>



// Define missing structures
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;


// Function pointer type for NtQueryDirectoryFile
typedef NTSTATUS(WINAPI* NtQueryDirectoryFile_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
    );

typedef NTSTATUS(NTAPI* NtQueryInformationFile_t)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
    );


typedef struct _FILE_PIPE_LOCAL_INFORMATION
{
    ULONG NamedPipeType;
    ULONG NamedPipeConfiguration;
    ULONG MaximumInstances;
    ULONG CurrentInstances;
    ULONG InboundQuota;
    ULONG ReadDataAvailable;
    ULONG OutboundQuota;
    ULONG WriteQuotaAvailable;
    ULONG NamedPipeState;
    ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION, * PFILE_PIPE_LOCAL_INFORMATION;

// Lists all named pipes on the local machine. Results are written to std::cout.
void pipe_list();

// Lists named pipes on a remote machine over SMB. Results are written to std::cout.
void pipe_list_remote(
    const std::wstring& host,
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& nthash,
    const std::wstring& domain,
    bool useSMB2,
    const std::wstring& filter);

int find_server_namepipe_pid(std::wstring pipeName);
