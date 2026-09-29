cmake_minimum_required(VERSION 3.15)
project(lspipe LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "lspipe can only be built on Windows.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(lspipe
    AV_PAIR.cpp
    BcryptAES.cpp
    BcryptHmac.cpp
    BcryptSHA512.cpp
    DirectTCPTransportHeader.cpp
    lspipe.cpp
    main.cpp
    ntlm.cpp
    NtlmCalcCrypto.cpp
    SMB2BasePacket.cpp
    SMB2CloseRequest.cpp
    SMB2CreateRequest.cpp
    SMB2Header.cpp
    SMB2ListTree.cpp
    SMB2Login.cpp
    SMB2Logoff.cpp
    SMB2Negotiate.cpp
    SMB2QueryDirectory.cpp
    SMB2QueryDirectoryResponse.cpp
    SMB2SessionSetup.cpp
    SMB2TranformPacket.cpp
    SMB2TreeConnect.cpp
    SMB3.cpp
    SMB3Negotiate.cpp
    SmbClient.cpp
    SMBConnectionTable.cpp
    spnego.cpp
    utils.cpp
    windows_socket.cpp
)

target_include_directories(lspipe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(lspipe PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)

if(MSVC)
    # /utf-8: treat source files as UTF-8 (some headers contain non-ASCII comments).
    target_compile_options(lspipe PRIVATE /W3 /utf-8)
else()
    target_compile_options(lspipe PRIVATE -Wall)
endif()

target_link_libraries(lspipe PRIVATE ws2_32 bcrypt ole32)
