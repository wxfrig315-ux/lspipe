#include "lspipe.h"
#include "utils.h"

#include <windows.h>
#include <iostream>
#include <string>

namespace {

std::string trim(const std::string& s)
{
    const char* ws = " \t\r\n";
    const std::string::size_type first = s.find_first_not_of(ws);
    if (first == std::string::npos)
    {
        return std::string();
    }
    const std::string::size_type last = s.find_last_not_of(ws);
    return s.substr(first, last - first + 1);
}

bool equalsIgnoreCase(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    for (std::string::size_type i = 0; i < a.size(); ++i)
    {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb)
        {
            return false;
        }
    }
    return true;
}

} // namespace

int main()
{
    // Make the console emit/accept UTF-8 so that pipe names render correctly.
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    std::cout << "==============================================" << std::endl;
    std::cout << "          lspipe - Named Pipe Lister          " << std::endl;
    std::cout << "==============================================" << std::endl;
    std::cout << "Select mode:" << std::endl;
    std::cout << "  1) local         - list pipes on this machine" << std::endl;
    std::cout << "  2) remote (SMB)  - list pipes on a remote machine over SMB" << std::endl;
    std::cout << "> ";

    std::string mode;
    std::getline(std::cin, mode);
    mode = trim(mode);

    if (equalsIgnoreCase(mode, "1") || equalsIgnoreCase(mode, "local"))
    {
        pipe_list();
    }
    else if (equalsIgnoreCase(mode, "2") || equalsIgnoreCase(mode, "remote") || equalsIgnoreCase(mode, "smb"))
    {
        std::cout << "Enter server name or IP address: ";
        std::string server;
        std::getline(std::cin, server);
        server = trim(server);
        if (server.empty())
        {
            std::cout << "[-] Server name/IP address is required." << std::endl;
            return 1;
        }

        std::cout << "Enter username (empty for null session): ";
        std::string username;
        std::getline(std::cin, username);
        username = trim(username);

        std::cout << "Enter password (leave empty if using an NTLM hash): ";
        std::string password;
        std::getline(std::cin, password);

        std::cout << "Enter NTLM hash (optional, hexadecimal): ";
        std::string nthash;
        std::getline(std::cin, nthash);
        nthash = trim(nthash);

        std::cout << "Enter domain (optional, default '.'): ";
        std::string domain;
        std::getline(std::cin, domain);
        domain = trim(domain);
        if (domain.empty())
        {
            domain = ".";
        }

        std::cout << "Use SMB2 instead of SMB3.1.1? (y/N): ";
        std::string smb2;
        std::getline(std::cin, smb2);
        smb2 = trim(smb2);
        const bool useSMB2 = equalsIgnoreCase(smb2, "y") || equalsIgnoreCase(smb2, "yes");

        std::cout << "Enter pipe name filter (optional, default '*'): ";
        std::string filter;
        std::getline(std::cin, filter);
        filter = trim(filter);
        if (filter.empty())
        {
            filter = "*";
        }

        pipe_list_remote(
            utf8ToWide(server),
            utf8ToWide(username),
            utf8ToWide(password),
            utf8ToWide(nthash),
            utf8ToWide(domain),
            useSMB2,
            utf8ToWide(filter));
    }
    else
    {
        std::cout << "[-] Invalid mode. Expected '1'/'local' or '2'/'remote'." << std::endl;
        return 1;
    }

    return 0;
}
