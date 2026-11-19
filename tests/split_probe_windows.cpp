// A small program for the per-app split tunneling tests. The driver excludes apps by the path of their EXE,
// so the tests copy this program to several folders and run each copy as a different app.
//
// xtun_split_probe <tcp|udp> <ip> <port> <tunnel-ip> [--wait <event>]
//     Connect to <ip>:<port> and exit with the path that the connection took:
//     CONNECTED_VIA_TUNNEL if the local address is <tunnel-ip>, CONNECTED_ELSEWHERE otherwise,
//     or the socket error, for example WSAEACCES when a firewall rule blocks the connection.
//     With --wait, wait for the named event before connecting.
// xtun_split_probe spawn <exe> <args>...
//     Run <exe> with <args> as a child process and exit with its exit code.
#include "util/probe_codes.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>

namespace
{
    constexpr int CONNECT_WAIT_MS = 2000;
    constexpr DWORD EVENT_WAIT_MS = 30000;
    constexpr DWORD CHILD_WAIT_MS = 10000;
    constexpr int PROBE_FAILED = 1;
    constexpr int USAGE_ERROR = 2;

    struct Address
    {
        sockaddr_storage storage {};
        int size = 0;
    };

    // Parse an IPv4 or IPv6 address, for example "93.184.215.14" or "2001:db8::1".
    bool parseAddress(const wchar_t *text, unsigned short port, Address &address)
    {
        auto *v4 = reinterpret_cast<sockaddr_in *>(&address.storage);
        if (::InetPtonW(AF_INET, text, &v4->sin_addr) == 1) {
            v4->sin_family = AF_INET;
            v4->sin_port = ::htons(port);
            address.size = sizeof(sockaddr_in);
            return true;
        }
        auto *v6 = reinterpret_cast<sockaddr_in6 *>(&address.storage);
        if (::InetPtonW(AF_INET6, text, &v6->sin6_addr) == 1) {
            v6->sin6_family = AF_INET6;
            v6->sin6_port = ::htons(port);
            address.size = sizeof(sockaddr_in6);
            return true;
        }
        return false;
    }

    bool sameAddress(const sockaddr_storage &left, const sockaddr_storage &right)
    {
        if (left.ss_family != right.ss_family) {
            return false;
        }
        if (left.ss_family == AF_INET) {
            return reinterpret_cast<const sockaddr_in &>(left).sin_addr.s_addr
                    == reinterpret_cast<const sockaddr_in &>(right).sin_addr.s_addr;
        }
        return std::memcmp(&reinterpret_cast<const sockaddr_in6 &>(left).sin6_addr,
                           &reinterpret_cast<const sockaddr_in6 &>(right).sin6_addr, sizeof(in6_addr))
                == 0;
    }

    // Start a TCP connection and wait for its result. Return 0 or the socket error.
    int connectTcp(SOCKET sock, const Address &remote)
    {
        u_long nonBlocking = 1;
        if (::ioctlsocket(sock, FIONBIO, &nonBlocking) != 0) {
            return ::WSAGetLastError();
        }
        if (::connect(sock, reinterpret_cast<const sockaddr *>(&remote.storage), remote.size) == 0) {
            return 0;
        }
        if (const int error = ::WSAGetLastError(); error != WSAEWOULDBLOCK) {
            return error;
        }
        // On Windows, select() reports a failed connection in the "except" set.
        fd_set connected;
        fd_set failed;
        FD_ZERO(&connected);
        FD_ZERO(&failed);
        FD_SET(sock, &connected);
        FD_SET(sock, &failed);
        const timeval wait { CONNECT_WAIT_MS / 1000, (CONNECT_WAIT_MS % 1000) * 1000 };
        if (::select(0, nullptr, &connected, &failed, &wait) == SOCKET_ERROR) {
            return ::WSAGetLastError();
        }
        int error = 0;
        int size = sizeof(error);
        if (::getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &size) != 0) {
            return ::WSAGetLastError();
        }
        // No answer in time is not an error here: the local address is already chosen.
        return error;
    }

    // Send one byte over UDP. Return 0 or the socket error.
    int sendUdp(SOCKET sock, const Address &remote)
    {
        if (::connect(sock, reinterpret_cast<const sockaddr *>(&remote.storage), remote.size) != 0) {
            return ::WSAGetLastError();
        }
        const char byte = 0;
        if (::send(sock, &byte, 1, 0) == SOCKET_ERROR) {
            return ::WSAGetLastError();
        }
        return 0;
    }

    int probe(bool tcp, const Address &remote, const Address &tunnel)
    {
        const SOCKET sock =
                ::socket(remote.storage.ss_family, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            return ::WSAGetLastError();
        }
        int result = tcp ? connectTcp(sock, remote) : sendUdp(sock, remote);
        if (result == 0) {
            sockaddr_storage local {};
            int size = sizeof(local);
            if (::getsockname(sock, reinterpret_cast<sockaddr *>(&local), &size) != 0) {
                result = ::WSAGetLastError();
            } else {
                result = sameAddress(local, tunnel.storage) ? libxtun::test::CONNECTED_VIA_TUNNEL
                                                            : libxtun::test::CONNECTED_ELSEWHERE;
            }
        }
        ::closesocket(sock);
        return result;
    }

    // The test creates this event before it starts the probe and signals it after attach.
    // So the probe process exists before attach, but connects after it.
    bool waitForEvent(const wchar_t *name)
    {
        HANDLE event = ::OpenEventW(SYNCHRONIZE, FALSE, name);
        if (event == nullptr) {
            std::fwprintf(stderr, L"cannot open event %ls: %lu\n", name, ::GetLastError());
            return false;
        }
        const bool signaled = ::WaitForSingleObject(event, EVENT_WAIT_MS) == WAIT_OBJECT_0;
        ::CloseHandle(event);
        if (!signaled) {
            std::fwprintf(stderr, L"event %ls was not signaled in time\n", name);
        }
        return signaled;
    }

    int spawn(int argc, wchar_t **argv)
    {
        // The arguments of the tests contain no quotes, so simple quoting is enough.
        std::wstring commandLine;
        for (int i = 2; i < argc; ++i) {
            commandLine += (i == 2 ? L"\"" : L" \"") + std::wstring(argv[i]) + L"\"";
        }
        STARTUPINFOW startup { sizeof(startup) };
        PROCESS_INFORMATION child {};
        if (!::CreateProcessW(argv[2], commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                              &startup, &child)) {
            std::fwprintf(stderr, L"cannot start %ls: %lu\n", argv[2], ::GetLastError());
            return PROBE_FAILED;
        }
        ::CloseHandle(child.hThread);
        DWORD code = PROBE_FAILED;
        if (::WaitForSingleObject(child.hProcess, CHILD_WAIT_MS) != WAIT_OBJECT_0) {
            std::fwprintf(stderr, L"%ls did not finish in time\n", argv[2]);
            ::TerminateProcess(child.hProcess, PROBE_FAILED);
        } else {
            ::GetExitCodeProcess(child.hProcess, &code);
        }
        ::CloseHandle(child.hProcess);
        return static_cast<int>(code);
    }
}

int wmain(int argc, wchar_t **argv)
{
    if (argc >= 3 && std::wcscmp(argv[1], L"spawn") == 0) {
        return spawn(argc, argv);
    }

    const bool tcp = argc >= 2 && std::wcscmp(argv[1], L"tcp") == 0;
    const bool udp = argc >= 2 && std::wcscmp(argv[1], L"udp") == 0;
    const bool wait = argc == 7 && std::wcscmp(argv[5], L"--wait") == 0;
    Address remote;
    Address tunnel;
    if ((!tcp && !udp) || (argc != 5 && !wait)
        || !parseAddress(argv[2], static_cast<unsigned short>(std::wcstoul(argv[3], nullptr, 10)), remote)
        || !parseAddress(argv[4], 0, tunnel)) {
        std::fwprintf(stderr,
                      L"usage: xtun_split_probe <tcp|udp> <ip> <port> <tunnel-ip> [--wait <event>]\n"
                      L"       xtun_split_probe spawn <exe> <args>...\n");
        return USAGE_ERROR;
    }

    WSADATA wsa {};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return PROBE_FAILED;
    }
    const int result = wait && !waitForEvent(argv[6]) ? PROBE_FAILED : probe(tcp, remote, tunnel);
    ::WSACleanup();
    return result;
}
