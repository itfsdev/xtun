#ifndef TEST_PATH_PROBE_H
#define TEST_PATH_PROBE_H

#include "config.h"
#include "os.h"
#include "probe_codes.h"
#include "util/noncopyable.h"
#include "xtun.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include "gtest/gtest.h"

namespace libxtun::test
{
    constexpr const char *PROBE_HOST = "example.com";
    constexpr std::uint16_t PROBE_PORT = 443;
    constexpr auto PROBE_TIMEOUT = std::chrono::milliseconds(2000);
    constexpr std::uint16_t DNS_PORT = 53;
    constexpr std::uint16_t DNS_TLS_PORT = 853;
    constexpr auto TCP_REJECTION_WAIT = std::chrono::milliseconds(50);
#if defined(__APPLE__)
    constexpr auto UDP_REJECTION_WAIT = std::chrono::milliseconds(50);
#else
    constexpr auto UDP_REJECTION_WAIT = std::chrono::milliseconds(0);
#endif
#if defined(__APPLE__)
    constexpr ::gid_t FOREIGN_GID = 1;
#endif

    const std::vector<std::string> PROBE_ADDRS = resolve(PROBE_HOST);
    const std::string PROBE_ADDR_V6 = "2001:db8::1";

    static std::string probeAddress(std::size_t index)
    {
        return index < PROBE_ADDRS.size() ? PROBE_ADDRS[index] : std::string {};
    }

    struct Destination
    {
        const char *name;
        std::string host;
    };

    const Destination ROUTED_HOST_V4 { "routed host v4", probeAddress(0) };
    const Destination UNROUTED_HOST_V6 { "unrouted host v6", PROBE_ADDR_V6 };
    const Destination EXCLUDED_HOST_V4 { "excluded host v4", probeAddress(1) };

    enum class Sender {
        App,
        Proxy
    };

    enum class ProbeResult {
        Tunnel,
        Uplink,
        Blocked
    };

    inline auto socketHandle(const ScopedFd &fd)
    {
#if defined(_WIN32)
        return static_cast<SOCKET>(fd.get());
#else
        return fd.get();
#endif
    }

    inline int waitForRejection(const ScopedFd &fd, short events, std::chrono::milliseconds timeout)
    {
        const auto handle = socketHandle(fd);
        ::pollfd ready { handle, events, 0 };
        ::poll(&ready, 1, static_cast<int>(timeout.count()));
        int error = 0;
        ::socklen_t size = sizeof(error);
        if (::getsockopt(handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &size) != 0) {
            return lastSocketError();
        }
        return error;
    }

    inline std::string localAddress(const ScopedFd &sock)
    {
        ::sockaddr_storage local {};
        ::socklen_t size = sizeof(local);
        std::array<char, INET6_ADDRSTRLEN> address {};
        const auto handle = socketHandle(sock);
        if (::getsockname(handle, reinterpret_cast<::sockaddr *>(&local), &size) != 0
            || ::getnameinfo(reinterpret_cast<::sockaddr *>(&local), size, address.data(),
                             static_cast<::socklen_t>(address.size()), nullptr, 0, NI_NUMERICHOST)
                    != 0) {
            return {};
        }
        return address.data();
    }

    inline int udpProbe(const std::string &host, std::uint16_t port, unsigned bypass)
    {
        const ConnectedSocket udp = udpConnect(host, port, bypass);
        if (udp.error != 0) {
            return udp.error;
        }
        const bool viaTunnel = localAddress(udp.fd) == DEFAULT_IFADDR;
        const char byte = 0;
        if (::send(socketHandle(udp.fd), &byte, 1, 0) != 1) {
            return lastSocketError();
        }
        if constexpr (UDP_REJECTION_WAIT.count() > 0) {
            if (const int error = waitForRejection(udp.fd, POLLIN, UDP_REJECTION_WAIT); error != 0) {
                return error;
            }
        }
        return viaTunnel ? CONNECTED_VIA_TUNNEL : CONNECTED_ELSEWHERE;
    }

    inline int tcpProbe(const std::string &host, std::uint16_t port, unsigned bypass)
    {
        const ConnectedSocket tcp = connectSocket(host, port, SOCK_STREAM, bypass);
        if (!tcp.fd || (tcp.error != 0 && tcp.error != ERR_IN_PROGRESS && tcp.error != ERR_INTERRUPTED)) {
            return tcp.error;
        }
        const bool viaTunnel = localAddress(tcp.fd) == DEFAULT_IFADDR;
        if (const int error = waitForRejection(tcp.fd, POLLOUT, TCP_REJECTION_WAIT); error != 0) {
            return error;
        }
        return viaTunnel ? CONNECTED_VIA_TUNNEL : CONNECTED_ELSEWHERE;
    }

#if defined(_WIN32)
    inline std::optional<unsigned long> bestInterface(const char *host)
    {
        sockaddr_in destination {};
        destination.sin_family = AF_INET;
        if (::inet_pton(AF_INET, host, &destination.sin_addr) != 1) {
            return std::nullopt;
        }

        DWORD index = 0;
        if (::GetBestInterfaceEx(reinterpret_cast<sockaddr *>(&destination), &index) != NO_ERROR) {
            return std::nullopt;
        }
        return index;
    }
#endif

    inline std::ostream &operator<<(std::ostream &out, Sender sender)
    {
        switch (sender) {
        case Sender::App: return out << "from an app";
        case Sender::Proxy: return out << "from the proxy";
        }
        return out;
    }

    inline std::ostream &operator<<(std::ostream &out, ProbeResult result)
    {
        switch (result) {
        case ProbeResult::Tunnel: return out << "tunnel";
        case ProbeResult::Uplink: return out << "uplink";
        case ProbeResult::Blocked: return out << "blocked";
        }
        return out;
    }

    class PathProbe : private NonCopyable
    {
    public:
        PathProbe();
        ~PathProbe();

        [[nodiscard]] std::string_view skipReason() const noexcept
        {
            return m_skipReason;
        }
        [[nodiscard]] std::optional<ProbeResult> probe(const Destination &to, Sender sender,
                                                       std::uint16_t port = PROBE_PORT) const;

    private:
        std::string m_skipReason;
#if defined(__APPLE__) || defined(_WIN32)
        unsigned m_uplinkIfIndex = 0;
#endif
    };

    class ProbeTest : public testing::Test
    {
    protected:
        void SetUp() override
        {
            if (!m_pathProbe.skipReason().empty()) {
                GTEST_SKIP() << "skipped: " << m_pathProbe.skipReason();
            }
            ASSERT_GE(PROBE_ADDRS.size(), 2u) << "could not resolve two addresses of " << PROBE_HOST;
        }
        void expectProbeResult(const Destination &to, Sender sender, ProbeResult wanted, std::string_view phase = {})
        {
            if (const std::optional<ProbeResult> result = m_pathProbe.probe(to, sender)) {
                EXPECT_EQ(*result, wanted) << to.name << ", " << sender << ' ' << phase;
            }
        }
        PathProbe m_pathProbe;
    };
}

#if defined(_WIN32)
    #include "path_probe_windows.h"
#elif defined(__APPLE__)
    #include "path_probe_macos.h"
#elif defined(__linux__) && !defined(__ANDROID__)
    #include "path_probe_linux.h"
#endif

#endif
