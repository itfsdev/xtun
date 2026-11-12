#ifndef LIBXTUN_KILLSWITCH_H
#define LIBXTUN_KILLSWITCH_H

#include "net/ip.h"
#include "util/noncopyable.h"
#include "xtun.h"

#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace libxtun
{
    class Killswitch : private NonCopyable
    {
    public:
        virtual ~Killswitch() = default;

        libxtun_error update(int ifIndex, const std::string &ifName);
        libxtun_error protect(const std::vector<net::IpPrefix> &routes, const std::vector<net::IpPrefix> &excludes,
                              const std::vector<net::IpAddress> &resolvers);

        static std::unique_ptr<Killswitch> create(libxtun_killswitch_mode mode, int macosGroup = -1,
                                                  std::vector<net::IpAddress> dnsExceptions = {},
                                                  bool splitTunnel = false);

    protected:
        Killswitch(libxtun_killswitch_mode mode, std::vector<net::IpAddress> dnsExceptions) noexcept
            : m_mode(mode), m_dnsExceptions(std::move(dnsExceptions))
        {
        }

        [[nodiscard]] bool persistent() const noexcept
        {
            return m_mode == LIBXTUN_KILLSWITCH_MODE_HARD;
        }

        [[nodiscard]] bool installed() const noexcept
        {
            return m_installed;
        }

        virtual libxtun_error install(int ifIndex, const std::string &ifName) = 0;
        virtual libxtun_error setProtected(const std::vector<net::IpPrefix> &prefixes,
                                           const std::vector<net::IpPrefix> &excludes,
                                           const std::vector<net::IpAddress> &dnsServers) = 0;
        virtual void remove() noexcept = 0;

    private:
        libxtun_killswitch_mode m_mode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
        std::vector<net::IpAddress> m_dnsExceptions;
        std::mutex m_mutex;
        bool m_installed = false;
    };
}
#endif
