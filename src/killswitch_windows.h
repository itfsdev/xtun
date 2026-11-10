#ifndef LIBXTUN_KILLSWITCH_WINDOWS_H
#define LIBXTUN_KILLSWITCH_WINDOWS_H

#include "killswitch.h"
#include "net/wfp.h"
#include "xtun.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace libxtun
{
    constexpr GUID PROVIDER_KEY = { 0xc8bb0995, 0x14c5, 0x47ec, 0xbb, 0x16, 0xea, 0xbb, 0xde, 0xef, 0x3f, 0xc5 };
    constexpr GUID SUBLAYER_KEY = { 0x6d0b7874, 0x4f21, 0x4c2a, 0x9d, 0x6a, 0x78, 0x74, 0xa1, 0xb2, 0x00, 0x01 };
    constexpr UINT16 SUBLAYER_WEIGHT = 0xFFFF;
    constexpr UINT8 WEIGHT_PASS = 14;
    constexpr UINT8 WEIGHT_BLOCK_DNS = 12;
    constexpr UINT8 WEIGHT_PASS_TUNNEL = 8;
    constexpr UINT8 WEIGHT_PASS_EXCLUDED = 4;
    constexpr UINT8 WEIGHT_BLOCK_PROTECTED = 0;

    wfp::WfpConfig makeWfpConfig(bool persistent, bool splitTunnel = false) noexcept;

    class WindowsKillswitch final : public Killswitch
    {
    public:
        explicit WindowsKillswitch(libxtun_killswitch_mode mode, std::vector<net::IpAddress> dnsExceptions,
                                   bool splitTunnel = false) noexcept
            : Killswitch(mode, std::move(dnsExceptions)), m_splitTunnel(splitTunnel)
        {
        }
        ~WindowsKillswitch() override = default;

    protected:
        libxtun_error install(int ifIndex, const std::string &ifName) override;
        libxtun_error setProtected(const std::vector<net::IpPrefix> &prefixes,
                                   const std::vector<net::IpPrefix> &excludes,
                                   const std::vector<net::IpAddress> &dnsServers) override;
        void remove() noexcept override;

    private:
        libxtun_error installFilters(std::uint64_t luidValue, const std::vector<net::IpPrefix> &prefixes,
                                     const std::vector<net::IpPrefix> &excludes,
                                     const std::vector<net::IpAddress> &dnsServers);
        libxtun_error blockProtected(const GUID &layer, const GUID &field, int family,
                                     const std::vector<net::IpPrefix> &prefixes);
        libxtun_error allowExcluded(const GUID &layer, const GUID &field, int family,
                                    const std::vector<net::IpPrefix> &excludes);
        libxtun_error allowTunnel(const GUID &layer, const GUID &field, std::uint64_t luidValue) noexcept;
        libxtun_error allowLoopback(const GUID &layer) noexcept;
        libxtun_error allowAppTraffic(const GUID &layer) noexcept;
        libxtun_error allowDhcp(const GUID &layer, int family) noexcept;
        libxtun_error allowDns(const GUID &layer, int family, const std::vector<net::IpAddress> &dnsServers,
                               const std::vector<net::IpPrefix> &prefixes, const std::vector<net::IpPrefix> &excludes,
                               std::uint64_t luidValue);
        libxtun_error blockDns(const GUID &layer) noexcept;
        std::unique_ptr<wfp::WfpEngine> m_wfp;
        bool m_splitTunnel = false;
        std::uint64_t m_luid = 0;
    };
}
#endif
