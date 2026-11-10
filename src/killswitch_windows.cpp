#include "killswitch_windows.h"
#include "net/wfp.h"
#include "split_tunnel_windows.h"
#include "xtun.h"

#include <ifdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <winerror.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace libxtun
{
    namespace
    {
        constexpr UINT16 DNS_PORT = 53;
        constexpr UINT16 DNS_TLS_PORT = 853;

        libxtun_error cleanupWfp()
        {
            // Old HARD KillSwitch filters may remain in either sublayer.
            // Do cleanup in both the regular (false) and driver (true) sublayers
            for (const bool splitTunnel : { false, true }) {
                auto engine = wfp::WfpEngine::open(makeWfpConfig(true, splitTunnel));
                if (!engine) {
                    return engine.error();
                }
                if (const auto error = engine.value()->cleanup(); error != LIBXTUN_OK) {
                    return error;
                }
            }
            return LIBXTUN_OK;
        }

        FWP_V4_ADDR_AND_MASK v4AddrMask(const net::IpPrefix &prefix)
        {
            ULONG mask = 0;
            ::ConvertLengthToIpv4Mask(prefix.bits(), &mask);
            std::uint32_t address = 0;
            std::memcpy(&address, prefix.address().octets().data(), sizeof(address));
            return FWP_V4_ADDR_AND_MASK { ::ntohl(address), ::ntohl(mask) };
        }

        FWP_V6_ADDR_AND_MASK v6AddrMask(const net::IpPrefix &prefix)
        {
            FWP_V6_ADDR_AND_MASK addrMask {};
            std::memcpy(addrMask.addr, prefix.address().octets().data(), sizeof(addrMask.addr));
            addrMask.prefixLength = static_cast<UINT8>(prefix.bits());
            return addrMask;
        }

        FWPM_FILTER_CONDITION uint8Condition(const GUID &field, UINT8 value) noexcept
        {
            FWPM_FILTER_CONDITION condition {};
            condition.fieldKey = field;
            condition.matchType = FWP_MATCH_EQUAL;
            condition.conditionValue.type = FWP_UINT8;
            condition.conditionValue.uint8 = value;
            return condition;
        }

        FWPM_FILTER_CONDITION uint16Condition(const GUID &field, UINT16 value) noexcept
        {
            FWPM_FILTER_CONDITION condition {};
            condition.fieldKey = field;
            condition.matchType = FWP_MATCH_EQUAL;
            condition.conditionValue.type = FWP_UINT16;
            condition.conditionValue.uint16 = value;
            return condition;
        }
    }

    wfp::WfpConfig makeWfpConfig(bool persistent, bool splitTunnel) noexcept
    {
        wfp::WfpConfig config {};
        if (splitTunnel) {
            config = split::baselineWfpConfig();
            config.ownsSublayer = false;
        } else {
            config.sublayer = SUBLAYER_KEY;
            config.sublayerName = L"xtun-killswitch-sublayer";
            config.sublayerDesc = L"xtun Killswitch Sublayer";
            config.sublayerWeight = SUBLAYER_WEIGHT;
        }
        config.provider = PROVIDER_KEY;
        config.providerName = L"xtun-killswitch-provider";
        config.providerDesc = L"xtun Killswitch Provider";
        config.persistent = persistent;
        return config;
    }

    libxtun_error WindowsKillswitch::install(int ifIndex, const std::string &ifName)
    {
        (void)ifName;

        NET_LUID luid {};
        if (ifIndex <= 0 || ::ConvertInterfaceIndexToLuid(static_cast<NET_IFINDEX>(ifIndex), &luid) != NO_ERROR) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        // filters installed by HARD mode cannot be removed from dynamic WFP session used by SOFT
        // thus, we have to use an engine with different config
        if (!persistent()) {
            if (const auto result = cleanupWfp(); result != LIBXTUN_OK) {
                return result;
            }
        }

        auto engine = wfp::WfpEngine::open(makeWfpConfig(persistent(), m_splitTunnel));
        if (!engine) {
            return engine.error();
        }

        m_wfp = std::move(engine).value();
        m_luid = luid.Value;

        if (const auto result = installFilters(m_luid, {}, {}, {}); result != LIBXTUN_OK) {
            m_wfp.reset();
            return result;
        }

        return LIBXTUN_OK;
    }

    libxtun_error WindowsKillswitch::setProtected(const std::vector<net::IpPrefix> &prefixes,
                                                  const std::vector<net::IpPrefix> &excludes,
                                                  const std::vector<net::IpAddress> &dnsServers)
    {
        return installFilters(m_luid, prefixes, excludes, dnsServers);
    }

    void WindowsKillswitch::remove() noexcept
    {
        if (m_wfp != nullptr) {
            m_wfp->cleanup();
            m_wfp.reset();
        }

        cleanupWfp();
    }

    libxtun_error WindowsKillswitch::installFilters(std::uint64_t luidValue, const std::vector<net::IpPrefix> &prefixes,
                                                    const std::vector<net::IpPrefix> &excludes,
                                                    const std::vector<net::IpAddress> &dnsServers)
    {
        wfp::WfpEngine::Transaction transaction(*m_wfp);
        if (transaction.status() != LIBXTUN_OK) {
            return transaction.status();
        }

        if (const auto result = m_wfp->addProvider(); result != LIBXTUN_OK) {
            return result;
        }

        if (const auto result = m_wfp->addSublayer(); result != LIBXTUN_OK) {
            return result;
        }

        // Replace KillSwitch filters in both the regular and driver sublayers.
        // If this transaction fails, the old filters stay.
        if (const auto result = m_wfp->deleteFilters(); result != LIBXTUN_OK) {
            return result;
        }
        const GUID otherSublayer = m_splitTunnel ? SUBLAYER_KEY : split::baselineWfpConfig().sublayer;
        if (const auto result = m_wfp->deleteFilters(otherSublayer); result != LIBXTUN_OK) {
            return result;
        }

        struct FamilyLayers
        {
            int family;
            GUID connect;
            GUID recvAccept;
        };
        const std::array<FamilyLayers, 2> families { {
            { AF_INET, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 },
            { AF_INET6, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 },
        } };
        for (const FamilyLayers &layers : families) {
            for (const GUID &layer : { layers.connect, layers.recvAccept }) {
                if (auto result = allowTunnel(layer, FWPM_CONDITION_IP_LOCAL_INTERFACE, luidValue);
                    result != LIBXTUN_OK) {
                    return result;
                }
                if (auto result = allowLoopback(layer); result != LIBXTUN_OK) {
                    return result;
                }
                if (auto result = allowAppTraffic(layer); result != LIBXTUN_OK) {
                    return result;
                }
                if (auto result = allowDhcp(layer, layers.family); result != LIBXTUN_OK) {
                    return result;
                }
                if (auto result = blockProtected(layer, FWPM_CONDITION_IP_REMOTE_ADDRESS, layers.family, prefixes);
                    result != LIBXTUN_OK) {
                    return result;
                }
                if (auto result = allowExcluded(layer, FWPM_CONDITION_IP_REMOTE_ADDRESS, layers.family, excludes);
                    result != LIBXTUN_OK) {
                    return result;
                }
            }

            if (!prefixes.empty()) {
                if (auto result = allowDns(layers.connect, layers.family, dnsServers, prefixes, excludes, luidValue);
                    result != LIBXTUN_OK) {
                    return result;
                }
                if (auto result = blockDns(layers.connect); result != LIBXTUN_OK) {
                    return result;
                }
            }
        }

        return transaction.commit();
    }

    libxtun_error WindowsKillswitch::blockProtected(const GUID &layer, const GUID &field, int family,
                                                    const std::vector<net::IpPrefix> &prefixes)
    {
        std::vector<FWP_V4_ADDR_AND_MASK> v4AddrMasks;
        std::vector<FWP_V6_ADDR_AND_MASK> v6AddrMasks;
        v4AddrMasks.reserve(prefixes.size());
        v6AddrMasks.reserve(prefixes.size());

        std::vector<FWPM_FILTER_CONDITION> conditions;
        for (const net::IpPrefix &prefix : prefixes) {
            if (prefix.address().family() != family) {
                continue;
            }
            if (prefix.isDefaultRoute()) {
                return m_wfp->addFilter(layer, FWP_ACTION_BLOCK, WEIGHT_BLOCK_PROTECTED, {},
                                        L"Block traffic to protected destinations");
            }

            FWPM_FILTER_CONDITION condition {};
            condition.fieldKey = field;
            condition.matchType = FWP_MATCH_EQUAL;
            if (family == AF_INET) {
                condition.conditionValue.type = FWP_V4_ADDR_MASK;
                condition.conditionValue.v4AddrMask = &v4AddrMasks.emplace_back(v4AddrMask(prefix));
            } else {
                condition.conditionValue.type = FWP_V6_ADDR_MASK;
                condition.conditionValue.v6AddrMask = &v6AddrMasks.emplace_back(v6AddrMask(prefix));
            }
            conditions.push_back(condition);
        }

        if (conditions.empty()) {
            return LIBXTUN_OK;
        }
        return m_wfp->addFilter(layer, FWP_ACTION_BLOCK, WEIGHT_BLOCK_PROTECTED, conditions,
                                L"Block traffic to protected destinations");
    }

    libxtun_error WindowsKillswitch::allowExcluded(const GUID &layer, const GUID &field, int family,
                                                   const std::vector<net::IpPrefix> &excludes)
    {
        std::vector<FWP_V4_ADDR_AND_MASK> v4AddrMasks;
        std::vector<FWP_V6_ADDR_AND_MASK> v6AddrMasks;
        v4AddrMasks.reserve(excludes.size());
        v6AddrMasks.reserve(excludes.size());

        std::vector<FWPM_FILTER_CONDITION> conditions;
        for (const net::IpPrefix &exclude : excludes) {
            if (exclude.address().family() != family) {
                continue;
            }

            FWPM_FILTER_CONDITION condition {};
            condition.fieldKey = field;
            condition.matchType = FWP_MATCH_EQUAL;
            if (family == AF_INET) {
                condition.conditionValue.type = FWP_V4_ADDR_MASK;
                condition.conditionValue.v4AddrMask = &v4AddrMasks.emplace_back(v4AddrMask(exclude));
            } else {
                condition.conditionValue.type = FWP_V6_ADDR_MASK;
                condition.conditionValue.v6AddrMask = &v6AddrMasks.emplace_back(v6AddrMask(exclude));
            }
            conditions.push_back(condition);
        }

        if (conditions.empty()) {
            return LIBXTUN_OK;
        }
        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, WEIGHT_PASS_EXCLUDED, conditions,
                                L"Allow traffic to excluded destinations");
    }

    libxtun_error WindowsKillswitch::allowTunnel(const GUID &layer, const GUID &field, std::uint64_t luidValue) noexcept
    {
        FWPM_FILTER_CONDITION condition {};
        condition.fieldKey = field;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT64;
        condition.conditionValue.uint64 = &luidValue;

        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, WEIGHT_PASS_TUNNEL, std::span(&condition, 1),
                                L"Allow traffic via tunnel");
    }

    libxtun_error WindowsKillswitch::allowLoopback(const GUID &layer) noexcept
    {
        FWPM_FILTER_CONDITION condition {};
        condition.fieldKey = FWPM_CONDITION_FLAGS;
        condition.matchType = FWP_MATCH_FLAGS_ANY_SET;
        condition.conditionValue.type = FWP_UINT32;
        condition.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, WEIGHT_PASS, std::span(&condition, 1),
                                L"Allow loopback traffic");
    }

    libxtun_error WindowsKillswitch::allowAppTraffic(const GUID &layer) noexcept
    {
        std::array<wchar_t, MAX_PATH> path {};
        if (::GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size())) == 0)
        {
            return LIBXTUN_ERR_SYSTEM;
        }

        FWP_BYTE_BLOB *rawAppId = nullptr;
        if (::FwpmGetAppIdFromFileName(path.data(), &rawAppId) != ERROR_SUCCESS) {
            return LIBXTUN_ERR_SYSTEM;
        }
        const std::unique_ptr<FWP_BYTE_BLOB, wfp::FwpmMemoryDeleter> appId(rawAppId);

        FWPM_FILTER_CONDITION condition {};
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        condition.conditionValue.byteBlob = appId.get();

        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, WEIGHT_PASS, std::span(&condition, 1), L"Allow app traffic");
    }

    libxtun_error WindowsKillswitch::allowDhcp(const GUID &layer, int family) noexcept
    {
        const bool v6 = family == AF_INET6;
        std::array<FWPM_FILTER_CONDITION, 3> conditions {
            uint8Condition(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP),
            uint16Condition(FWPM_CONDITION_IP_LOCAL_PORT, v6 ? 546 : 68),
            uint16Condition(FWPM_CONDITION_IP_REMOTE_PORT, v6 ? 547 : 67),
        };

        return m_wfp->addFilter(layer, FWP_ACTION_PERMIT, WEIGHT_PASS, conditions, L"Allow DHCP");
    }

    libxtun_error WindowsKillswitch::allowDns(const GUID &layer, int family,
                                              const std::vector<net::IpAddress> &dnsServers,
                                              const std::vector<net::IpPrefix> &prefixes,
                                              const std::vector<net::IpPrefix> &excludes, std::uint64_t luidValue)
    {
        const auto inside = [&prefixes, &excludes](const net::IpAddress &server) {
            return std::ranges::any_of(prefixes, [&server](const net::IpPrefix &prefix) { return prefix.contains(server); })
                    && std::ranges::none_of(excludes,
                                            [&server](const net::IpPrefix &exclude) { return exclude.contains(server); });
        };

        for (const bool viaTunnel : { false, true }) {
            std::vector<FWP_V4_ADDR_AND_MASK> v4AddrMasks;
            std::vector<FWP_V6_ADDR_AND_MASK> v6AddrMasks;
            v4AddrMasks.reserve(dnsServers.size());
            v6AddrMasks.reserve(dnsServers.size());

            std::vector<FWPM_FILTER_CONDITION> conditions;
            for (const net::IpAddress &server : dnsServers) {
                if (server.family() != family || inside(server) != viaTunnel) {
                    continue;
                }

                const net::IpPrefix host(server, family == AF_INET ? 32 : 128);
                FWPM_FILTER_CONDITION condition {};
                condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                condition.matchType = FWP_MATCH_EQUAL;
                if (family == AF_INET) {
                    condition.conditionValue.type = FWP_V4_ADDR_MASK;
                    condition.conditionValue.v4AddrMask = &v4AddrMasks.emplace_back(v4AddrMask(host));
                } else {
                    condition.conditionValue.type = FWP_V6_ADDR_MASK;
                    condition.conditionValue.v6AddrMask = &v6AddrMasks.emplace_back(v6AddrMask(host));
                }
                conditions.push_back(condition);
            }

            if (conditions.empty()) {
                continue;
            }
            if (viaTunnel) {
                FWPM_FILTER_CONDITION tunnel {};
                tunnel.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
                tunnel.matchType = FWP_MATCH_EQUAL;
                tunnel.conditionValue.type = FWP_UINT64;
                tunnel.conditionValue.uint64 = &luidValue;
                conditions.push_back(tunnel);
            }

            std::vector<FWPM_FILTER_CONDITION> udp = conditions;
            udp.push_back(uint8Condition(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP));
            udp.push_back(uint16Condition(FWPM_CONDITION_IP_REMOTE_PORT, DNS_PORT));
            if (auto result = m_wfp->addFilter(layer, FWP_ACTION_PERMIT, WEIGHT_PASS, udp, L"Allow DNS over UDP");
                result != LIBXTUN_OK) {
                return result;
            }

            std::vector<FWPM_FILTER_CONDITION> tcp = conditions;
            tcp.push_back(uint8Condition(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_TCP));
            tcp.push_back(uint16Condition(FWPM_CONDITION_IP_REMOTE_PORT, DNS_PORT));
            tcp.push_back(uint16Condition(FWPM_CONDITION_IP_REMOTE_PORT, DNS_TLS_PORT));
            if (auto result = m_wfp->addFilter(layer, FWP_ACTION_PERMIT, WEIGHT_PASS, tcp, L"Allow DNS over TCP");
                result != LIBXTUN_OK) {
                return result;
            }
        }
        return LIBXTUN_OK;
    }

    libxtun_error WindowsKillswitch::blockDns(const GUID &layer) noexcept
    {
        std::array<FWPM_FILTER_CONDITION, 2> udp {
            uint8Condition(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP),
            uint16Condition(FWPM_CONDITION_IP_REMOTE_PORT, DNS_PORT),
        };
        if (auto result = m_wfp->addFilter(layer, FWP_ACTION_BLOCK, WEIGHT_BLOCK_DNS, udp, L"Block DNS over UDP");
            result != LIBXTUN_OK) {
            return result;
        }

        std::array<FWPM_FILTER_CONDITION, 3> tcp {
            uint8Condition(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_TCP),
            uint16Condition(FWPM_CONDITION_IP_REMOTE_PORT, DNS_PORT),
            uint16Condition(FWPM_CONDITION_IP_REMOTE_PORT, DNS_TLS_PORT),
        };
        return m_wfp->addFilter(layer, FWP_ACTION_BLOCK, WEIGHT_BLOCK_DNS, tcp, L"Block DNS over TCP");
    }
}
