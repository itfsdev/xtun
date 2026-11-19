#ifndef TEST_CONFIG_H
#define TEST_CONFIG_H

#include "../mock/memserver.h"
#include "socket.h"
#include "util/noncopyable.h"
#include "wrapper.h"
#include "xtun.h"
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{
    template<typename... A> std::string formatString(const char *fmt, A... args)
    {
        int len = std::snprintf(nullptr, 0, fmt, args...);
        if (len < 0) {
            return {};
        }

        std::string str(len, '\0');
        std::snprintf(&str[0], str.size() + 1, fmt, args...);
        return str;
    }

    std::string join(const std::vector<std::string> list, const std::string sep = ", ")
    {
        if (list.empty()) {
            return {};
        }

        return std::accumulate(std::next(list.begin()), list.end(), list[0],
                               [&sep](std::string acc, const std::string &next) { return std::move(acc) + sep + next; });
    }
}

namespace libxtun::test
{
    constexpr const char *DEFAULT_IFADDR = "10.9.9.1";
    constexpr const char *DEFAULT_IFADDR_PREFIX = "10.9.9.1/32";
    constexpr const char *DEFAULT_ROUTE = "10.9.9.2";
    constexpr const char *DEFAULT_ROUTE_PREFIX = "10.9.9.2/32";
    constexpr uint16_t DEFAULT_PORT = 35777;

    struct Setup
    {
        std::string name;
        libxtun_proxy_proto proto;
        std::string clientA;
        std::optional<std::string> clientB;
        std::shared_ptr<ProxyWrapper> wrapper;
        std::function<std::unique_ptr<MemServer>(std::string log)> createServer;
    };

    class SetupBuilder
    {
    private:
        std::optional<std::string> loadFromFile(std::string path)
        {
            std::ifstream f(path);
            if (!f) {
                return std::nullopt;
            }
            std::string cfg { std::istreambuf_iterator<char>(f), {} };
            if (auto pos = cfg.find("{ROUTES}"); pos != std::string::npos) {
                cfg.replace(pos, 8, join(m_routes));
            }
            return cfg;
        }

        Setup awgLocalSetup()
        {
            const char *clientTemplateA = "[Interface]\n"
                                          "Address = 10.9.10.2/32\n"
                                          "PrivateKey = eMTu4xarpbzj2RKaXO0WiLXA5Xd3coo2rcZPmnR111k=\n"
                                          "%s"
                                          "[Peer]\n"
                                          "PublicKey = Wg8kZUNcdM6034MJwxlj02Nx9wut7QcUPyb88+j0QXY=\n"
                                          "AllowedIPs = 10.9.10.2/32, %s\n"
                                          "Endpoint = 127.0.0.1:%d\n";

            const char *clientTemplateB = "[Interface]\n"
                                          "Address = 10.9.10.3/32\n"
                                          "PrivateKey = yH6N0U9I7Ui4KYNOWyacmDqY4KcD21mL0MdA6v7IuXI=\n"
                                          "%s"
                                          "[Peer]\n"
                                          "PublicKey = Wg8kZUNcdM6034MJwxlj02Nx9wut7QcUPyb88+j0QXY=\n"
                                          "AllowedIPs = 10.9.10.3/32, %s\n"
                                          "Endpoint = 127.0.0.1:%d\n";

            const char *serverTemplate = "[Interface]\n"
                                         "Address = 10.9.10.1/32\n"
                                         "ListenPort = %d\n"
                                         "PrivateKey = 6MCXtO93sn3WXDWu2MqLi9EZ3Kq2BNqQX9fgIuPijUA=\n"
                                         "[Peer]\n"
                                         "PublicKey = +UXxZp+YETlS9HP/ggN/Y6Ya2sGiYSDvCqU67cdmUyc=\n"
                                         "AllowedIPs = 10.9.10.2/32\n"
                                         "[Peer]\n"
                                         "PublicKey = DQKhiAQPdzOtpJhQ57rdA2JeMbKKcfJ93NKj4e1QNUU=\n"
                                         "AllowedIPs = 10.9.10.3/32\n";

            auto routes = join(m_routes);
            const std::string dns = m_dns.empty() ? std::string() : "DNS = " + join(m_dns) + "\n";

            return {
                .name = "awg_local",
                .proto = LIBXTUN_PROXY_PROTO_AWG,
                .clientA = formatString(clientTemplateA, dns.c_str(), routes.c_str(), m_port),
                .clientB = formatString(clientTemplateB, dns.c_str(), routes.c_str(), m_port),
                .wrapper = std::make_shared<SockBindRemover>(),
                .createServer =
                        [cfg = formatString(serverTemplate, m_port)](std::string log) {
                            return std::make_unique<MemServer>(log, LIBXTUN_PROXY_PROTO_AWG, cfg.c_str());
                        },
            };
        }

        std::optional<Setup> awgRealSetup()
        {
            auto cfgA = loadFromFile(XTUN_TEST_SECRETS_DIR "/awg.conf");
            if (!cfgA) {
                return std::nullopt;
            }
            auto cfgB = loadFromFile(XTUN_TEST_SECRETS_DIR "/awgB.conf");

            return Setup {
                .name = "awg_real",
                .proto = LIBXTUN_PROXY_PROTO_AWG,
                .clientA = std::move(cfgA.value()),
                .clientB = std::move(cfgB),
                .wrapper = std::make_shared<DummyWrapper>(),
                .createServer = [](std::string log) { return nullptr; },
            };
        }

        std::optional<Setup> xrayRealSetup()
        {
            auto cfgA = loadFromFile(XTUN_TEST_SECRETS_DIR "/xray.json");
            if (!cfgA) {
                return std::nullopt;
            }
            auto cfgB = loadFromFile(XTUN_TEST_SECRETS_DIR "/xrayB.json");

            return Setup {
                .name = "xray_real",
                .proto = LIBXTUN_PROXY_PROTO_XRAY,
                .clientA = std::move(cfgA).value(),
                .clientB = std::move(cfgB),
                .wrapper = std::make_shared<DummyWrapper>(),
                .createServer = [](std::string log) { return nullptr; },
            };
        }

    public:
        SetupBuilder &withPort(uint16_t port)
        {
            m_port = port;
            return *this;
        }
        SetupBuilder &withRoutes(std::vector<std::string> routes)
        {
            m_routes = std::move(routes);
            return *this;
        }
        SetupBuilder &withDns(std::vector<std::string> dns)
        {
            m_dns = std::move(dns);
            return *this;
        }

        std::vector<Setup> build()
        {
            std::vector<Setup> res;
            res.emplace_back(awgLocalSetup());
            if (auto setup = awgRealSetup()) {
                res.emplace_back(std::move(setup).value());
            }
            if (auto setup = xrayRealSetup()) {
                res.emplace_back(std::move(setup).value());
            }
            return res;
        }

    private:
        uint16_t m_port = DEFAULT_PORT;
        std::string m_ifaddr = DEFAULT_IFADDR_PREFIX;
        std::vector<std::string> m_routes = { DEFAULT_ROUTE_PREFIX };
        std::vector<std::string> m_dns;
    };

    struct TunOpts : private NonCopyable
    {
    public:
        TunOpts()
        {
            m_opts.size = sizeof(libxtun_tunnel_opts);
            m_opts.macos_group = -1;
        }

        TunOpts &dns(std::vector<std::string> dns)
        {
            m_dns = dns;
            return *this;
        }
        TunOpts &dnsExceptions(std::vector<std::string> dnsExceptions)
        {
            m_dnsExceptions = dnsExceptions;
            return *this;
        }
        TunOpts &killswitchMode(libxtun_killswitch_mode killswitchMode)
        {
            m_opts.killswitch_mode = killswitchMode;
            return *this;
        }
        TunOpts &ifaddrs(std::vector<std::string> ifaddrs)
        {
            m_ifaddrs = ifaddrs;
            return *this;
        }
        TunOpts &mtu(int mtu)
        {
            m_opts.mtu = mtu;
            return *this;
        }
        TunOpts &healthSeconds(int healthSeconds)
        {
            m_opts.health_seconds = healthSeconds;
            return *this;
        }
        TunOpts &excludedApps(std::vector<std::string> excludedApps)
        {
            m_excludedApps = excludedApps;
            return *this;
        }

        const libxtun_tunnel_opts &get()
        {
            m_opts.dns = toPtrs(m_dns, m_dnsPtrs);
            m_opts.dns_exceptions = toPtrs(m_dnsExceptions, m_dnsExceptionsPtrs);
            m_opts.if_addrs = toPtrs(m_ifaddrs, m_ifaddrsPtrs);
            m_opts.excluded_apps = toPtrs(m_excludedApps, m_excludedAppsPtrs);
            return m_opts;
        }

    private:
        static const char *const *toPtrs(const std::vector<std::string> &list, std::vector<const char *> &ptrs)
        {
            ptrs.clear();
            ptrs.reserve(list.size() + 1);
            for (const auto &it : list) {
                ptrs.push_back(it.c_str());
            }
            ptrs.push_back(nullptr);
            return ptrs.data();
        }

        libxtun_tunnel_opts m_opts {};
        std::vector<std::string> m_dns;
        std::vector<std::string> m_dnsExceptions;
        std::vector<std::string> m_ifaddrs = { DEFAULT_IFADDR };
        std::vector<std::string> m_excludedApps;
        std::vector<const char *> m_dnsPtrs, m_dnsExceptionsPtrs, m_ifaddrsPtrs, m_excludedAppsPtrs;
    };

    static std::vector<libxtun_proxy_proto> allProtos()
    {
        std::vector<libxtun_proxy_proto> res;
        for (int i = LIBXTUN_PROXY_PROTO_AWG; i < LIBXTUN_PROXY_PROTO_LAST; i++) {
            res.push_back(static_cast<libxtun_proxy_proto>(i));
        }
        return res;
    }

    static std::vector<libxtun_killswitch_mode> allKillswitchModes()
    {
        std::vector<libxtun_killswitch_mode> res;
        for (int i = LIBXTUN_KILLSWITCH_MODE_DISABLED; i <= LIBXTUN_KILLSWITCH_MODE_LAST; i++) {
            res.push_back(static_cast<libxtun_killswitch_mode>(i));
        }
        return res;
    }
}

#endif
