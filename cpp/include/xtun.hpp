#ifndef XTUN_HPP
#define XTUN_HPP

#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>
#include <xtun.h>

namespace xtun
{
    namespace internal
    {
        inline std::vector<const char *> asArgv(const std::vector<std::string> &items)
        {
            std::vector<const char *> argv;
            argv.reserve(items.size() + 1);

            for (const auto &item : items) {
                argv.push_back(item.c_str());
            }

            argv.push_back(nullptr);
            return argv;
        }
    }

    class Proxy
    {
    public:
        Proxy(Proxy &&) noexcept = default;
        Proxy &operator=(Proxy &&other) noexcept
        {
            if (this != &other) {
                m_inner.reset();
                m_sockCb = std::move(other.m_sockCb);
                m_logCb = std::move(other.m_logCb);
                m_statusCb = std::move(other.m_statusCb);
                m_inner = std::move(other.m_inner);
            }
            return *this;
        }

        friend class Tunnel;
        friend class ProxyBuilder;

    private:
        using SockCb = std::function<void(int)>;
        using StatusCb = std::function<void(int)>;
        using LogCb = std::function<void(std::string)>;

        struct InnerCloser
        {
            void operator()(libxtun_proxy *inner) const noexcept
            {
                if (inner) {
                    libxtun_proxy_free(inner);
                }
                delete inner;
            }
        };

        explicit Proxy(std::unique_ptr<SockCb> sockCb, std::unique_ptr<LogCb> logCb, std::unique_ptr<StatusCb> statusCb,
                       std::unique_ptr<libxtun_proxy, InnerCloser> inner)
            : m_sockCb(std::move(sockCb)),
              m_logCb(std::move(logCb)),
              m_statusCb(std::move(statusCb)),
              m_inner(std::move(inner))
        {
        }
        std::unique_ptr<SockCb> m_sockCb;
        std::unique_ptr<LogCb> m_logCb;
        std::unique_ptr<StatusCb> m_statusCb;
        std::unique_ptr<libxtun_proxy, InnerCloser> m_inner;
    };

    class ProxyBuilder
    {
    public:
        ProxyBuilder &withSockCallback(std::function<void(int)> cb)
        {
            m_sockCb = std::move(cb);
            return *this;
        }

        ProxyBuilder &withLogHandler(std::function<void(std::string)> cb)
        {
            m_logHandlerCb = std::move(cb);
            return *this;
        }

        ProxyBuilder &withStatusHandler(std::function<void(int)> cb)
        {
            m_statusHandlerCb = std::move(cb);
            return *this;
        }

        ProxyBuilder &withIncludeRoutes(std::vector<std::string> prefixes)
        {
            m_includeRoutes = std::move(prefixes);
            return *this;
        }

        ProxyBuilder &withExcludeRoutes(std::vector<std::string> prefixes)
        {
            m_excludeRoutes = std::move(prefixes);
            return *this;
        }

        std::variant<Proxy, int> build(libxtun_proxy_proto proto, const std::string &conf)
        {
            std::unique_ptr<libxtun_proxy, Proxy::InnerCloser> inner(new libxtun_proxy());

            std::unique_ptr<decltype(m_sockCb)> sockCb = nullptr;
            if (m_sockCb) {
                sockCb.reset(new std::function(m_sockCb));
                inner->onsockspawn_priv = sockCb.get();
                inner->onsockspawn = +[](int socket, void *priv) {
                    auto *fn = reinterpret_cast<decltype(&m_sockCb)>(priv);
                    (*fn)(socket);
                };
            }

            std::unique_ptr<decltype(m_logHandlerCb)> logCb = nullptr;
            if (m_logHandlerCb) {
                logCb.reset(new std::function(m_logHandlerCb));
                inner->loghandler_priv = logCb.get();
                inner->loghandler = +[](const char *log, void *priv) {
                    auto *fn = reinterpret_cast<decltype(&m_logHandlerCb)>(priv);
                    if (log != nullptr)
                        (*fn)(std::string(log));
                };
            }

            std::unique_ptr<decltype(m_statusHandlerCb)> statusCb = nullptr;
            if (m_statusHandlerCb) {
                statusCb.reset(new std::function(m_statusHandlerCb));
                inner->statushandler_priv = statusCb.get();
                inner->statushandler = +[](const int status, void *priv) {
                    auto *fn = reinterpret_cast<decltype(&m_statusHandlerCb)>(priv);
                    (*fn)(status);
                };
            }

            const auto includeRoutes = internal::asArgv(m_includeRoutes);
            const auto excludeRoutes = internal::asArgv(m_excludeRoutes);

            libxtun_proxy_opts opts {};
            opts.size = sizeof(libxtun_proxy_opts);
            opts.includeRoutes = includeRoutes.data();
            opts.excludeRoutes = excludeRoutes.data();

            if (auto res = libxtun_proxy_new(inner.get(), proto, conf.c_str(), &opts); res != LIBXTUN_OK) {
                return res;
            }

            return Proxy { std::move(sockCb), std::move(logCb), std::move(statusCb), std::move(inner) };
        }

    private:
        std::function<void(int)> m_sockCb;
        std::function<void(std::string)> m_logHandlerCb;
        std::function<void(int)> m_statusHandlerCb;
        std::vector<std::string> m_includeRoutes;
        std::vector<std::string> m_excludeRoutes;
    };

    class Tunnel
    {
    public:
        Tunnel(Tunnel &&) noexcept = default;
        Tunnel &operator=(Tunnel &&) noexcept = default;

        int start()
        {
            return libxtun_tunnel_start(m_inner.get());
        }
        int attachProxy(Proxy &proxy)
        {
            return libxtun_tunnel_attach_proxy(m_inner.get(), proxy.m_inner.get());
        }
        void detachProxy(Proxy &proxy)
        {
            libxtun_tunnel_detach_proxy(m_inner.get(), proxy.m_inner.get());
        }
        void networkChanged()
        {
            libxtun_tunnel_network_changed(m_inner.get());
        }

        friend class TunnelBuilder;

    private:
        struct TunnelCloser
        {
            void operator()(libxtun_tunnel *inner) const noexcept
            {
                if (inner) {
                    libxtun_tunnel_free(inner);
                }
                delete inner;
            }
        };

        Tunnel(std::unique_ptr<libxtun_tunnel, TunnelCloser> inner) : m_inner(std::move(inner))
        {
        }
        std::unique_ptr<libxtun_tunnel, TunnelCloser> m_inner;
    };

    class TunnelBuilder
    {
    public:
        TunnelBuilder &withExcludedApps(std::vector<std::string> paths, std::string serviceName)
        {
            m_excludedApps = std::move(paths);
            m_splitServiceName = std::move(serviceName);
            return *this;
        }

        TunnelBuilder &withDns(std::vector<std::string> addrs)
        {
            m_dns = std::move(addrs);
            return *this;
        }

        TunnelBuilder &withDnsExceptions(std::vector<std::string> addrs)
        {
            m_dnsExceptions = std::move(addrs);
            return *this;
        }

        TunnelBuilder &withKillswitchMode(libxtun_killswitch_mode mode)
        {
            m_killswitchMode = mode;
            return *this;
        }

        TunnelBuilder &withInterfaceAddrs(std::vector<std::string> addrs)
        {
            m_ifaceAddrs = std::move(addrs);
            return *this;
        }

        TunnelBuilder &withMtu(int mtu)
        {
            m_mtu = mtu;
            return *this;
        }

        TunnelBuilder &withMacosGroup(int group)
        {
            m_macosGroup = group;
            return *this;
        }

        std::variant<Tunnel, int> build()
        {
            libxtun_tunnel_opts opts {};
            opts.size = sizeof(libxtun_tunnel_opts);

            std::unique_ptr<libxtun_tunnel, Tunnel::TunnelCloser> inner(new libxtun_tunnel());

            const auto dns = internal::asArgv(m_dns);
            opts.dns = dns.data();

            const auto dnsExceptions = internal::asArgv(m_dnsExceptions);
            opts.dns_exceptions = dnsExceptions.data();

            const auto ifAddrs = internal::asArgv(m_ifaceAddrs);
            opts.if_addrs = ifAddrs.data();

            const auto excludedApps = internal::asArgv(m_excludedApps);
            opts.excluded_apps = excludedApps.data();
            opts.split_service_name = m_splitServiceName.c_str();

            opts.killswitch_mode = m_killswitchMode;
            opts.mtu = m_mtu;
            opts.macos_group = m_macosGroup;

            if (auto res = libxtun_tunnel_new(inner.get(), &opts); res != LIBXTUN_OK) {
                return res;
            }

            return Tunnel { std::move(inner) };
        }

    private:
        std::vector<std::string> m_dns;
        std::vector<std::string> m_dnsExceptions;
        std::vector<std::string> m_ifaceAddrs;
        std::vector<std::string> m_excludedApps;
        std::string m_splitServiceName;
        libxtun_killswitch_mode m_killswitchMode = LIBXTUN_KILLSWITCH_MODE_DISABLED;
        int m_mtu = 0;
        int m_macosGroup = 0;
    };
} // namespace xtun

#endif // XTUN_HPP
