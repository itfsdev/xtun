#include "tunnel.h"
#include "dns.h"
#include "killswitch.h"
#include "net/ip.h"
#include "proxy.h"
#include "router.h"
#include "tun_device.h"
#include "util/cinterop.h"
#include "util/result.h"
#include "xtun.h"
#include <cstddef>
#include <memory>
#include <mutex>
#include <span>
#include <utility>
#include <vector>

namespace libxtun
{
    Tunnel::~Tunnel()
    {
        if (m_proxy) {
            m_proxy->attachIo(nullptr);
        }
        if (m_device != nullptr) {
            m_device->stopMonitor();
            m_device->cancelRead();
        }
        if (m_dns != nullptr) {
            m_dns->revert();
        }
        if (m_router != nullptr) {
            m_router->revert();
        }
    }

    ResultXtun<std::unique_ptr<Tunnel>> Tunnel::fromOpts(const libxtun_tunnel_opts &opts)
    {
        if (opts.excluded_apps != nullptr && *opts.excluded_apps != nullptr) {
            return fail(LIBXTUN_ERR_UNSUPPORTED);
        }
        
        auto dnsDefaults = cinterop::parseListT<net::IpAddress>(opts.dns);
        if (!dnsDefaults) {
            return fail(dnsDefaults.error());
        }
        auto dnsExceptions = cinterop::parseListT<net::IpAddress>(opts.dns_exceptions);
        if (!dnsExceptions) {
            return fail(dnsExceptions.error());
        }

        auto tun = std::unique_ptr<Tunnel>(new Tunnel());
        tun->m_dnsDefaults = std::move(dnsDefaults).value();
        tun->m_device = createTunDevice();
        tun->m_router = Router::create(*tun);
        tun->m_killswitch = Killswitch::create(opts.killswitch_mode, opts.macos_group, std::move(dnsExceptions).value());

        auto &dev = tun->m_device;
        auto &router = tun->m_router;
        auto &killswitch = tun->m_killswitch;

        if (auto rc = dev->open(); rc != LIBXTUN_OK) {
            return fail(rc);
        }

        dev->startMonitor(*tun);

        const auto ifAddrs = cinterop::parseStrList(opts.if_addrs);
        if (auto rc = router->configureInterface(dev->name(), dev->ifIndex(), ifAddrs, opts.mtu); rc != LIBXTUN_OK) {
            return fail(rc);
        }

        if (auto rc = killswitch->update(dev->ifIndex(), dev->name())) {
            return fail(rc);
        }

        tun->m_dns = Dns::create(dev->ifIndex(), dev->name());

        // FIXME(cd-amn): add a handle in router to obtain these addrs, and remove this one completely
        for (const auto &ifAddr : ifAddrs) {
            if (auto prefix = net::IpPrefix::parse(ifAddr)) {
                tun->m_addrs.emplace_back(std::move(*prefix));
            }
        }

        return tun;
    }

    ResultXtun<std::unique_ptr<Tunnel>> Tunnel::fromTunfactory(Tunnel::TunfactoryFunc tunfactory,
                                                               std::vector<net::IpPrefix> ifaddrs,
                                                               std::vector<net::IpAddress> defaultDns)
    {
#ifdef WIN32
        return fail(LIBXTUN_ERR_UNSUPPORTED);
#endif

        if (!tunfactory || ifaddrs.empty()) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }

        auto tun = std::unique_ptr<Tunnel>(new Tunnel());
        tun->m_tunfactory = tunfactory;
        tun->m_addrs = std::move(ifaddrs);
        tun->m_dnsDefaults = std::move(defaultDns);
        return tun;
    }

    int Tunnel::attachProxy(Proxy *proxy)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (proxy == nullptr) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        ProxyProfile profile = proxy->profile();
        const std::vector<net::IpAddress> &resolvers = profile.dnsServers.empty() ? m_dnsDefaults : profile.dnsServers;

        if (m_killswitch != nullptr) {
            if (auto rc = m_killswitch->protect(profile.includeRoutes, profile.excludeRoutes, resolvers);
                rc != LIBXTUN_OK) {
                if (m_router != nullptr) {
                    m_router->clearProxyRoutes();
                }
                detachProxyLocked(m_proxy);
                if (m_dns != nullptr) {
                    m_dns->revert();
                }
                m_killswitch->protect({}, {}, {});
                return rc;
            }
        }

        if (m_proxy) {
            detachProxyLocked(m_proxy);
        }

        if (m_tunfactory) {
            if (int fd = m_tunfactory(resolvers, profile.includeRoutes, profile.excludeRoutes, profile.mtu); fd >= 0) {
                auto dev = createTunDevice();
                if (auto err = dev->adoptFd(fd)) {
                    return err;
                }
                m_device = std::move(dev);
            } else {
                return LIBXTUN_ERR_DEVICE_CREATE;
            }
        }

        if (profile.mtu) {
            // TODO(cd-amn): write MTU
            void(profile.mtu);
        }

        if (m_router != nullptr) {
            if (auto rc = m_router->setProxyRoutes(profile.includeRoutes, profile.excludeRoutes); rc != LIBXTUN_OK) {
                // FIXME(cd-amn): we are reverting too much in here. Should be rollback() or similar
                m_router->revert();
                if (m_dns != nullptr) {
                    m_dns->revert();
                }
                if (m_killswitch != nullptr) {
                    m_killswitch->protect({}, {}, {});
                }
                return LIBXTUN_ERR_SYSTEM;
            }
        }

        if (m_dns != nullptr) {
            if (m_dns->apply(resolvers) != LIBXTUN_OK) {
                m_dns->revert();
                if (m_router != nullptr) {
                    m_router->clearProxyRoutes();
                }
                if (m_killswitch != nullptr) {
                    m_killswitch->protect({}, {}, {});
                }
                return LIBXTUN_ERR_DNS;
            }
        }

        m_device->resetReadCancellation();

        proxy->attachIo(this);
        proxy->event(m_device->up() ? ProxyEvent::Up : ProxyEvent::Down);
        m_proxy = proxy;

        return LIBXTUN_OK;
    }

    void Tunnel::detachProxy(Proxy *proxy)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (proxy == nullptr || m_proxy != proxy) {
            return;
        }

        if (m_dns != nullptr) {
            m_dns->revert();
        }
        if (m_router != nullptr) {
            // FIXME(cd-amn): clear routes only for particular Proxy
            m_router->clearProxyRoutes();
        }
        detachProxyLocked(proxy);
        if (m_killswitch != nullptr) {
            m_killswitch->protect({}, {}, {});
        }
    }

    void Tunnel::detachProxyLocked(Proxy *proxy)
    {
        if (proxy == nullptr || m_proxy != proxy) {
            return;
        }

        // FIXME: this abstraction make sense for ONE to MANY model
        (void)proxy;

        m_proxy->event(ProxyEvent::Down);
        m_proxy->attachIo(nullptr);
        m_proxy = nullptr;
    }

    int Tunnel::start()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_started = true;
        // TODO(cd-amn): implement kick-off and suspend/shutdown based on metrics for the routes
        // The idea:
        // - All routes initialize with high metrics (system never use them until the raise)
        // - Calling start() sets all routes' metrics to the lower value
        // - So the traffic starts flowing
        //
        // This makes start() to respond almost instantly: interface is ready, and everything
        // is established, no further change required
        return LIBXTUN_OK;
    }

    void Tunnel::emit(Event ev)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_proxy == nullptr) {
            return;
        }

        switch (ev) {
        case Event::Up: m_proxy->event(ProxyEvent::Up); break;
        case Event::Down: m_proxy->event(ProxyEvent::Down); break;
        case Event::MtuUpdate: m_proxy->event(ProxyEvent::MtuUpdate); break;
        case Event::UplinkUpdate:
            m_proxy->event(ProxyEvent::Down);
            m_proxy->event(ProxyEvent::Up);
            break;
        }
    }

    int Tunnel::read(std::span<std::byte> buf)
    {
        return m_device->read(buf);
    }

    int Tunnel::write(std::span<const std::byte> packet)
    {
        return m_device->write(packet);
    }

    void Tunnel::protectSocket(int fd)
    {
        if (m_router != nullptr) {
            m_router->protectSocket(fd);
        }
    }

    void Tunnel::wake()
    {
        m_device->wakeRead();
    }

    void Tunnel::halt()
    {
        m_device->cancelRead();
    }

    int Tunnel::mtu() const
    {
        return m_device->mtu();
    }

    std::vector<net::IpPrefix> Tunnel::addresses()
    {
        return m_addrs;
    }

    void Tunnel::onLinkStateChanged(bool up)
    {
        emit(up ? Event::Up : Event::Down);
    }

    void Tunnel::onMtuChanged(int)
    {
        emit(Event::MtuUpdate);
    }

    void Tunnel::onRouteChanged()
    {
        if (m_router != nullptr) {
            m_router->onRouteChanged();
        }
    }

    void Tunnel::onUplinkChanged()
    {
        emit(Event::UplinkUpdate);
    }

    void Tunnel::networkChanged()
    {
        emit(Event::UplinkUpdate);
    }
}

int libxtun_tunnel_new(struct libxtun_tunnel *tun, const struct libxtun_tunnel_opts *opts)
{
    if (tun == nullptr || opts == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    // TODO(cd-amn): handle all opts up to the specified size
    // If a newer xtun .dll/.so is used in already compiled application - it
    // should not break anything, just handle all available opts
    if (opts->size < sizeof(*opts)) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    if (opts->killswitch_mode < LIBXTUN_KILLSWITCH_MODE_DISABLED || opts->killswitch_mode > LIBXTUN_KILLSWITCH_MODE_LAST) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    auto res = libxtun::Tunnel::fromOpts(*opts);
    if (!res) {
        return res.error();
    }

    tun->handle = res.value().release();
    return LIBXTUN_OK;
}

int libxtun_tunnel_new_from_tunfactory(struct libxtun_tunnel *tun, libxtun_tunfactory *tunfactory)
{
    using namespace libxtun;

    if (!tun || !tunfactory || !tunfactory->factory_func) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    tun->handle = nullptr;

    auto ifaddrs = cinterop::parseListT<net::IpPrefix>(tunfactory->if_addrs);
    if (!ifaddrs) {
        return ifaddrs.error();
    }
    auto dns = cinterop::parseListT<net::IpAddress>(tunfactory->dns);
    if (!dns) {
        return dns.error();
    }

    auto res = Tunnel::fromTunfactory(
            [createTun = tunfactory->factory_func, priv = tunfactory->factory_priv](
                    const std::vector<net::IpAddress> &dns, const std::vector<net::IpPrefix> &includeRoutes,
                    const std::vector<net::IpPrefix> &excludeRoutes, int mtu) {
                const auto cDns = cinterop::toStrList(dns);
                const auto cIncludeRoutes = cinterop::toStrList(includeRoutes);
                const auto cExcludeRoutes = cinterop::toStrList(excludeRoutes);
                return createTun(cDns.data(), cIncludeRoutes.data(), cExcludeRoutes.data(), mtu, priv);
            },
            ifaddrs.value(), dns.value());
    if (!res) {
        return res.error();
    }

    tun->handle = res.value().release();
    return LIBXTUN_OK;
}

void libxtun_tunnel_free(struct libxtun_tunnel *tun)
{
    if (tun == nullptr) {
        return;
    }
    delete reinterpret_cast<libxtun::Tunnel *>(tun->handle);
    tun->handle = nullptr;
}

int libxtun_tunnel_start(struct libxtun_tunnel *tun)
{
    if (tun == nullptr || tun->handle == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }
    return reinterpret_cast<libxtun::Tunnel *>(tun->handle)->start();
}

int libxtun_tunnel_attach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy)
{
    if (tun == nullptr || tun->handle == nullptr || proxy == nullptr || proxy->handle == nullptr) {
        return LIBXTUN_ERR_INVALID_ARGS;
    }

    auto *obj = reinterpret_cast<libxtun::Tunnel *>(tun->handle);
    return obj->attachProxy(reinterpret_cast<libxtun::Proxy *>(proxy->handle));
}

void libxtun_tunnel_detach_proxy(struct libxtun_tunnel *tun, struct libxtun_proxy *proxy)
{
    if (tun == nullptr || tun->handle == nullptr || proxy == nullptr || proxy->handle == nullptr) {
        return;
    }

    auto *obj = reinterpret_cast<libxtun::Tunnel *>(tun->handle);
    obj->detachProxy(reinterpret_cast<libxtun::Proxy *>(proxy->handle));
}

void libxtun_tunnel_network_changed(struct libxtun_tunnel *tun)
{
    if (!tun || !tun->handle) {
        return;
    }

    auto *obj = reinterpret_cast<libxtun::Tunnel *>(tun->handle);
    obj->networkChanged();
}
