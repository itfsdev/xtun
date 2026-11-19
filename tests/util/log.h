#ifndef TEST_LOG_H
#define TEST_LOG_H

#include "proxy.h"
#include "wrapper.h"
#include "xtun.h"

namespace libxtun::test
{
    class Logger : public ProxyWrapper
    {
    public:
        Logger() {};
        explicit Logger(std::string prefix) : m_prefix(prefix) {};

        ClientCallbacks &wrapCallbacks(ClientCallbacks &callbacks) override
        {
            callbacks.onLog = Logger::clog;
            callbacks.onLogPriv = this;
            return callbacks;
        }
        ClientCallbacks defaultCallbacks() override
        {
            ClientCallbacks callbacks {};
            return wrapCallbacks(callbacks);
        }

        libxtun_proxy &wrapProxy(libxtun_proxy &proxy) override
        {
            proxy.loghandler = Logger::clog;
            proxy.loghandler_priv = this;
            return proxy;
        }
        libxtun_proxy defaultProxy() override
        {
            libxtun_proxy proxy {};
            return wrapProxy(proxy);
        }

        static void clog(const char *message, void *priv)
        {
            reinterpret_cast<Logger *>(priv)->log(message);
        }
        void log(const char *message)
        {
            if (!m_prefix.empty()) {
                printf("[%s] %s\n", m_prefix.c_str(), message);
            } else {
                printf("%s\n", message);
            }
            // Call fflush() so that the full log can be read when a test crashes or hangs in CI.
            fflush(stdout);
        }

    private:
        std::string m_prefix;
    };
}

#endif
