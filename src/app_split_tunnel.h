#ifndef LIBXTUN_APP_SPLIT_TUNNEL_H
#define LIBXTUN_APP_SPLIT_TUNNEL_H

#include "util/noncopyable.h"
#include "util/result.h"
#include "xtun.h"

#include <memory>

namespace libxtun
{
    class AppSplitTunnel : private NonCopyable
    {
    public:
        virtual ~AppSplitTunnel() = default;

        virtual libxtun_error activate(int ifIndex) = 0;
        virtual libxtun_error deactivate() = 0;
        virtual libxtun_error updateAddresses() = 0;
        virtual libxtun_error setTrafficBlocked(bool blocked) = 0;

        static ResultXtun<std::unique_ptr<AppSplitTunnel>> create(const char *const *apps, const char *serviceName);
    };
}

#endif // LIBXTUN_APP_SPLIT_TUNNEL_H
