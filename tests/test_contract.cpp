#include "util/config.h"
#include "util/log.h"
#include "xtun.h"
#include "gtest/gtest.h"
#include <gtest/gtest.h>

TEST(ContractTunnel, NewRejectsNullTunnel)
{
    libxtun::test::TunOpts opts;
    EXPECT_EQ(libxtun_tunnel_new(nullptr, &opts.get()), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, NewRejectsNullOpts)
{
    libxtun_tunnel tun {};
    EXPECT_EQ(libxtun_tunnel_new(&tun, nullptr), LIBXTUN_ERR_INVALID_ARGS);
    libxtun_tunnel_free(&tun);
}

TEST(ContractTunnel, NewRejectsOutOfRangeKillswitch)
{
    libxtun::test::TunOpts opts;
    opts.killswitchMode(static_cast<libxtun_killswitch_mode>(LIBXTUN_KILLSWITCH_MODE_LAST + 1));

    libxtun_tunnel tun {};
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts.get()), LIBXTUN_ERR_INVALID_ARGS);
    libxtun_tunnel_free(&tun);
}

TEST(ContractTunnel, NewRejectsUnsupportedExcludedApps)
{
    const char *const excludedApps[] = { "C:\\Apps\\app.exe", nullptr };
    libxtun_tunnel_opts opts {};
    opts.size = sizeof(opts);
    opts.excluded_apps = excludedApps;

    libxtun_tunnel tun {};
    EXPECT_EQ(libxtun_tunnel_new(&tun, &opts), LIBXTUN_ERR_UNSUPPORTED);
    EXPECT_EQ(tun.handle, nullptr);
    libxtun_tunnel_free(&tun);
}

class ContractTunnelFd : public testing::TestWithParam<int>
{
};

TEST(ContractTunnel, RejectsNullTunfactory)
{
    libxtun_tunnel tun {};
    libxtun_tunfactory factory {
        .size = sizeof(libxtun_tunfactory),
        .factory_func = nullptr,
        .factory_priv = nullptr,
    };
    EXPECT_EQ(libxtun_tunnel_new_from_tunfactory(&tun, &factory), LIBXTUN_ERR_INVALID_ARGS);
}

TEST(ContractTunnel, FreeIgnoresNull)
{
    libxtun_tunnel_free(nullptr);
}

TEST(ContractProxy, FreeIgnoresNull)
{
    libxtun_proxy_free(nullptr);
}

TEST(ContractProxy, NewRejectsOutOfRangeProto)
{
    libxtun::test::Logger log;

    libxtun_proxy proxy {};
    log.wrapProxy(proxy);

    int res = libxtun_proxy_new(&proxy, static_cast<libxtun_proxy_proto>(LIBXTUN_PROXY_PROTO_LAST + 1), "", nullptr);
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
    libxtun_proxy_free(&proxy);
}

class ContractProxyProto : public testing::TestWithParam<libxtun_proxy_proto>
{
};

TEST_P(ContractProxyProto, NewRejectsNullHandle)
{
    const libxtun_proxy_proto proto = GetParam();

    int res = libxtun_proxy_new(nullptr, proto, nullptr, nullptr);
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
}

TEST_P(ContractProxyProto, NewRejectsNullConf)
{
    const libxtun_proxy_proto proto = GetParam();

    libxtun::test::Logger log;

    libxtun_proxy proxy {};
    log.wrapProxy(proxy);

    int res = libxtun_proxy_new(&proxy, proto, nullptr, nullptr);
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
    libxtun_proxy_free(&proxy);
}

TEST_P(ContractProxyProto, NewRejectsInvalidConf)
{
    const libxtun_proxy_proto proto = GetParam();

    libxtun::test::Logger log;

    libxtun_proxy proxy {};
    log.wrapProxy(proxy);

    int res = libxtun_proxy_new(&proxy, proto, "d34db33f", nullptr);
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
    libxtun_proxy_free(&proxy);
}

INSTANTIATE_TEST_SUITE_P(ContractProxy, ContractProxyProto, testing::ValuesIn(libxtun::test::allProtos()));

class ContractProxySetup : public testing::TestWithParam<libxtun::test::Setup>
{
};

TEST_P(ContractProxySetup, InitsFromConf)
{
    const auto &p = GetParam();
    const auto proto = p.proto;
    const auto &cfg = p.clientA;

    libxtun::test::Logger log;

    libxtun_proxy proxy {};
    log.wrapProxy(proxy);

    int res = libxtun_proxy_new(&proxy, proto, cfg.c_str(), nullptr);
    EXPECT_EQ(res, 0);
    libxtun_proxy_free(&proxy);
}

TEST_P(ContractProxySetup, NewRejectsMalformedRoute)
{
    const auto &p = GetParam();

    libxtun::test::Logger log;

    libxtun_proxy proxy {};
    log.wrapProxy(proxy);

    const char *malformed[] = { "10.0.0.0/33", nullptr };

    libxtun_proxy_opts malformedInclude { .size = sizeof(libxtun_proxy_opts), .includeRoutes = malformed };
    int res = libxtun_proxy_new(&proxy, p.proto, p.clientA.c_str(), &malformedInclude);
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
    libxtun_proxy_free(&proxy);

    libxtun_proxy_opts malformedExclude { .size = sizeof(libxtun_proxy_opts), .excludeRoutes = malformed };
    res = libxtun_proxy_new(&proxy, p.proto, p.clientA.c_str(), &malformedExclude);
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
    libxtun_proxy_free(&proxy);
}

TEST_P(ContractProxySetup, NewRejectsAllRoutesExcluded)
{
    const auto &p = GetParam();

    libxtun::test::Logger log;

    libxtun_proxy proxy {};
    log.wrapProxy(proxy);

    const char *all[] = { "0.0.0.0/0", "::/0", nullptr };
    libxtun_proxy_opts excludeAll { .size = sizeof(libxtun_proxy_opts), .excludeRoutes = all };
    int res = libxtun_proxy_new(&proxy, p.proto, p.clientA.c_str(), &excludeAll);
    EXPECT_EQ(res, LIBXTUN_ERR_INVALID_ARGS);
    libxtun_proxy_free(&proxy);
}

INSTANTIATE_TEST_SUITE_P(ContractProxy, ContractProxySetup, testing::ValuesIn(libxtun::test::SetupBuilder().build()),
                         [](const testing::TestParamInfo<libxtun::test::Setup> &info) { return info.param.name; });
