// Checks with the real split tunnel driver that an excluded app goes around the tunnel and an included app goes
// through it. Both apps are copies of the same xtun_split_probe program in different folders: the driver tells
// apps apart only by the full path of their EXE.
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/log.h"
#include "util/probe_codes.h"
#include "util/random.h"
#include "util/split_driver_windows.h"
#include "util/status.h"

#include <windows.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    using namespace libxtun;
    using test::ProbeResult;
    namespace fs = std::filesystem;

    constexpr DWORD PROBE_WAIT_MS = 10000;

    std::string pathUtf8(const fs::path &path)
    {
        const auto text = path.u8string();
        return { reinterpret_cast<const char *>(text.data()), text.size() };
    }

    std::wstring wide(const std::string &ascii)
    {
        return { ascii.begin(), ascii.end() };
    }

    std::string modeName(libxtun_killswitch_mode mode)
    {
        switch (mode) {
        case LIBXTUN_KILLSWITCH_MODE_DISABLED: return "Disabled";
        case LIBXTUN_KILLSWITCH_MODE_SOFT: return "Soft";
        case LIBXTUN_KILLSWITCH_MODE_HARD: return "Hard";
        }
        return "Unknown";
    }

    // Return the long form of an existing path: "C:\Users\RUNNER~1\..." becomes "C:\Users\runneradmin\...".
    fs::path longPath(const fs::path &path)
    {
        const DWORD size = ::GetLongPathNameW(path.c_str(), nullptr, 0);
        if (size == 0) {
            return {};
        }
        std::wstring result(size, L'\0');
        result.resize(::GetLongPathNameW(path.c_str(), result.data(), size));
        return result;
    }

    // Starts an app (a copy of xtun_split_probe) by its EXE path with CreateProcessW().
    // finish() waits until the app exits and turns its exit code into the path of its connection.
    // If the test stops before finish(), the destructor kills the app.
    class ProbeProcess
    {
    public:
        ProbeProcess(const fs::path &exe, const std::vector<std::wstring> &args)
        {
            // The arguments of the tests contain no quotes, so simple quoting is enough.
            std::wstring commandLine = L"\"" + exe.native() + L"\"";
            for (const std::wstring &arg : args) {
                commandLine += L" \"" + arg + L"\"";
            }
            STARTUPINFOW startup { sizeof(startup) };
            PROCESS_INFORMATION child {};
            if (!::CreateProcessW(exe.c_str(), commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                                  nullptr, &startup, &child)) {
                ADD_FAILURE() << "cannot start the probe: " << ::GetLastError();
                return;
            }
            ::CloseHandle(child.hThread);
            m_process = child.hProcess;
        }

        ~ProbeProcess()
        {
            if (m_process != nullptr) {
                ::TerminateProcess(m_process, 1);
                ::WaitForSingleObject(m_process, PROBE_WAIT_MS);
                ::CloseHandle(m_process);
            }
        }

        ProbeProcess(const ProbeProcess &) = delete;
        ProbeProcess &operator=(const ProbeProcess &) = delete;

        std::optional<ProbeResult> finish()
        {
            // Windows signals a process handle when the process exits.
            if (m_process == nullptr || ::WaitForSingleObject(m_process, PROBE_WAIT_MS) != WAIT_OBJECT_0) {
                ADD_FAILURE() << "the probe did not finish";
                return std::nullopt;
            }
            DWORD code = 0;
            ::GetExitCodeProcess(m_process, &code);
            ::CloseHandle(m_process);
            m_process = nullptr;

            switch (code) {
            case test::CONNECTED_VIA_TUNNEL: return ProbeResult::Tunnel;
            case test::CONNECTED_ELSEWHERE: return ProbeResult::Uplink;
            case WSAEACCES: return ProbeResult::Blocked;
            default: ADD_FAILURE() << "the probe failed with " << code; return std::nullopt;
            }
        }

    private:
        HANDLE m_process = nullptr;
    };

    class SplitTraffic : public test::KillswitchTest, public testing::WithParamInterface<libxtun_killswitch_mode>
    {
    protected:
        void SetUp() override
        {
            KillswitchTest::SetUp();
            if (IsSkipped() || HasFatalFailure()) {
                return;
            }
            if (const std::string reason = test::splitDriverSkipReason(); !reason.empty()) {
                GTEST_SKIP() << reason;
            }

            // CMake builds xtun_split_probe.exe next to xtun_tests.exe.
            std::wstring self(MAX_PATH, L'\0');
            self.resize(::GetModuleFileNameW(nullptr, self.data(), static_cast<DWORD>(self.size())));
            const fs::path probe = fs::path(self).parent_path() / L"xtun_split_probe.exe";

            // Copy the same program into two folders:
            //   %TEMP%\xtun-split-<random>\exclude-П浏🚀\xtun_split_probe.exe   the excluded app
            //   %TEMP%\xtun-split-<random>\include\xtun_split_probe.exe         the included app
            // The excluded path has a Cyrillic letter, a CJK ideograph and an emoji to check Unicode paths too.
            // On GitHub runners %TEMP% has a short name, see longPath().
            const fs::path temp = longPath(fs::temp_directory_path());
            ASSERT_FALSE(temp.empty()) << ::GetLastError();
            m_directory = temp / (L"xtun-split-" + std::to_wstring(libxtun::rand::next32()));
            m_exclude = m_directory / L"exclude-\u041f\u6d4f\U0001f680" / probe.filename();
            m_include = m_directory / L"include" / probe.filename();
            for (const fs::path &app : { m_exclude, m_include }) {
                fs::create_directories(app.parent_path());
                fs::copy_file(probe, app);
            }
            test::Logger("test").log(("excluded app: " + pathUtf8(m_exclude)).c_str());
        }

        void TearDown() override
        {
            // Free the proxy here even after a failed ASSERT, so it stops before the logger and the server go away.
            libxtun_tunnel_detach_proxy(&m_tunnel, &m_proxy);
            libxtun_proxy_free(&m_proxy);
            libxtun_tunnel_free(&m_tunnel);

            if (!m_directory.empty()) {
                std::error_code error;
                fs::remove_all(fs::path(L"\\\\?\\" + m_directory.native()), error);
                EXPECT_FALSE(error) << error.message();
            }
        }

        // Create a full tunnel that excludes m_exclude. The exclusions start working only after attachProxy().
        void createTunnel()
        {
            m_server = m_setup.createServer("server");
            m_opts.killswitchMode(GetParam()).excludedApps({ pathUtf8(m_exclude) });
            ASSERT_EQ(libxtun_tunnel_new(&m_tunnel, &m_opts.get()), LIBXTUN_OK);
        }

        // Attach a new local AWG proxy and wait until it connects.
        void attachProxy()
        {
            m_setup.wrapper->wrapProxy(m_proxy);
            m_log.wrapProxy(m_proxy);
            m_status.wrapProxy(m_proxy);
            ASSERT_EQ(libxtun_proxy_new(&m_proxy, m_setup.proto, m_setup.clientA.c_str(), nullptr), LIBXTUN_OK);
            ASSERT_EQ(libxtun_tunnel_attach_proxy(&m_tunnel, &m_proxy), LIBXTUN_OK);
            ASSERT_TRUE(m_status.await(LIBXTUN_STATUS_CONNECTED, std::chrono::seconds(5)));
        }

        void detachProxy()
        {
            libxtun_tunnel_detach_proxy(&m_tunnel, &m_proxy);
            libxtun_proxy_free(&m_proxy);
            m_proxy = {};
        }

        // Arguments for the probe: connect over TCP to an Internet address.
        std::vector<std::wstring> tcpArgs() const
        {
            return { L"tcp", wide(test::ROUTED_HOST_V4.host), std::to_wstring(test::PROBE_PORT),
                     wide(test::DEFAULT_IFADDR) };
        }

        // Run the app and return the path of its connection.
        std::optional<ProbeResult> connectFrom(const fs::path &app)
        {
            return ProbeProcess(app, tcpArgs()).finish();
        }

        // The first setup is awg_local: an AWG server inside this test process.
        test::Setup m_setup = test::SetupBuilder().withRoutes({ "0.0.0.0/0" }).build().front();
        std::unique_ptr<test::MemServer> m_server;
        test::Logger m_log { "client" };
        test::StatusChecker m_status;
        test::TunOpts m_opts;
        libxtun_tunnel m_tunnel {};
        libxtun_proxy m_proxy {};

        fs::path m_directory;
        fs::path m_exclude;
        fs::path m_include;
    };
}

TEST_P(SplitTraffic, BothAppsGoDirectlyBeforeAttach)
{
    // Without a proxy there are no VPN routes yet, and the driver does not exclude anything.
    ASSERT_NO_FATAL_FAILURE(createTunnel());
    EXPECT_EQ(connectFrom(m_exclude), ProbeResult::Uplink);
    EXPECT_EQ(connectFrom(m_include), ProbeResult::Uplink);
}

TEST_P(SplitTraffic, ExcludedAppGoesAroundTheTunnel)
{
    ASSERT_NO_FATAL_FAILURE(createTunnel());
    ASSERT_NO_FATAL_FAILURE(attachProxy());
    EXPECT_EQ(connectFrom(m_exclude), ProbeResult::Uplink);
    EXPECT_EQ(connectFrom(m_include), ProbeResult::Tunnel);
}

TEST_P(SplitTraffic, ChildOfExcludedAppIsExcluded)
{
    ASSERT_NO_FATAL_FAILURE(createTunnel());
    ASSERT_NO_FATAL_FAILURE(attachProxy());

    // The excluded app starts the included app as its child. The driver excludes children of excluded apps.
    std::vector<std::wstring> args = tcpArgs();
    args.insert(args.begin(), { L"spawn", m_include.native() });
    EXPECT_EQ(ProbeProcess(m_exclude, args).finish(), ProbeResult::Uplink);
}

TEST_P(SplitTraffic, AppStartedBeforeAttachIsExcluded)
{
    // The app starts before attach and connects only after the test signals this event.
    const std::wstring eventName = L"Local\\xtun-split-probe-" + std::to_wstring(libxtun::rand::next32());
    const std::unique_ptr<void, decltype(&::CloseHandle)> event(::CreateEventW(nullptr, TRUE, FALSE, eventName.c_str()),
                                                                &::CloseHandle);
    ASSERT_TRUE(event) << ::GetLastError();
    std::vector<std::wstring> args = tcpArgs();
    args.insert(args.end(), { L"--wait", eventName });
    ProbeProcess app(m_exclude, args);

    ASSERT_NO_FATAL_FAILURE(createTunnel());
    ASSERT_NO_FATAL_FAILURE(attachProxy());
    ASSERT_TRUE(::SetEvent(event.get())) << ::GetLastError();
    EXPECT_EQ(app.finish(), ProbeResult::Uplink);
}

TEST_P(SplitTraffic, DetachRemovesTheExclusions)
{
    ASSERT_NO_FATAL_FAILURE(createTunnel());
    ASSERT_NO_FATAL_FAILURE(attachProxy());
    detachProxy();

    // Without exclusions both apps behave the same: HARD keeps blocking them, other modes let them go directly.
    const ProbeResult wanted = persistent(GetParam()) ? ProbeResult::Blocked : ProbeResult::Uplink;
    EXPECT_EQ(connectFrom(m_exclude), wanted);
    EXPECT_EQ(connectFrom(m_include), wanted);
}

TEST_P(SplitTraffic, ReattachRestoresTheExclusions)
{
    // Like a reconnect: detach resets the driver, and the next attach must set the exclusions again.
    ASSERT_NO_FATAL_FAILURE(createTunnel());
    ASSERT_NO_FATAL_FAILURE(attachProxy());
    detachProxy();
    ASSERT_NO_FATAL_FAILURE(attachProxy());
    EXPECT_EQ(connectFrom(m_exclude), ProbeResult::Uplink);
    EXPECT_EQ(connectFrom(m_include), ProbeResult::Tunnel);
}

TEST_P(SplitTraffic, FreeReleasesTheDriver)
{
    ASSERT_NO_FATAL_FAILURE(createTunnel());
    ASSERT_NO_FATAL_FAILURE(attachProxy());
    detachProxy();
    libxtun_tunnel_free(&m_tunnel);

    // HARD keeps blocking after the tunnel is gone, other modes let both apps go directly.
    const ProbeResult wanted = persistent(GetParam()) ? ProbeResult::Blocked : ProbeResult::Uplink;
    EXPECT_EQ(connectFrom(m_exclude), wanted);
    EXPECT_EQ(connectFrom(m_include), wanted);

    // The driver is free again: a new tunnel with exclusions can take it.
    EXPECT_EQ(libxtun_tunnel_new(&m_tunnel, &m_opts.get()), LIBXTUN_OK);
}

INSTANTIATE_TEST_SUITE_P(SplitTraffic, SplitTraffic, testing::ValuesIn(libxtun::test::allKillswitchModes()),
                         [](const auto &info) { return modeName(info.param); });
