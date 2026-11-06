#include "split_tunnel_windows.h"
#include "split_tunnel_windows_data.h"
#include "util/os.h"
#include "util/random.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>

namespace
{
    using namespace libxtun;
    using namespace libxtun::split;
    namespace fs = std::filesystem;

    // Read a field from some byte storage without assuming its pointer alignment.
    template<typename T> T readAt(const std::vector<std::byte> &buffer, size_t offset)
    {
        if (offset > buffer.size() || sizeof(T) > buffer.size() - offset) {
            ADD_FAILURE() << "Field outside the serialized buffer";
            return {};
        }
        T value {};
        std::memcpy(&value, buffer.data() + offset, sizeof(value));
        return value;
    }

    std::string pathUtf8(const fs::path &path)
    {
        const auto text = path.u8string();
        return { reinterpret_cast<const char *>(text.data()), text.size() };
    }

    class SplitTunnelPaths : public testing::Test
    {
    protected:
        void SetUp() override
        {
            // Makes a new temporary directory
            // "C:\Users\<username>\AppData\Local\Temp\xtun-rd59-П浏🚀-<random number>"
            // and creates there an empty EXE file "probe.exe"
            // Directory name: xtun-rd59-П浏🚀-<random number>.
            const auto testDirectory = fs::temp_directory_path()
                    / (L"xtun-rd59-\u041f\u6d4f\U0001f680-" + std::to_wstring(libxtun::rand::next32()));
            std::error_code error;
            ASSERT_TRUE(fs::create_directory(testDirectory, error)) << error.message();

            // Store the path only after creating it, so cleanup owns this directory.
            m_directory = testDirectory;
            m_imagePath = m_directory / L"probe.exe";
            std::ofstream file(m_imagePath, std::ios::binary);
            ASSERT_TRUE(file.is_open());
        }

        void TearDown() override
        {
            if (m_directory.empty()) {
                return;
            }
            std::error_code error;
            fs::remove_all(fs::path(L"\\\\?\\" + m_directory.native()), error);
            EXPECT_FALSE(error) << error.message();
        }

        fs::path m_directory;
        fs::path m_imagePath;
    };
}

TEST(SplitTunnelOwnership, RejectsSecondOwnerAndClosesItsHandle)
{
#if defined(_M_ARM64EC) || (!defined(_M_X64) && !defined(__x86_64__))
    GTEST_SKIP() << "Split tunneling requires Windows x64";
#else
    HANDLE handle = ::CreateMutexW(nullptr, FALSE, L"Global\\XtunSplitTunnel");
    const DWORD error = ::GetLastError();
    ASSERT_NE(handle, nullptr) << error;
    std::unique_ptr<void, decltype(&::CloseHandle)> marker(handle, &::CloseHandle);
    if (error == ERROR_ALREADY_EXISTS) {
        GTEST_SKIP() << "Another process already owns the driver marker";
    }

    const auto secondOwner = libxtun::WindowsSplitTunnel::open();
    ASSERT_FALSE(secondOwner);
    EXPECT_EQ(secondOwner.error(), LIBXTUN_ERR_SPLIT_BUSY);

    // The failed open() must not keep the named object alive.
    marker.reset();
    HANDLE nextHandle = ::CreateMutexW(nullptr, FALSE, L"Global\\XtunSplitTunnel");
    const DWORD nextError = ::GetLastError();
    std::unique_ptr<void, decltype(&::CloseHandle)> nextMarker(nextHandle, &::CloseHandle);
    ASSERT_TRUE(nextMarker) << nextError;
    EXPECT_NE(nextError, ERROR_ALREADY_EXISTS);
#endif
}

TEST(SplitTunnelDriver, OpenReadsStartedState)
{
#if defined(_M_ARM64EC) || (!defined(_M_X64) && !defined(__x86_64__))
    GTEST_SKIP() << "Split tunneling requires Windows x64";
#else
    if (!test::privileged()) {
        GTEST_SKIP() << "The driver requires Administrator";
    }

    // Run only where the installer registered the driver service.
    SC_HANDLE manager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    ASSERT_NE(manager, nullptr) << ::GetLastError();
    SC_HANDLE service = ::OpenServiceW(manager, L"XtunSplitTunnel", SERVICE_QUERY_STATUS);
    const DWORD serviceError = ::GetLastError();
    if (service != nullptr) {
        ::CloseServiceHandle(service);
    }
    ::CloseServiceHandle(manager);
    if (service == nullptr && serviceError == ERROR_SERVICE_DOES_NOT_EXIST) {
        GTEST_SKIP() << "XtunSplitTunnel service is not installed";
    }
    ASSERT_NE(service, nullptr) << serviceError;

    // Another xtun process may use the driver right now.
    if (HANDLE owner = ::OpenMutexW(SYNCHRONIZE, FALSE, L"Global\\XtunSplitTunnel")) {
        ::CloseHandle(owner);
        GTEST_SKIP() << "Another process owns the driver";
    }

    const auto component = WindowsSplitTunnel::open();
    ASSERT_TRUE(component) << libxtun_strerror(component.error());
    const auto state = component.value()->state();
    ASSERT_TRUE(state) << libxtun_strerror(state.error());
    EXPECT_EQ(state.value(), WindowsSplitTunnel::State::Started);
#endif
}

TEST(SplitTunnelData, Utf8IsStrictAndPreservesUnicode)
{
    // Original path: "C:\П\浏\🚀\app.exe" (Cyrillic letter, CJK ideograph, emoji).
    const auto decoded = utf16("C:\\\xd0\x9f\\\xe6\xb5\x8f\\\xf0\x9f\x9a\x80\\app.exe");
    ASSERT_TRUE(decoded);
    EXPECT_EQ(decoded.value(), L"C:\\\u041f\\\u6d4f\\\U0001f680\\app.exe");

    for (const auto invalid : { "", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82" }) {
        const auto result = utf16(invalid);
        ASSERT_FALSE(result);
        EXPECT_EQ(result.error(), LIBXTUN_ERR_INVALID_ARGS);
    }
    // Expect a conversion error: the input contains an embedded NULL byte.
    EXPECT_FALSE(utf16(std::string("a\0b", 3)));
    // Expect a conversion error: 32768 UTF-16 code units exceed the driver path limit.
    EXPECT_FALSE(utf16(std::string(32768, 'a')));
}

TEST(SplitTunnelData, NullAndEmptyPathListsHaveNoExclusions)
{
    const char *const empty[] = { nullptr };
    const char *const *lists[] = { nullptr, empty };
    for (const auto paths : lists) {
        const auto result = executablePaths(paths);
        ASSERT_TRUE(result);
        EXPECT_TRUE(result.value().empty());
    }
}

TEST_F(SplitTunnelPaths, RejectsRelativeNetworkDeviceAndInvalidPaths)
{
    for (const auto path : { "probe.exe", "C:probe.exe", "\\probe.exe", "\\\\server\\share\\probe.exe",
                             "\\\\.\\C:\\probe.exe", "C:\\a.exe:stream", "C:\\*.exe", "C:\\app.txt" }) {
        const auto result = executablePath(path);
        ASSERT_FALSE(result) << path;
        EXPECT_EQ(result.error(), LIBXTUN_ERR_INVALID_ARGS) << path;
    }
    EXPECT_FALSE(executablePath(pathUtf8(m_directory / L"missing.exe")));
    std::error_code error;
    const auto subdirectory = m_directory / L"directory.exe";
    ASSERT_TRUE(fs::create_directory(subdirectory, error)) << error.message();
    EXPECT_FALSE(executablePath(pathUtf8(subdirectory)));
}

TEST_F(SplitTunnelPaths, CopiesUnicodePathsAndDeduplicatesAliases)
{
    std::string original = pathUtf8(m_imagePath);
    std::string alias = pathUtf8(m_directory / L"." / L"PROBE.EXE");
    std::replace(alias.begin(), alias.end(), '\\', '/');
    const char *paths[] = { original.c_str(), alias.c_str(), nullptr };
    const auto result = executablePaths(paths);
    ASSERT_TRUE(result);

    original.assign("caller storage released");
    alias.clear();
    paths[0] = nullptr;
    ASSERT_EQ(result.value().size(), 1u);

    const auto &nativePath = result.value().front();
    EXPECT_TRUE(nativePath.starts_with(L"\\Device\\"));
    EXPECT_NE(nativePath.find(L"\u041f\u6d4f\U0001f680"), std::wstring::npos);
    EXPECT_TRUE(nativePath.ends_with(L"\\probe.exe"));
}

TEST_F(SplitTunnelPaths, ResolvesPathsLongerThanMaxPath)
{
    const auto longDirectory = m_directory / std::wstring(240, L'x');
    std::error_code error;
    ASSERT_TRUE(fs::create_directory(fs::path(L"\\\\?\\" + longDirectory.native()), error)) << error.message();
    const auto longImagePath = longDirectory / L"probe.exe";
    {
        std::ofstream file(fs::path(L"\\\\?\\" + longImagePath.native()), std::ios::binary);
        ASSERT_TRUE(file.is_open());
    }
    ASSERT_GT(longImagePath.native().size(), static_cast<size_t>(MAX_PATH));
    const auto result = executablePath(pathUtf8(longImagePath));
    ASSERT_TRUE(result);
    EXPECT_TRUE(result.value().ends_with(L"\\probe.exe"));
}

TEST(SplitTunnelData, AppBufferUsesUtf16ByteLengthsAndOffsetsAfterEntries)
{
    // Original paths: "\Device\П.exe" and "\Device\🚀.exe"
    const std::wstring paths[] = { L"\\Device\\\u041f.exe", L"\\Device\\\U0001f680.exe" };
    const auto result = packApps(paths);
    ASSERT_TRUE(result);

    const auto &buffer = result.value();
    const auto header = readAt<Header>(buffer, 0);
    const size_t stringsAt = sizeof(Header) + 2 * sizeof(AppEntry);
    EXPECT_EQ(header.count, 2u);
    ASSERT_EQ(header.bytes, stringsAt + (paths[0].size() + paths[1].size()) * sizeof(wchar_t));
    ASSERT_EQ(header.bytes, buffer.size());

    const auto first = readAt<AppEntry>(buffer, sizeof(Header));
    const auto second = readAt<AppEntry>(buffer, sizeof(Header) + sizeof(AppEntry));
    ASSERT_EQ(first.offset, 0u);
    ASSERT_EQ(first.bytes, paths[0].size() * sizeof(wchar_t));
    ASSERT_EQ(second.offset, first.bytes);
    ASSERT_EQ(second.bytes, paths[1].size() * sizeof(wchar_t));
    EXPECT_EQ(std::memcmp(buffer.data() + stringsAt, paths[0].data(), first.bytes), 0);
    EXPECT_EQ(std::memcmp(buffer.data() + stringsAt + second.offset, paths[1].data(), second.bytes), 0);
}

TEST(SplitTunnelData, RejectsEmptyOversizedAndEmbeddedNullPaths)
{
    EXPECT_FALSE(packApps({}));
    EXPECT_FALSE(packProcesses({}));
    const std::wstring empty[] = { L"" };
    EXPECT_FALSE(packApps(empty));
    const std::wstring nul[] = { std::wstring(L"a\0b", 3) };
    EXPECT_FALSE(packApps(nul));

    const size_t maxChars = std::numeric_limits<USHORT>::max() / sizeof(wchar_t);
    const std::wstring largest[] = { std::wstring(maxChars, L'x') };
    EXPECT_TRUE(packApps(largest));
    const std::wstring tooLong[] = { std::wstring(maxChars + 1, L'x') };
    EXPECT_FALSE(packApps(tooLong));
    const Process longProcess[] = { { 1, 0, 100, tooLong[0] } };
    EXPECT_FALSE(packProcesses(longProcess));
    const std::vector<std::wstring> tooMany(65537, L"x");
    EXPECT_FALSE(packApps(tooMany));
    const std::vector<Process> tooManyProcesses(65537);
    EXPECT_FALSE(packProcesses(tooManyProcesses));
    const std::vector<std::wstring> tooLarge(257, largest[0]);
    EXPECT_FALSE(packApps(tooLarge));
}

TEST(SplitTunnelData, ProcessBufferRejectsDuplicateAndZeroPids)
{
    const Process duplicate[] = { { 1, 0, 100, L"a" }, { 1, 0, 200, L"b" } };
    EXPECT_FALSE(packProcesses(duplicate));
    const Process zero[] = { { 0, 0, 100, L"a" } };
    EXPECT_FALSE(packProcesses(zero));
}

TEST(SplitTunnelData, ProcessBufferClearsCyclesReusedAndUnverifiedParents)
{
    const Process processes[] = { { 1, 2, 100, L"a" },  { 2, 1, 200, L"b" }, { 3, 3, 300, L"c" },  { 4, 99, 400, L"d" },
                                  { 5, 2, 0, L"e" },    { 6, 2, 200, L"f" }, { 7, 8, 700, L"g" },  { 8, 7, 600, L"h" },
                                  { 9, 10, 900, L"i" }, { 10, 0, 0, L"j" },  { 11, 2, 1100, L"k" } };
    const ULONG_PTR expectedParents[] = { 0, 1, 0, 0, 0, 0, 8, 0, 0, 0, 2 };
    const auto result = packProcesses(processes);
    ASSERT_TRUE(result);
    const auto &buffer = result.value();
    const auto header = readAt<Header>(buffer, 0);
    const size_t count = std::size(processes);
    EXPECT_EQ(header.count, count);
    ASSERT_EQ(header.bytes, buffer.size());

    const size_t stringsAt = sizeof(Header) + count * sizeof(ProcessEntry);
    for (size_t i = 0; i < count; ++i) {
        const auto entry = readAt<ProcessEntry>(buffer, sizeof(Header) + i * sizeof(ProcessEntry));
        EXPECT_EQ(reinterpret_cast<ULONG_PTR>(entry.pid), processes[i].pid);
        EXPECT_EQ(reinterpret_cast<ULONG_PTR>(entry.parentPid), expectedParents[i]) << "entry " << i;
        ASSERT_EQ(entry.bytes, sizeof(wchar_t));
        EXPECT_EQ(readAt<wchar_t>(buffer, stringsAt + entry.offset), processes[i].imagePath[0]);
    }
    EXPECT_EQ(processes[0].parentPid, 2u);
}

TEST(SplitTunnelData, UnknownProcessPathsStillHaveAValidStringArea)
{
    const Process processes[] = { { 1, 0, 100, L"" } };
    const auto result = packProcesses(processes);
    ASSERT_TRUE(result);
    const auto &buffer = result.value();
    const auto header = readAt<Header>(buffer, 0);
    EXPECT_EQ(header.count, 1u);
    EXPECT_EQ(header.bytes, sizeof(Header) + sizeof(ProcessEntry) + sizeof(wchar_t));
    EXPECT_EQ(header.bytes, buffer.size());
    const auto entry = readAt<ProcessEntry>(buffer, sizeof(Header));
    EXPECT_EQ(entry.bytes, 0);
    EXPECT_EQ(entry.offset, 0u);
}

TEST(SplitTunnelData, SnapshotContainsCurrentProcessAndCanBePacked)
{
    const auto snapshot = snapshotProcesses();
    ASSERT_TRUE(snapshot);
    const auto &processes = snapshot.value();
    const auto current = std::find_if(processes.begin(), processes.end(),
                                      [](const auto &process) { return process.pid == ::GetCurrentProcessId(); });
    ASSERT_NE(current, processes.end());
    EXPECT_GT(current->created, 0u);
    EXPECT_FALSE(current->imagePath.empty());
    const auto buffer = packProcesses(processes);
    ASSERT_TRUE(buffer);
    EXPECT_EQ(readAt<Header>(buffer.value(), 0).count, processes.size());
}
