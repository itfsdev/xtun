#ifndef LIBXTUN_SPLIT_TUNNEL_WINDOWS_DATA_H
#define LIBXTUN_SPLIT_TUNNEL_WINDOWS_DATA_H

#include "util/result.h"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace libxtun::split
{
    // Native ABI of win-split-tunnel 1.2.5.0, revision 198ecde.
    // offsets start after all entries, and lengths count UTF-16 bytes.
    struct Header
    {
        SIZE_T count;
        SIZE_T bytes;
    };

    struct AppEntry
    {
        SIZE_T offset;
        USHORT bytes;
    };

    struct ProcessEntry
    {
        HANDLE pid;
        HANDLE parentPid;
        SIZE_T offset;
        USHORT bytes;
    };

    static_assert(sizeof(wchar_t) == 2);
#ifdef _WIN64
    static_assert(sizeof(Header) == 16 && offsetof(Header, bytes) == 8);
    static_assert(sizeof(AppEntry) == 16 && offsetof(AppEntry, bytes) == 8);
    static_assert(sizeof(ProcessEntry) == 32 && offsetof(ProcessEntry, offset) == 16
                  && offsetof(ProcessEntry, bytes) == 24);
#endif

    struct Process
    {
        DWORD pid = 0;
        DWORD parentPid = 0;
        std::uint64_t created = 0; // FILETIME ticks: zero means unknown
        std::wstring imagePath;    // Full native EXE path in UTF-16
    };

    // Convert UTF-8 text to UTF-16. Return an error for invalid text.
    ResultXtun<std::wstring> utf16(std::string_view text);

    // Check that a UTF-8 path points to an existing local EXE file.
    // Return its full Windows system path in UTF-16.
    ResultXtun<std::wstring> executablePath(std::string_view text);

    // Check and convert a NULL-terminated list of UTF-8 EXE paths.
    // Remove duplicates ignoring case; NULL or an empty list gives an empty result.
    ResultXtun<std::vector<std::wstring>> executablePaths(const char *const *paths);

    // Pack native UTF-16 EXE paths into the byte buffer used by the driver.
    ResultXtun<std::vector<std::byte>> packApps(std::span<const std::wstring> paths);

    // Pack the system process list collected by snapshotProcesses().
    // Keep parentPid only when that parent is in the list and both creation
    // times are known, with the parent created earlier. Otherwise, store zero.
    ResultXtun<std::vector<std::byte>> packProcesses(std::span<const Process> processes);

    // Collect the system process list, skipping the Idle entry (PID 0).
    // For each PID, try to read its creation time and native EXE path using query
    // access.
    // Unavailable times stay zero. Unavailable paths stay empty.
    // Processes started after we began reading the process list have no saved
    // path or parent information here.
    // packProcesses() later checks whether each parent exists and is older.
    ResultXtun<std::vector<Process>> snapshotProcesses();
}

#endif // LIBXTUN_SPLIT_TUNNEL_WINDOWS_DATA_H
