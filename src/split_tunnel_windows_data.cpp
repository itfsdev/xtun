#include "split_tunnel_windows_data.h"

#include <tlhelp32.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <utility>

namespace libxtun::split
{
    namespace
    {
        // Local safety limits for one driver input buffer: header, entries and
        // all path strings.
        constexpr size_t MAX_DRIVER_BUFFER_BYTES = 16 * 1024 * 1024;
        constexpr size_t MAX_ENTRIES = 65536;
        // The driver stores each UTF-16 path's byte length in a USHORT.
        constexpr size_t MAX_PATH_CHARS = std::numeric_limits<USHORT>::max() / sizeof(wchar_t);

        struct HandleCloser
        {
            void operator()(HANDLE handle) const noexcept
            {
                if (handle != INVALID_HANDLE_VALUE) {
                    ::CloseHandle(handle);
                }
            }
        };
        using Handle = std::unique_ptr<void, HandleCloser>;

        bool addPathSize(std::wstring_view imagePath, size_t &bufferBytes)
        {
            if (imagePath.size() > MAX_PATH_CHARS || imagePath.find(L'\0') != std::wstring_view::npos) {
                return false;
            }
            if (bufferBytes > MAX_DRIVER_BUFFER_BYTES) {
                return false;
            }
            const size_t pathBytes = imagePath.size() * sizeof(wchar_t);
            if (pathBytes > MAX_DRIVER_BUFFER_BYTES - bufferBytes) {
                return false;
            }
            bufferBytes += pathBytes;
            return true;
        }

        std::uint64_t fileTime(const FILETIME &time)
        {
            return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
        }

        int comparePaths(const std::wstring &left, const std::wstring &right)
        {
            return ::CompareStringOrdinal(left.data(), static_cast<int>(left.size()), right.data(),
                                          static_cast<int>(right.size()), TRUE);
        }
    }

    ResultXtun<std::wstring> utf16(std::string_view text)
    {
        if (text.empty() || text.size() > MAX_PATH_CHARS * 4 || text.find('\0') != std::string_view::npos) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        // Required UTF-16 buffer size. No terminating NULL: the input length is explicit.
        const int requiredChars = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                                        static_cast<int>(text.size()), nullptr, 0);
        if (requiredChars <= 0 || static_cast<size_t>(requiredChars) > MAX_PATH_CHARS) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        std::wstring result(requiredChars, L'\0');
        if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                                  result.data(), requiredChars)
            != requiredChars) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        return result;
    }

    ResultXtun<std::wstring> executablePath(std::string_view text)
    {
        // Public API paths are UTF-8. Win32 API *W functions and the driver use UTF-16.
        auto decoded = utf16(text);
        if (!decoded) {
            return fail(decoded.error());
        }
        auto path = std::move(decoded).value();
        // Remove "." and resolve ".." directories.
        // Example: "C:\Apps\.\old\..\app.exe" becomes "C:\Apps\app.exe".
        // Do this before adding \\?\, which disables normal Windows path cleanup.
        path = std::filesystem::path(path).lexically_normal().native();

        // Require an absolute path such as C:\Apps\app.exe.
        // Reject network paths such as \\server\share\app.exe and device paths.
        if (path.size() < 3) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        const bool hasDriveLetter = (path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z');
        if (!hasDriveLetter || path[1] != L':' || path[2] != L'\\') {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }

        // Rules name individual files: reject alternate data streams, wildcard
        // patterns and quoted paths.
        if (path.find(L':', 2) != std::wstring::npos || path.find_first_of(L"*?\"") != std::wstring::npos) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        // Only EXE paths are accepted; the extension comparison ignores case.
        const bool hasExeExtension = (path.size() >= 7)
                && ::CompareStringOrdinal(path.data() + path.size() - 4, 4, L".exe", 4, TRUE) == CSTR_EQUAL;
        if (!hasExeExtension) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        const UINT drive = ::GetDriveTypeW(path.substr(0, 3).c_str());
        if (drive == DRIVE_REMOTE || drive == DRIVE_UNKNOWN || drive == DRIVE_NO_ROOT_DIR) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }

        const std::wstring fullPath = L"\\\\?\\" + path;
        Handle file { ::CreateFileW(fullPath.c_str(), FILE_READ_ATTRIBUTES,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr) };
        if (file.get() == INVALID_HANDLE_VALUE) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        BY_HANDLE_FILE_INFORMATION info {};
        if (!::GetFileInformationByHandle(file.get(), &info)) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }
        if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || ::GetFileType(file.get()) != FILE_TYPE_DISK) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        // Network shares have no volume GUID, including targets reached through
        // a junction on a local drive. Require a local mounted volume.
        if (::GetFinalPathNameByHandleW(file.get(), nullptr, 0, VOLUME_NAME_GUID) == 0) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }

        // returns the required buffer size, in TCHARs, incuding the terminating null character
        const DWORD nativeSize = ::GetFinalPathNameByHandleW(file.get(), nullptr, 0, VOLUME_NAME_NT);
        if (nativeSize == 0 || nativeSize > (MAX_PATH_CHARS + 1)) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        std::wstring nativePath(nativeSize, L'\0');
        const DWORD written = ::GetFinalPathNameByHandleW(file.get(), nativePath.data(), nativeSize, VOLUME_NAME_NT);
        if (written == 0 || written >= nativeSize) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }
        nativePath.resize(written);
        return nativePath;
    }

    ResultXtun<std::vector<std::wstring>> executablePaths(const char *const *paths)
    {
        std::vector<std::wstring> result;
        if (paths == nullptr) {
            return result;
        }
        for (size_t i = 0; paths[i] != nullptr; ++i) {
            if (i == MAX_ENTRIES) {
                return fail(LIBXTUN_ERR_INVALID_ARGS);
            }
            auto path = executablePath(paths[i]);
            if (!path) {
                return fail(path.error());
            }
            result.push_back(std::move(path).value());
        }
        // Sort in ascending ordinal order, ignoring case, to group equal paths.
        std::sort(result.begin(), result.end(),
                  [](const auto &left, const auto &right) { return comparePaths(left, right) == CSTR_LESS_THAN; });
        // Remove duplicate paths; comparisons also ignore case here.
        result.erase(
                std::unique(result.begin(), result.end(),
                            [](const auto &left, const auto &right) { return comparePaths(left, right) == CSTR_EQUAL; }),
                result.end());
        return result;
    }

    ResultXtun<std::vector<std::byte>> packApps(std::span<const std::wstring> paths)
    {
        // Buffer layout:
        // [Header: count, bytes][AppEntry 0]...[AppEntry N-1][path 0][path 1]...
        //
        // stringsAt = sizeof(Header) + N * sizeof(AppEntry).
        // Each entry stores an offset in bytes from stringsAt and a path length
        // in bytes. Paths have no NULL terminators.
        if (paths.empty() || paths.size() > MAX_ENTRIES) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        const size_t stringsAt = sizeof(Header) + paths.size() * sizeof(AppEntry);
        size_t bytes = stringsAt;

        for (const auto &path : paths) {
            if (path.empty() || !addPathSize(path, bytes)) {
                return fail(LIBXTUN_ERR_INVALID_ARGS);
            }
        }

        std::vector<std::byte> buffer(bytes);
        const Header header { paths.size(), bytes };
        std::memcpy(buffer.data(), &header, sizeof(header));
        size_t offset = 0;

        for (size_t i = 0; i < paths.size(); ++i) {
            AppEntry entry {};
            entry.offset = offset;
            entry.bytes = static_cast<USHORT>(paths[i].size() * sizeof(wchar_t));

            std::memcpy(buffer.data() + sizeof(Header) + i * sizeof(AppEntry), &entry, sizeof(entry));
            std::memcpy(buffer.data() + stringsAt + offset, paths[i].data(), entry.bytes);
            offset += entry.bytes;
        }
        return buffer;
    }

    ResultXtun<std::vector<std::byte>> packProcesses(std::span<const Process> processes)
    {
        if (processes.empty() || processes.size() > MAX_ENTRIES) {
            return fail(LIBXTUN_ERR_INVALID_ARGS);
        }
        const size_t stringsAt = sizeof(Header) + processes.size() * sizeof(ProcessEntry);
        size_t bytes = stringsAt;
        std::map<DWORD, const Process *> byPid;

        for (const auto &process : processes) {
            if (process.pid == 0) {
                return fail(LIBXTUN_ERR_INVALID_ARGS);
            }
            if (!byPid.emplace(process.pid, &process).second) {
                return fail(LIBXTUN_ERR_INVALID_ARGS);
            }
            if (!addPathSize(process.imagePath, bytes)) {
                return fail(LIBXTUN_ERR_INVALID_ARGS);
            }
        }
        // Driver 1.2.5.0 rejects a buffer ending immediately after its entries.
        // If all paths are empty, append one unused zero WCHAR (2 bytes) to the buffer.
        // The path lengths in the entries remain zero.
        if (bytes == stringsAt) {
            bytes += sizeof(wchar_t);
        }

        std::vector<std::byte> buffer(bytes);
        const Header header { processes.size(), bytes };
        std::memcpy(buffer.data(), &header, sizeof(header));
        size_t offset = 0;

        for (size_t i = 0; i < processes.size(); ++i) {
            const auto &process = processes[i];
            ProcessEntry entry {};
            entry.pid = ULongToHandle(process.pid);

            // A parent must be present and older than its child. Otherwise,
            // leave parentPid zero. This also removes self-links and cycles.
            const auto parent = byPid.find(process.parentPid);
            if (parent != byPid.end()) {
                const Process &parentProcess = *parent->second;
                const bool creationTimesKnown = process.created != 0 && parentProcess.created != 0;
                if (creationTimesKnown && parentProcess.created < process.created) {
                    entry.parentPid = ULongToHandle(process.parentPid);
                }
            }

            // Append the EXE path to the shared string area. The entry stores
            // its byte offset and length; then copy the entry to the entry table.
            entry.bytes = static_cast<USHORT>(process.imagePath.size() * sizeof(wchar_t));
            if (!process.imagePath.empty()) {
                entry.offset = offset;
                std::memcpy(buffer.data() + stringsAt + offset, process.imagePath.data(), entry.bytes);
                offset += entry.bytes;
            }
            std::memcpy(buffer.data() + sizeof(Header) + i * sizeof(ProcessEntry), &entry, sizeof(entry));
        }
        return buffer;
    }

    ResultXtun<std::vector<Process>> snapshotProcesses()
    {
        FILETIME started {};
        ::GetSystemTimePreciseAsFileTime(&started);

        Handle snapshot { ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if (snapshot.get() == INVALID_HANDLE_VALUE) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        PROCESSENTRY32W entry {};
        entry.dwSize = sizeof(entry);
        if (!::Process32FirstW(snapshot.get(), &entry)) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        std::vector<Process> processes;
        std::wstring imagePathBuffer(MAX_PATH_CHARS + 1, L'\0');

        do {
            if (entry.th32ProcessID == 0) {
                continue;
            }
            if (processes.size() == MAX_ENTRIES) {
                return fail(LIBXTUN_ERR_SYSTEM);
            }
            Process process { entry.th32ProcessID, entry.th32ParentProcessID };
            Handle handle { ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.pid) };
            if (handle) {
                FILETIME created {}, exited {}, kernel {}, user {};

                if (::GetProcessTimes(handle.get(), &created, &exited, &kernel, &user)) {
                    process.created = fileTime(created);
                }
                // A process may exit after the snapshot contains its PID. Windows
                // can reuse that PID, so OpenProcess() may open a new process.
                // If it was created after we started reading the process list, discard
                // its old parent PID and leave its path and creation time unknown.
                // This prevents trusting a parent relationship from the old process.
                if (process.created > fileTime(started)) {
                    process.created = 0;
                    process.parentPid = 0;
                } else {
                    DWORD count = static_cast<DWORD>(imagePathBuffer.size());
                    if (::QueryFullProcessImageNameW(handle.get(), PROCESS_NAME_NATIVE, imagePathBuffer.data(), &count)) {
                        process.imagePath.assign(imagePathBuffer.data(), count);
                    }
                }
            }
            processes.push_back(std::move(process));
        } while (::Process32NextW(snapshot.get(), &entry));

        if (::GetLastError() != ERROR_NO_MORE_FILES || processes.empty()) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }
        return processes;
    }
}
