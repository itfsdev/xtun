#ifndef TEST_SPLIT_DRIVER_WINDOWS_H
#define TEST_SPLIT_DRIVER_WINDOWS_H

#include "os.h"

#include <windows.h>
#include <winsvc.h>

#include <string>

#include "gtest/gtest.h"

namespace libxtun::test
{
    constexpr const char *SPLIT_SERVICE_NAME = "XtunSplitTunnel";

    // Return why the tests cannot use the split tunnel driver here, or an empty string.
    // An unexpected error of the service manager also fails the test.
    inline std::string splitDriverSkipReason()
    {
#if defined(_M_ARM64EC) || (!defined(_M_X64) && !defined(__x86_64__))
        return "Split tunneling requires Windows x64";
#else
        if (!privileged()) {
            return "The driver requires Administrator";
        }

        // Run only where the installer registered the driver service.
        SC_HANDLE manager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (manager == nullptr) {
            ADD_FAILURE() << "OpenSCManager failed: " << ::GetLastError();
            return "No access to the service manager";
        }
        SC_HANDLE service = ::OpenServiceA(manager, SPLIT_SERVICE_NAME, SERVICE_QUERY_STATUS);
        const DWORD serviceError = ::GetLastError();
        if (service != nullptr) {
            ::CloseServiceHandle(service);
        }
        ::CloseServiceHandle(manager);
        if (service == nullptr) {
            if (serviceError != ERROR_SERVICE_DOES_NOT_EXIST) {
                ADD_FAILURE() << "OpenService failed: " << serviceError;
            }
            return std::string(SPLIT_SERVICE_NAME) + " service is not installed";
        }

        // Another xtun process may use the driver right now.
        if (HANDLE owner = ::OpenMutexW(SYNCHRONIZE, FALSE, L"Global\\XtunSplitTunnel")) {
            ::CloseHandle(owner);
            return "Another process owns the driver";
        }
        return {};
#endif
    }
}

#endif
