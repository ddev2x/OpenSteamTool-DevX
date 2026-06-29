#include "include/Path.h"
#include "include/Log.h"

#include <windows.h>
#include <shlobj.h>

namespace OSTPlatform::Path {

std::optional<std::filesystem::path> GetLocalAppDataPath() {
    std::filesystem::path localAppDataPath;
    PWSTR path = nullptr;

    // Try SHGetKnownFolderPath first (Vista+, more reliable)
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path);
    if (SUCCEEDED(hr) && path != nullptr) {
        localAppDataPath = path;
        CoTaskMemFree(path);
        return localAppDataPath;
    }

    // Fallback to LOCALAPPDATA environment variable
    DWORD bufferSize = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
    if (bufferSize > 0) {
        std::wstring envPath(bufferSize, L'\0');
        GetEnvironmentVariableW(L"LOCALAPPDATA", &envPath[0], bufferSize);

        // Remove trailing null character
        size_t nullPos = envPath.find(L'\0');
        if (nullPos != std::wstring::npos) {
            envPath.resize(nullPos);
        }

        if (!envPath.empty()) {
            return std::filesystem::path(envPath);
        }
    }

    // Final fallback to USERPROFILE\AppData\Local
    bufferSize = GetEnvironmentVariableW(L"USERPROFILE", nullptr, 0);
    if (bufferSize > 0) {
        std::wstring envPath(bufferSize, L'\0');
        GetEnvironmentVariableW(L"USERPROFILE", &envPath[0], bufferSize);

        size_t nullPos = envPath.find(L'\0');
        if (nullPos != std::wstring::npos) {
            envPath.resize(nullPos);
        }

        if (!envPath.empty()) {
            return std::filesystem::path(envPath) / "AppData" / "Local";
        }
    }

    OSTP_LOG_WARN("GetLocalAppDataPath: failed to determine LocalAppData path");
    return std::nullopt;
}

std::optional<std::filesystem::path> GetOrCreateLocalAppDataSubdir(const std::filesystem::path& subdir) {
    auto localAppData = GetLocalAppDataPath();
    if (!localAppData) {
        return std::nullopt;
    }

    std::filesystem::path targetPath = *localAppData / subdir;

    std::error_code ec;
    if (!std::filesystem::exists(targetPath, ec)) {
        if (!std::filesystem::create_directories(targetPath, ec)) {
            OSTP_LOG_WARN("GetOrCreateLocalAppDataSubdir: failed to create directory '{}' ({})",
                          targetPath.string(), ec.message());
            return std::nullopt;
        }
    }

    return targetPath;
}

} // namespace OSTPlatform::Path
