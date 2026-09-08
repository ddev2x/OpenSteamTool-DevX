#include <windows.h>

#include <cctype>
#include <cstdint>
#include <sstream>
#include <memory>
#include <stdexcept>
#include "extract_tickets.h"
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "steam.h"

namespace {

// Only a trivial pointer is thread-local. The stream is owned by each call.
thread_local std::ostringstream* errorStream = nullptr;
#define errors (*errorStream)
thread_local const char* lastStage = "Idle";
SRWLOCK extractionMutex = SRWLOCK_INIT;
struct ExtractionLock {
    ExtractionLock() { AcquireSRWLockExclusive(&extractionMutex); }
    ~ExtractionLock() { ReleaseSRWLockExclusive(&extractionMutex); }
};
struct ErrorScope {
    std::ostringstream stream;
    ErrorScope() { errorStream = &stream; }
    ~ErrorScope() { errorStream = nullptr; }
};
std::optional<std::string> QueryRegistryString(HKEY root, const char* subKey, const char* valueName) {
    HKEY key{nullptr};
    if (RegOpenKeyExA(root, subKey, 0, KEY_READ | KEY_WOW64_32KEY, &key) != ERROR_SUCCESS) {
        return std::nullopt;
    }

    DWORD valueType{0};
    DWORD valueSize{0};
    LSTATUS status{RegQueryValueExA(key, valueName, nullptr, &valueType, nullptr, &valueSize)};
    if (status != ERROR_SUCCESS || valueType != REG_SZ || valueSize == 0) {
        RegCloseKey(key);
        return std::nullopt;
    }

    std::string value(valueSize, '\0');
    status = RegQueryValueExA(
        key,
        valueName,
        nullptr,
        nullptr,
        reinterpret_cast<LPBYTE>(value.data()),
        &valueSize);
    RegCloseKey(key);

    if (status != ERROR_SUCCESS) return std::nullopt;
    if (!value.empty() && value.back() == '\0') value.pop_back();
    return value;
}

std::optional<std::string> FindSteamInstallPath() {
    constexpr const char* kSteamKey{"Software\\Valve\\Steam"};

    if (auto path{QueryRegistryString(HKEY_CURRENT_USER, kSteamKey, "SteamPath")}) {

        return path;
    }

    return std::nullopt;
}

std::string JoinPath(std::string base, const char* name) {
    for (char& ch : base) {
        if (ch == '/') ch = '\\';
    }
    if (!base.empty() && base.back() != '\\') base += '\\';
    base += name;
    return base;
}

std::string NormalizeDir(std::string dir) {
    for (char& ch : dir) {
        if (ch == '/') ch = '\\';
    }
    if (!dir.empty() && dir.back() == '\\') dir.pop_back();
    return dir;
}

HMODULE LoadSteamClient64(std::string& loadedPath) {
    auto steamPath{FindSteamInstallPath()};
    if (!steamPath) {
        errors << "Failed to find Steam install path in registry.\n";
        return nullptr;
    }

    const std::string steamDir{NormalizeDir(*steamPath)};
    loadedPath = JoinPath(*steamPath, "steamclient64.dll");

    // steamclient64.dll pulls in tier0_s64.dll / vstdlib_s64.dll from the Steam
    // directory. Add that directory to the search path and load with
    // LOAD_WITH_ALTERED_SEARCH_PATH so those dependencies resolve; otherwise the
    // load fails with ERROR_MOD_NOT_FOUND (126).

    lastStage = "LoadLibraryExA(steamclient64.dll)";
    HMODULE module{LoadLibraryExA(loadedPath.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH)};
    if (!module) {
        errors << "Failed to load " << loadedPath << " (GetLastError=" << GetLastError() << ").\n";
        return nullptr;
    }

    return module;
}

ISteamClient* CreateSteamClient(HMODULE module) {
    auto createInterface{reinterpret_cast<CreateInterfaceFn>(GetProcAddress(module, "CreateInterface"))};
    if (!createInterface) {
        errors << "steamclient64.dll has no CreateInterface export.\n";
        return nullptr;
    }

    lastStage = "CreateInterface(SteamClient023)";
    int returnCode{0};
    auto* client{reinterpret_cast<ISteamClient*>(createInterface(kSteamClientInterfaceVersion, &returnCode))};
    if (!client) {
        errors << "CreateInterface(" << kSteamClientInterfaceVersion
                  << ") failed (returnCode=" << returnCode << ").\n";
        return nullptr;
    }
    return client;
}

// Open a pipe and attach to the already-running global user
bool OpenSession(ISteamClient* client, HSteamPipe& pipe, HSteamUser& user) {
    lastStage = "CreateSteamPipe";
    pipe = client->CreateSteamPipe();
    if (!pipe) {
        errors << "CreateSteamPipe failed. Is Steam running?\n";
        return false;
    }

    lastStage = "ConnectToGlobalUser";
    user = client->ConnectToGlobalUser(pipe);
    if (!user) {
        errors << "ConnectToGlobalUser failed. Is a user logged in?\n";
        client->BReleaseSteamPipe(pipe);
        pipe = 0;
        return false;
    }

    return true;
}

// App ownership ticket: ISteamAppTicket hands back the raw signed buffer plus
// offsets into it. nAppID is explicit, so this works for any owned app.
std::optional<std::vector<uint8_t>> ExtractAppOwnershipTicket(
    ISteamClient* client, HSteamPipe pipe, HSteamUser user, uint32_t appId) {
    lastStage = "GetISteamGenericInterface(AppTicket)";
    auto* appTicket{reinterpret_cast<ISteamAppTicket*>(
        client->GetISteamGenericInterface(user, pipe, kSteamAppTicketInterfaceVersion))};
    if (!appTicket) {
        errors << "GetISteamGenericInterface(" << kSteamAppTicketInterfaceVersion
                  << ") returned null.\n";
        return std::nullopt;
    }

    std::vector<uint8_t> buffer(2048);
    uint32_t appIdOffset{0};
    uint32_t steamIdOffset{0};
    uint32_t signatureOffset{0};
    uint32_t signatureSize{0};
    lastStage = "GetAppOwnershipTicketData";
    const uint32_t written{appTicket->GetAppOwnershipTicketData(
        appId,
        buffer.data(),
        static_cast<uint32_t>(buffer.size()),
        &appIdOffset,
        &steamIdOffset,
        &signatureOffset,
        &signatureSize)};

    if (written == 0 || written > buffer.size()) {
        errors << "GetAppOwnershipTicketData returned no ticket for AppID " << appId
                  << " (own the app and have it cached locally?).\n";
        return std::nullopt;
    }

    buffer.resize(written);

    return buffer;
}

// Encrypted app ticket: asynchronous request whose result arrives as
// EncryptedAppTicketResponse_t. We have no callback dispatcher, so we poll
// ISteamUtils::IsAPICallCompleted and then read the result + ticket.
// See https://partner.steamgames.com/doc/api/ISteamUser#RequestEncryptedAppTicket
std::optional<std::vector<uint8_t>> ExtractEncryptedAppTicket(
    ISteamClient* client, HSteamPipe pipe, HSteamUser user, uint32_t appId) {
    lastStage = "GetISteamUtils(encrypted)";
    auto* utils{client->GetISteamUtils(pipe, kSteamUtilsInterfaceVersion)};
    lastStage = "GetISteamUser";
    auto* steamUser{client->GetISteamUser(user, pipe, kSteamUserInterfaceVersion)};
    if (!utils || !steamUser) {
        errors << "GetISteamUtils/GetISteamUser returned null.\n";
        return std::nullopt;
    }

    lastStage = "BLoggedOn";
    if (!steamUser->BLoggedOn()) {
        errors << "Steam user is not logged on.";
        return std::nullopt;
    }
    lastStage = "RequestEncryptedAppTicket";
    const SteamAPICall_t hCall{steamUser->RequestEncryptedAppTicket(nullptr, 0)};
    if (!hCall) {
        errors << "RequestEncryptedAppTicket failed to start for AppID " << appId << ".\n";
        return std::nullopt;
    }

    // Bounded poll so a wedged client can never hang the tool.
    constexpr int kMaxWaitMs{15000};
    constexpr int kStepMs{50};
    bool failed{false};
    int waited{0};
    lastStage = "IsAPICallCompleted";
    while (!utils->IsAPICallCompleted(hCall, &failed)) {
        if (waited >= kMaxWaitMs) {
            errors << "Timed out waiting for EncryptedAppTicketResponse_t.\n";
            return std::nullopt;
        }
        Sleep(kStepMs);
        waited += kStepMs;
    }

    EncryptedAppTicketResponse_t response{};
    lastStage = "GetAPICallResult";
    const bool gotResult{utils->GetAPICallResult(
        hCall,
        &response,
        sizeof(response),
        EncryptedAppTicketResponse_t::k_iCallback,
        &failed)};
    if (!gotResult || failed) {
        errors << "GetAPICallResult failed for EncryptedAppTicketResponse_t.\n";
        return std::nullopt;
    }
    if (response.m_eResult != k_EResultOK) {
        errors << "RequestEncryptedAppTicket returned EResult "
                  << static_cast<int>(response.m_eResult) << ".\n";
        return std::nullopt;
    }

    // The API requires a real destination; NULL is not a supported size query.
    uint32_t cbTicket{0};
    std::vector<uint8_t> buffer(65536);
    lastStage = "GetEncryptedAppTicket";
    if (!steamUser->GetEncryptedAppTicket(buffer.data(), static_cast<int>(buffer.size()), &cbTicket)) {
        errors << "GetEncryptedAppTicket failed.\n";
        return std::nullopt;
    }

    if (cbTicket == 0 || cbTicket > buffer.size()) { errors << "Invalid ticket length."; return std::nullopt; }
    buffer.resize(cbTicket);

    return buffer;
}


struct Storage { TicketsResult result{}; std::string app, encrypted, error; };
std::string Hex(const std::optional<std::vector<uint8_t>>& bytes) {
    std::string out;
    if (bytes) for (auto b : *bytes) {
        out += "0123456789abcdef"[b >> 4]; out += "0123456789abcdef"[b & 15];
    }
    return out;
}
struct Session {
    HMODULE module{}; ISteamClient* client{}; HSteamPipe pipe{}; HSteamUser user{};
    ~Session() {
        if (client && user) { lastStage = "ReleaseUser"; client->ReleaseUser(pipe, user); }
        if (client && pipe) { lastStage = "BReleaseSteamPipe"; client->BReleaseSteamPipe(pipe); }
        if (module) { lastStage = "FreeLibrary(steamclient64.dll)"; FreeLibrary(module); }
    }
};
struct Environment {
    const char* name; std::optional<std::string> old;
    explicit Environment(const char* key) : name(key) {
        DWORD n = GetEnvironmentVariableA(name, nullptr, 0);
        if (n) {
            std::string value(n, '\0');
            GetEnvironmentVariableA(name, value.data(), n);
            value.resize(n - 1); old = std::move(value);
        }
    }
    ~Environment() { SetEnvironmentVariableA(name, old ? old->c_str() : nullptr); }
};
}
extern "C" TICKETS_API TicketsResult* __cdecl ExtractTickets(uint32_t appid) noexcept {
    lastStage = "Entry";
    std::unique_ptr<Storage> data;
    try {
        lastStage = "AllocateResult";
        data = std::make_unique<Storage>();
        data->result.appid = appid; data->result.status = 2;
        lastStage = "AcquireLock";
        ExtractionLock lock;
        lastStage = "InitializeErrorStream";
        ErrorScope errorScope;
        if (!appid) throw std::runtime_error("Invalid AppID.");
        lastStage = "ReadEnvironment";
        Environment appEnv("SteamAppId"), gameEnv("SteamGameId");
        auto id = std::to_string(appid);
        lastStage = "SetEnvironment";
        if (!SetEnvironmentVariableA("SteamAppId", id.c_str()) ||
            !SetEnvironmentVariableA("SteamGameId", id.c_str()))
            throw std::runtime_error("Cannot set Steam context.");
        Session session; std::string path;
        lastStage = "FindSteamInstallPath";
        session.module = LoadSteamClient64(path);
        if (!session.module) throw std::runtime_error(errors.str());
        session.client = CreateSteamClient(session.module);
        if (!session.client || !OpenSession(session.client, session.pipe, session.user))
            throw std::runtime_error(errors.str());
        lastStage = "GetISteamUtils(context)";
        auto* utils = session.client->GetISteamUtils(session.pipe, kSteamUtilsInterfaceVersion);
        lastStage = "GetAppID";
        if (!utils || utils->GetAppID() != appid)
            throw std::runtime_error("AppID context mismatch; use a fresh process for this AppID.");
        data->app = Hex(ExtractAppOwnershipTicket(session.client, session.pipe, session.user, appid));
        data->encrypted = Hex(ExtractEncryptedAppTicket(session.client, session.pipe, session.user, appid));
        data->error = errors.str();
        data->result.status = !data->app.empty() && !data->encrypted.empty() ? 0 :
            (!data->app.empty() || !data->encrypted.empty() ? 1 : 2);
    } catch (const std::exception& e) {
        if (!data) return nullptr;
        try { data->error = e.what(); } catch (...) { return nullptr; }
    } catch (...) { return nullptr; }
    data->result.appticket = data->app.empty() ? nullptr : data->app.c_str();
    data->result.eticket = data->encrypted.empty() ? nullptr : data->encrypted.c_str();
    data->result.error = data->error.c_str(); data->result.internal = data.get();
    lastStage = "Completed";
    auto* result = &data->result; data.release(); return result;
}
extern "C" TICKETS_API const char* __cdecl GetTicketsLastStage() noexcept {
    return lastStage;
}
extern "C" TICKETS_API void __cdecl FreeTickets(TicketsResult* result) noexcept {
    if (result) delete static_cast<Storage*>(result->internal);
}
