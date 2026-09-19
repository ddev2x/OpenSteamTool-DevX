#include "ManifestClient.h"
#include "OSTPlatform/include/Http.h"
#include "Utils/Config/Config.h"
#include "Utils/Config/LuaConfig.h"
#include "Utils/Logging/Log.h"

// 修复 Windows 头文件冲突
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <mutex>
#include <string_view>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

// 链接 BCrypt 库 (MSVC 适用)
#pragma comment(lib, "bcrypt.lib")

namespace ManifestClient {

    // ── parsers ────────────────────────────────────────────────────
    using Parser = bool (*)(std::string_view body, uint64_t* out);

    static bool ParsePlainUint(std::string_view body, uint64_t* out) {
        uint64_t code = 0;
        auto [_, ec] = std::from_chars(body.data(), body.data() + body.size(), code);
        if (ec != std::errc{}) return false;
        *out = code;
        return true;
    }

    static bool ParseSteamRunJson(std::string_view body, uint64_t* out) {
        size_t key = body.find("\"content\"");
        if (key == std::string_view::npos) return false;
        size_t q1 = body.find('"', key + 9);
        if (q1 == std::string_view::npos) return false;
        size_t q2 = body.find('"', q1 + 1);
        if (q2 == std::string_view::npos) return false;
        return ParsePlainUint(body.substr(q1 + 1, q2 - q1 - 1), out);
    }

    // ── provider table ────────────────────────────────────────────
    //
    // Adding a new provider: add one row to kProviders below.
    // URL 使用 depotid/manifestid 两个参数，与 Python 的 caigamer 路由一致。

    struct Provider {
        std::string_view name;          // matches [manifest] url = "..."
        const char*      urlTemplate;   // full literal with depotid/manifestid placeholders
        Parser           parse;
    };

    consteval Provider Make(std::string_view name, const char* url, Parser parse) {
        return {name, url, parse};
    }

    static constexpr Provider kProviders[] = {
        Make("cgamer",        "https://www.niuplayer.xyz/api/manifest/%llu/%llu",    ParsePlainUint),
        // Make("cgamer",           "https://manifest.manifestdex.com/%llu",    ParsePlainUint),
        // Make("wudrm",         "http://gmrc.wudrm.com/manifest/%llu",           ParsePlainUint),
        // Make("opensteamtool", "https://manifest.opensteamtool.com/%llu",       ParsePlainUint),
        // Make("steamrun",      "https://manifest.steam.run/api/manifest/%llu",  ParseSteamRunJson),
    };

    static const Provider* g_active = &kProviders[0];   // cgamer
    static std::mutex      g_mutex;

    bool SetProvider(std::string_view name) {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const auto& p : kProviders)
            if (p.name == name) { 
                g_active = &p; 
                return true; 
            }
        // 兼容旧配置名称；实际请求仍统一走 niuplayer.xyz。
        if (name == "caigamer" || name == "opensteamtool" || name == "wudrm") {
            g_active = &kProviders[0];
            return true;
        }
        return false;
    }

    const char* ActiveProviderName() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_active->name.data(); 
    }

    // ── request ───────────────────────────────────────────────────

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
    }

    // ── fetch ─────────────────────────────────────────────────────
    // ---------------------------------------------------------
    // 1. Python manifest_single_encrypt 的逆运算。
    // Python 接口返回的是加密后的 64 位整数，C++ 必须先解密，
    // 才能把原始 request code 交给调用方。
// ---------------------------------------------------------
    static uint64_t ManifestEncode(uint64_t encrypted) {
        constexpr uint64_t kMask = UINT64_MAX;
        constexpr uint64_t kKey = 0x5A3C9E17ULL;
        constexpr uint64_t kMagic = 0x9E3779B97F4A7C15ULL;
        constexpr uint64_t kFinalMask = 0xDEADBEEFCAFEBABEULL;

        uint64_t value = encrypted ^ kFinalMask;
        value = (value - kMagic) & kMask;
        value = ((value >> 13) | (value << (64 - 13))) & kMask;
        return value ^ kKey;
    }

    static bool FetchActive(uint64_t gid, AppId_t depotId, uint64_t* outCode) {
        const Provider& p = *g_active;
        const Config::ManifestTimeouts timeouts = Config::GetManifestTimeouts();

        char urlLog[256];
        const int written = std::snprintf(
            urlLog,
            sizeof(urlLog),
            p.urlTemplate,
            static_cast<unsigned long long>(depotId),
            static_cast<unsigned long long>(gid));
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(urlLog)) {
            LOG_MANIFEST_WARN(
                "Manifest URL formatting failed: depot={} gid={}", depotId, gid);
            return false;
        }

        auto r = OSTPlatform::Http::Execute(
            L"GET",
            urlLog,
            nullptr,
            0,
            nullptr,
            timeouts.resolve,
            timeouts.connect,
            timeouts.send,
            timeouts.recv);

        LOG_MANIFEST_INFO(
            "Manifest {} status={} depot={} gid={}",
            p.name, r.status, depotId, gid);

        if (!r.ok || r.status != 200) return false;

        uint64_t encryptedCode = 0;
        if (!p.parse(r.body, &encryptedCode)) return false;

        *outCode = ManifestEncode(encryptedCode);
        return true;
    }

    // ── public ────────────────────────────────────────────────────

    bool FetchManifestRequestCode(uint64_t manifestGid, uint64_t* outRequestCode,
                                  AppId_t appId, AppId_t depotId)
    {
        std::lock_guard<std::mutex> lock(g_mutex);

        if (appId && depotId && LuaConfig::HasManifestCodeFuncEx()) {
            if (LuaConfig::CallManifestFetchCodeEx(appId, depotId, manifestGid, outRequestCode)) {
                LOG_MANIFEST_INFO("Manifest gid={} resolved via fetch_manifest_code_ex", manifestGid);
                return true;
            }
            LOG_MANIFEST_WARN("Manifest gid={} fetch_manifest_code_ex returned nil, trying fetch_manifest_code", manifestGid);
        }

        if (LuaConfig::HasManifestCodeFunc()) {
            if (LuaConfig::CallManifestFetchCode(manifestGid, outRequestCode)) {
                LOG_MANIFEST_INFO("Manifest gid={} resolved via manifest.lua", manifestGid);
                return true;
            }
            LOG_MANIFEST_WARN("Manifest gid={} lua returned nil, falling back to config", manifestGid);
        }

        return FetchActive(manifestGid, depotId, outRequestCode);
    }
}
