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
    // host / port / tls / path are all derived from the URL template
    // by Make() at compile time.

    struct Provider {
        std::string_view name;          // matches [manifest] url = "..."
        const char*      urlTemplate;   // full literal with one %llu — for log & path
        Parser           parse;
    };

    consteval Provider Make(std::string_view name, const char* url, Parser parse) {
        return {name, url, parse};
    }

    static constexpr Provider kProviders[] = {
        // Make("cgamer",        "http://code.caigamer.cn/GetCode/%llu",    ParsePlainUint),
        Make("cgamer",           "https://manifest.manifestdex.com/%llu",    ParsePlainUint),
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
// 1. Python 方法 manifest_encode 的 C++ 翻译
// ---------------------------------------------------------
    static uint64_t ManifestEncode(uint64_t v10) {
        uint64_t a = v10 + 998;
        uint64_t b = v10 + 0x3E600000000ULL;
        return a ^ ((a ^ b) & 0xFFFFFFFF00000000ULL);
    }

    // ---------------------------------------------------------
    // 2. Python 方法 encrypt_signature 的 C++ 翻译 (Windows 原生 CNG API)
    // ---------------------------------------------------------
    static std::wstring GenerateSignature(uint64_t gid) {
        // 逆向提取的硬编码 AES-128 Key
        const unsigned char AES_KEY[16] = {
            0x2B, 0x7E, 0x55, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x55, 0x88, 0x89, 0xCF, 0x4F, 0x3C
        };

        std::string plaintext = std::to_string(gid);
        size_t pt_len = plaintext.length();

        // 1. 生成 16 字节随机 IV
        unsigned char iv[16];
        BCryptGenRandom(NULL, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        // 2. 初始化 BCrypt 加密提供者 (AES)
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        DWORD cbKeyObject = 0;
        DWORD cbData = 0;
        std::vector<BYTE> pbKeyObject;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);

        // 设置为 ECB 模式，以便我们自己构建 CTR 流
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);

        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0);
        pbKeyObject.resize(cbKeyObject);

        // 导入对称密钥
        BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject.data(), cbKeyObject, (PUCHAR)AES_KEY, sizeof(AES_KEY), 0);

        // 3. 实现 CTR 模式
        // 计算需要的 16 字节块数量
        size_t num_blocks = (pt_len + 15) / 16;
        std::vector<unsigned char> counters(num_blocks * 16);
        unsigned char current_counter[16];
        memcpy(current_counter, iv, 16);

        for (size_t i = 0; i < num_blocks; ++i) {
            memcpy(&counters[i * 16], current_counter, 16);
            // 标准 CTR: 大端序递增 Counter
            for (int j = 15; j >= 0; --j) {
                if (++current_counter[j] != 0) break;
            }
        }

        std::vector<unsigned char> encrypted_counters(num_blocks * 16);
        ULONG cbResult = 0;

        // ECB 批量加密所有的 Counter 块，生成密钥流
        BCryptEncrypt(hKey, counters.data(), (ULONG)counters.size(), NULL, NULL, 0,
            encrypted_counters.data(), (ULONG)encrypted_counters.size(), &cbResult, 0);

        // 核心 CTR 步骤：明文与生成的密钥流进行异或 (XOR)
        std::vector<unsigned char> ciphertext(pt_len);
        for (size_t i = 0; i < pt_len; ++i) {
            ciphertext[i] = plaintext[i] ^ encrypted_counters[i];
        }

        // 清理 BCrypt 资源
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        // 4. 拼接并转为 16 进制字符串
        std::wstringstream wss;
        for (int i = 0; i < 16; ++i) {
            wss << std::hex << std::setfill(L'0') << std::setw(2) << static_cast<int>(iv[i]);
        }
        for (size_t i = 0; i < pt_len; ++i) {
            wss << std::hex << std::setfill(L'0') << std::setw(2) << static_cast<int>(ciphertext[i]);
        }

        return wss.str();
    }

    // ---------------------------------------------------------
    // 3. 融合后的 FetchActive 主函数
    // ---------------------------------------------------------
    static bool FetchActive(uint64_t gid, uint64_t* outCode) {
        const Provider& p = *g_active;
        const Config::ManifestTimeouts timeouts = Config::GetManifestTimeouts();

        char urlLog[256];
        std::snprintf(urlLog, sizeof(urlLog), p.urlTemplate, gid);

        // 动态生成签名
        std::wstring signature = GenerateSignature(gid);

        // 拼接 HTTP Headers (根据 HTTP 标准，每行后要有 \r\n，末尾不能多出空行导致正文被截断)
        std::wstring headers = L"User-Agent: ManifestDeX/1.0\r\n";
            // L"Connection: Keep-Alive\r\n"
            // L"User-Agent: CaigamerQ/1.0\r\n"
            // L"Signature: " + signature + L"\r\n"
            // L"Host: code.caigamer.cn\r\n";

        // 使用拼接好的 headers 执行 HTTP 请求
        auto r = OSTPlatform::Http::Execute(
            L"GET",
            urlLog,
            nullptr,
            0,
            headers.c_str(),
            timeouts.resolve,
            timeouts.connect,
            timeouts.send,
            timeouts.recv);

        LOG_MANIFEST_INFO("Manifest {} status={} gid={}", p.name, r.status, gid);

        if (!r.ok || r.status != 200) return false;
        
        return p.parse(r.body, outCode);

        // if (!r.ok || r.status != 200) return false;
        // 解析请求结果并利用我们翻译好的 C++ 函数进行掩码处理
        // uint64_t rawCode = 0;
        // if (p.parse(r.body, &rawCode)) {
        //    *outCode = ManifestEncode(rawCode);
        //    return true;
        // }

        // return false;
    }
    /*static bool FetchActive(uint64_t gid, uint64_t* outCode) {
        const Provider& p = *g_active;
        const Config::ManifestTimeouts timeouts = Config::GetManifestTimeouts();

        char urlLog[256];
        std::snprintf(urlLog, sizeof(urlLog), p.urlTemplate, gid);

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

        LOG_MANIFEST_INFO("Manifest {} status={} gid={}", p.name, r.status, gid);

        if (!r.ok || r.status != 200) return false;
        return p.parse(r.body, outCode);
    }*/

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

        return FetchActive(manifestGid, outRequestCode);
    }
}
