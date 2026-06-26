#pragma once

#include <string>

namespace OSTPlatform::Dialog {

    std::wstring Utf8ToWString(const std::string& utf8Str);
    void ShowWarning(std::string title, std::string message);

} // namespace OSTPlatform::Dialog
