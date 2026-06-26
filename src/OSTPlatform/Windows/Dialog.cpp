#include "include/Dialog.h"

#include <windows.h>
#include <string>




namespace OSTPlatform::Dialog {

    
    std::wstring Utf8ToWString(const std::string& utf8Str) {
        if (utf8Str.empty()) return std::wstring();
        int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, utf8Str.data(), (int)utf8Str.size(), NULL, 0);
        if (sizeNeeded == 0) return std::wstring();
        std::wstring wstrTo(sizeNeeded, 0);
        MultiByteToWideChar(CP_UTF8, 0, utf8Str.data(), (int)utf8Str.size(), &wstrTo[0], sizeNeeded);
        return wstrTo;
    }

    
    void ShowWarning(std::string title, std::string message) {
        
        std::wstring wTitle = Utf8ToWString(title);
        std::wstring wMessage = Utf8ToWString(message);

        
        MessageBoxW(
            nullptr,
            wMessage.c_str(),
            wTitle.c_str(),
            MB_OK | MB_ICONWARNING | MB_TOPMOST
        );
    }

} // namespace OSTPlatform::Dialog
