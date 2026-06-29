#pragma once

#include <filesystem>
#include <optional>

namespace OSTPlatform::Path {

    // Get user's AppData\Local directory path.
    // Returns std::nullopt if the path cannot be determined.
    std::optional<std::filesystem::path> GetLocalAppDataPath();

    // Get or create a subdirectory under AppData\Local.
    // Creates the directory if it doesn't exist.
    // Returns std::nullopt if creation fails.
    std::optional<std::filesystem::path> GetOrCreateLocalAppDataSubdir(const std::filesystem::path& subdir);

} // namespace OSTPlatform::Path
