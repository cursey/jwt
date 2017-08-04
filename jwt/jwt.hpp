#pragma once

#include <string>
#include <set>

#include "json.hpp"

namespace jwt {
    // Returns an empty string on failure.
    std::string encode(const nlohmann::json& payload, const std::string& key, const std::string& alg = "");

    // Returns a null json object on failure.
    nlohmann::json decode(const std::string& jwt, const std::string& key, const std::set<std::string>& alg = {});
}
