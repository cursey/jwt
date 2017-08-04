#pragma once

#include <string>
#include <set>

#include "json.hpp"

namespace jwt {
    std::string encode(const nlohmann::json& payload, const std::string& key, const std::string& alg = "");
    nlohmann::json decode(const std::string& jwt, const std::string& key, const std::set<std::string>& alg = {});
}
