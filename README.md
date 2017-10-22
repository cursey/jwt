# jwt
JWT in C++

Uses [nlohmann's json library](https://github.com/nlohmann/json) and SSL (not included). 

Example usage:
```c++
#include <jwt/jwt.hpp>

using namespace std;
using json = nlohmann::json;

string key{ "my super secret key" };
json payload{
    { "user", "some_username" },
    { "isAdmin", true }
};

// Add some standard claims.
jwt::issuedBy(payload, "my company");               // ISS claim.
jwt::issuedAt(payload);                             // IAT claim. Defaults to current time.
jwt::issuedFor(payload, {"me", "you", "everyone"}); // AUD claim.

// Encode the jwt with the default algorithm (HS256).
auto encodedHS256 = jwt::encode(payload, key);

// Or specify an algorithm to use (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512).
auto encodedHS384 = jwt::encode(payload, key, "HS384");

// Decode with a specified set of acceptable algorithms.
auto decoded = jwt::decode(encodedHS256, key, { "HS256", "HS384" });

// Verify the standard claims.
jwt::AcceptedParameters params{};

params.issuers = { "my company", "your company" };
params.audience = { "me" };

auto isValid = jwt::verify(decoded, jwt::claims::ISS | jwt::claims::IAT | jwt::claims::AUD, params);
```