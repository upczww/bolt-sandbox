#include "protocol/version.h"

#include <cstddef>
#include <cstdint>

static_assert(bolt::protocol::kProtocolVersion == 1);
static_assert(bolt::protocol::kPolicyEnvelopeLength == 44);
static_assert(bolt::protocol::kPolicyVersionOffset == 4);
static_assert(bolt::protocol::kPolicyHeaderLengthOffset == 6);
static_assert(bolt::protocol::kPolicyBodyLengthOffset == 8);
static_assert(bolt::protocol::kPolicyDigestOffset == 12);
static_assert(bolt::protocol::kPolicyMaximumBodyLength == 1'048'576);

int main() {
    constexpr std::uint8_t expected_magic[] = {'B', 'L', 'P', '1'};
    for (std::size_t index = 0; index < sizeof(expected_magic); ++index) {
        if (bolt::protocol::kPolicyMagic[index] != expected_magic[index]) {
            return 1;
        }
    }
    return 0;
}
