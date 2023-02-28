#include <mailio/bit7.hpp>
#include <string>
#include <vector>

extern "C" {
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string msg_str((const char *) data, size);
    std::vector<std::string> strings;
    strings.push_back(msg_str);

    mailio::bit7 bit7;

    try {
        bit7.decode(strings);
    } catch (mailio::codec_error) {

    }

    return 0;
}