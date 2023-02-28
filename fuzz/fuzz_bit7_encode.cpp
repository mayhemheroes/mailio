#include <mailio/message.hpp>
#include <mailio/bit7.hpp>
#include <string>

extern "C" {
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string msg_str((const char *) data, size);

    mailio::bit7 bit7;

    try {
        bit7.encode(msg_str);
    } catch (mailio::codec_error) {

    }

    return 0;
}