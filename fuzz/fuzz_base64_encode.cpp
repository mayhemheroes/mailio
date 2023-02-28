#include <mailio/message.hpp>
#include <mailio/base64.hpp>
#include <string>

extern "C" {
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string msg_str((const char *) data, size);

    mailio::base64 b64;

    try {
        b64.encode(msg_str);
    } catch (mailio::codec_error) {

    }

    return 0;
}