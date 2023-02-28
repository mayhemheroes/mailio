#include <mailio/quoted_printable.hpp>
#include <string>

extern "C" {
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string msg_str((const char *) data, size);

    mailio::quoted_printable quotedPrintable;

    try {
        quotedPrintable.encode(msg_str);
    } catch (mailio::codec_error) {

    }

    return 0;
}