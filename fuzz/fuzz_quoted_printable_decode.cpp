#include <mailio/quoted_printable.hpp>
#include <string>

extern "C" {
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string msg_str((const char *) data, size);
    std::vector<std::string> strings;
    strings.push_back(msg_str);

    mailio::quoted_printable quotedPrintable;

    try {
        quotedPrintable.decode(strings);
    } catch (mailio::codec_error) {

    }

    return 0;
}