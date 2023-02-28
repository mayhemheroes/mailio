#include <mailio/message.hpp>
#include <string>

extern "C" {
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == nullptr) return 0;

    std::string msg_str((const char *) data, size);

    mailio::message msg;
    msg.line_policy(mailio::codec::line_len_policy_t::MANDATORY, mailio::codec::line_len_policy_t::MANDATORY);

    try {
        msg.parse(msg_str);
    } catch (mailio::codec_error) {

    } catch (mailio::message_error) {

    } catch (mailio::mime_error) {

    }

    return 0;
}