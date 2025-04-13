#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"
#include "simple_crypto.h"

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT 0xDEADBEEF

static timestamp_t last_timestamp = 0;

// Placeholder decryption key.
// In practice, the key should be securely derived (e.g. from a secrets file) 
// in the same way as encoder.py computes it.
static const uint8_t decryption_key[KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
};

// Assume that frame_packet_t is defined similarly to how encoder.py packs its header;
// for example:
typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t data[];  // Encrypted payload follows
} frame_packet_t;

int is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel &&
            decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    // Check that the timestamp of the new frame is in order.
    if (new_frame->timestamp <= last_timestamp) {
        return -1;
    }
    last_timestamp = new_frame->timestamp;

    if (is_subscribed(new_frame->channel)) {
        // Calculate the length of the encrypted payload.
        // This assumes that pkt_len includes the header and the encrypted data,
        // and that the payload length is a multiple of BLOCK_SIZE.
        size_t enc_data_len = pkt_len - sizeof(frame_packet_t);

        // Allocate a buffer for the decrypted data.
        uint8_t decrypted_data[enc_data_len];

        // Decrypt the encrypted payload.
        int ret = decrypt_sym(new_frame->data, enc_data_len, (uint8_t *)decryption_key, decrypted_data);
        if (ret != 0) {
            STATUS_LED_RED();
            return -1;
        }
        // Now forward the decrypted payload.
        write_packet(DECODE_MSG, decrypted_data, enc_data_len);
        return 0;
    } else {
        STATUS_LED_RED();
        return -1;
    }
}
