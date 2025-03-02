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

int is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    if (new_frame->timestamp <= last_timestamp) {
        return -1;
    }
    last_timestamp = new_frame->timestamp;

    if (is_subscribed(new_frame->channel)) {
        write_packet(DECODE_MSG, new_frame->data, pkt_len - sizeof(frame_packet_t));
        return 0;
    } else {
        STATUS_LED_RED();
        return -1;
    }
}
