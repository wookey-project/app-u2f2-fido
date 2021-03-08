#include "autoconf.h"
#include "libc/types.h"
#include "libc/sys/msg.h"
#include "libc/stdio.h"
#include "libc/errno.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/syscall.h"

#include "libfido.h"

#include "handlers.h"
#include "main.h"


mbed_error_t handle_wink(uint16_t timeout_ms, int usb_msq)
{
    /* FIXME: get back EMULATION config and handle it here */
    wink_up();
    waitfor(timeout_ms);
    wink_down();

    printf("[FIDO] Send WINK acknowledge to USB\n");
    uint32_t mtype = MAGIC_ACKNOWLEDGE;
    msgsnd(usb_msq, &mtype, 0, 0);

    return MBED_ERROR_NONE;
}

uint8_t cmd_buf[1024] = { 0 };
uint8_t resp_buf[1024] = { 0 };

/*
 * handle APDU request reception from USB, execute it, and send response to USB
 *
 */
mbed_error_t handle_fido_request(int usb_msq)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    int ret;
    size_t msgsz = 64; /* max msg buf size */
    uint32_t mtype = MAGIC_ACKNOWLEDGE;
    uint32_t msg_size = 0;
    uint16_t resp_len = 1024;
    uint32_t metadata = 0;
    struct msgbuf msgbuf = { 0 };


    /* now wait for APDU_CMD_MSG_META, to calculate the number of needed msg */
    ret = msgrcv(usb_msq, &msgbuf.mtext, msgsz, MAGIC_APDU_CMD_META, 0);
    if (ret == -1) {
        log_printf("[FIDO] Unable to get back CMD_MSG_META with errno %x\n", errno);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
    metadata = msgbuf.mtext.u32[0];
    printf("[FIDO] received APDU_CMD_META from USB: %x\n", metadata);

    /* now wait for APDU_CMD_MSG_LEN, to calculate the number of needed msg */
    ret = msgrcv(usb_msq, &msgbuf.mtext, msgsz, MAGIC_APDU_CMD_MSG_LEN, 0);
    if (ret == -1) {
        log_printf("[FIDO] Unable to get back CMD_MSG_LEN with errno %x\n", errno);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
    msg_size = msgbuf.mtext.u16[0];
    printf("[FIDO] received APDU_CMD_MSG_LEN from USB (len is %d)\n", msg_size);

    /* calculating number of messages */
    uint32_t num_full_msg = msg_size / 64;
    uint8_t residual_msg = msg_size % 64;
    /* there is num_full_msg msg of size 64 + 1 residual msg of size residal_msg to get from USB to
     * fullfill the buffer */
    uint32_t offset = 0;
    uint32_t i;
    for (i = 0; i < num_full_msg; ++i) {
        ret = msgrcv(usb_msq, &cmd_buf[offset], msgsz, MAGIC_APDU_CMD_MSG, 0);
        if (ret == -1) {
            log_printf("[FIDO] Unable to get back CMD_MSG_LEN with errno %x\n", errno);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        printf("[FIDO] received APDU_CMD_MSG (pkt %d) from USB\n", i);
        offset += ret;
    }
    if (residual_msg) {
        ret = msgrcv(usb_msq, &cmd_buf[offset], residual_msg, MAGIC_APDU_CMD_MSG, 0);
        if (ret == -1) {
            log_printf("[FIDO] Unable to get back CMD_MSG_LEN with errno %x\n", errno);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        printf("[FIDO] received APDU_CMD_MSG (pkt %d, residual, %d bytes) from USB\n", i, ret);
        offset += ret;
    }
    if (offset != msg_size) {
        log_printf("[FIDO] Received data size %x does not match specified one %x\n", offset, msg_size);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }

    /* ready to execute the effective content */

    printf("[FIDO] received APDU from USB\n");
    hexdump(cmd_buf, msg_size);
    cmd_buf[msg_size] = 0x0;

    errcode = u2f_fido_handle_cmd(metadata, &cmd_buf[0], msg_size, &resp_buf[0], &resp_len);

    /* return back content */

    printf("[FIDO] Send APDU_RESP_INIT to USB\n");
    mtype = MAGIC_APDU_RESP_INIT;
    msgsnd(usb_msq, &mtype, 0, 0);

    msgbuf.mtype = MAGIC_APDU_RESP_MSG_LEN;
    msgbuf.mtext.u32[0] = resp_len;
    printf("[FIDO] Send APDU_RESP_MSG_LEN to USB\n");
    msgsnd(usb_msq, &msgbuf, sizeof(uint32_t), 0);

    num_full_msg = resp_len / 64;
    residual_msg = resp_len % 64;
    offset = 0;
    for (i = 0; i < num_full_msg; ++i) {
        msgbuf.mtype = MAGIC_APDU_RESP_MSG;
        memcpy(&msgbuf.mtext.u8[0], &resp_buf[offset], msgsz);
        printf("[FIDO] Send APDU_RESP_MSG (pkt %d) to USB\n", i);
        msgsnd(usb_msq, &msgbuf, msgsz, 0);
        offset += msgsz;
    }
    if (residual_msg != 0) {
        msgbuf.mtype = MAGIC_APDU_RESP_MSG;
        memcpy(&msgbuf.mtext.u8[0], &resp_buf[offset], residual_msg);
        printf("[FIDO] Send APDU_RESP_MSG (pkt %d, residual) to USB\n", i);
        msgsnd(usb_msq, &msgbuf, residual_msg, 0);
        offset += residual_msg;
    }
    /* response transmission done, sending local call return from u2fapdu_handle_cmd() */
    msgbuf.mtype = MAGIC_CMD_RETURN;
    msgbuf.mtext.u8[0] = errcode;
    msgsnd(usb_msq, &msgbuf, 1, 0);

err:
    return errcode;
}

volatile bool button_pushed = false;

void exti_button_handler (void)
{
    button_pushed = true;
}



bool handle_userpresence_backend(uint16_t timeout)
{
    /* wait half of duration and return ok by now */
    button_pushed = false;
    /* TODO: this should be timeouted here */
    timeout = timeout;

    send_signal_with_acknowledge(get_pin_msq(), MAGIC_USER_PRESENCE_REQ, MAGIC_USER_PRESENCE_ACK);
    button_pushed = true;
    return button_pushed;
}


