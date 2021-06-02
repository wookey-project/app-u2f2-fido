#include "autoconf.h"
#include "libc/types.h"
#include "libc/sys/msg.h"
#include "libc/stdio.h"
#include "libc/errno.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/syscall.h"
#include "libc/sync.h"
#include "libc/malloc.h"
#include "libfidostorage.h"

#include "libtoken_auth.h"
#include "libfido.h"
#include "handlers.h"
#include "main.h"

#include "generated/bsram_keybag.h"


typedef struct ephemeral_fido_ctx {
    bool        valid;
    bool        metadata_exist;
    uint8_t     fido_action;
    uint32_t    ctr;
    uint8_t     appid[FIDO_APPLICATION_PARAMETER_SIZE];
    uint8_t     kh[FIDO_KEY_HANDLE_SIZE];
    uint8_t     kh_hash[32];
} ephemeral_fido_ctx_t;

static ephemeral_fido_ctx_t fido_ctx = { 0 };


static inline void dump_ephemeral(void) {
    printf("ephemeral fido ctx:\n");
    printf("-> valid: %d\n", fido_ctx.valid);
    printf("-> meta_exists: %d\n", fido_ctx.metadata_exist);
    printf("-> fido_action: %d\n", fido_ctx.fido_action);
    printf("-> ctr: %d\n", fido_ctx.ctr);
    printf("-> appid:\n");
    hexdump(&fido_ctx.appid[0], FIDO_APPLICATION_PARAMETER_SIZE);
    printf("-> kh_hash:\n");
    hexdump(&fido_ctx.kh_hash[0], 32);
}

static inline void clear_ephemeral_fido_ctx(ephemeral_fido_ctx_t *ctx) {
    memset(ctx, 0, sizeof(ephemeral_fido_ctx_t));
    ctx->valid = false;
    ctx->metadata_exist = false;
    request_data_membarrier();
}

//static volatile uint32_t ctr;
//static volatile bool     ctr_valid = false;

/*@
  @ requires \valid(hash + (0 .. 31));
  @ requires \valid_read(kh + (0 .. 31));
  */
static inline int get_hash_from_kh(uint8_t       hash[32] __attribute__((unused)),
                                    const uint8_t kh[FIDO_KEY_HANDLE_SIZE]   __attribute__((unused))) {
    if((hash == NULL) || (kh == NULL)){
        goto err;
    }
    /* Compute the SHA-256 hash of our key handle for anonymization */
    sha256_context sha256_ctx;
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, kh, FIDO_KEY_HANDLE_SIZE);
    sha256_final(&sha256_ctx, hash);

    return 0;
err:
    return -1;
}

uint32_t fido_get_auth_counter(void) {
    if (fido_ctx.valid == true) {
        return fido_ctx.ctr;
    }
    return 0;
}

void fido_inc_auth_counter(const uint8_t *appid, uint16_t appid_len) {

    struct msgbuf msgbuf = { 0 };
    msgbuf.mtype = MAGIC_STORAGE_INC_CTR;
    if (appid_len > 64) {
        printf("[fido] appid len too big!\n");
        goto err;
    }
    memcpy(&msgbuf.mtext.u8[0], appid, appid_len);
    if (msgsnd(get_storage_msq(), &msgbuf, appid_len, 0) < 0) {
        printf("[fido] failed to send CTR inc to storage!\n");
    }

err:
    return;
}



mbed_error_t handle_wink(uint16_t timeout_ms, int usb_msq)
{
    /* FIXME: get back EMULATION config and handle it here */
    wink_up();
    waitfor(timeout_ms);
    wink_down();

    log_printf("[FIDO] Send WINK acknowledge to USB\n");
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
    ret = msgrcv(usb_msq, &msgbuf, msgsz, MAGIC_APDU_CMD_META, 0);
    if (ret == -1) {
        printf("[FIDO] Unable to get back CMD_MSG_META with errno %x\n", errno);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
    metadata = msgbuf.mtext.u32[0];
    log_printf("[FIDO] received APDU_CMD_META from USB: %x\n", metadata);

    /* now wait for APDU_CMD_MSG_LEN, to calculate the number of needed msg */
    ret = msgrcv(usb_msq, &msgbuf, msgsz, MAGIC_APDU_CMD_MSG_LEN, 0);
    if (ret == -1) {
        printf("[FIDO] Unable to get back CMD_MSG_LEN with errno %x\n", errno);
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
        ret = msgrcv(usb_msq, &msgbuf, msgsz, MAGIC_APDU_CMD_MSG, 0);
        if (ret == -1) {
            printf("[FIDO] Unable to get back CMD_MSG_LEN with errno %x\n", errno);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        memcpy(&cmd_buf[offset], &msgbuf.mtext.u8[0], ret);
        log_printf("[FIDO] received APDU_CMD_MSG (pkt %d) from USB\n", i);
        offset += ret;
    }
    if (residual_msg) {
        ret = msgrcv(usb_msq, &msgbuf, residual_msg, MAGIC_APDU_CMD_MSG, 0);
        if (ret == -1) {
            printf("[FIDO] Unable to get back CMD_MSG_LEN with errno %x\n", errno);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        memcpy(&cmd_buf[offset], &msgbuf.mtext.u8[0], ret);
        log_printf("[FIDO] received APDU_CMD_MSG (pkt %d, residual, %d bytes) from USB\n", i, ret);
        offset += ret;
    }
    if (offset != msg_size) {
        log_printf("[FIDO] Received data size %x does not match specified one %x\n", offset, msg_size);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }

    /* ready to execute the effective content */

    log_printf("[FIDO] received APDU from USB\n");
    //hexdump(cmd_buf, msg_size);
    cmd_buf[msg_size] = 0x0;

    errcode = u2f_fido_handle_cmd(metadata, &cmd_buf[0], msg_size, &resp_buf[0], &resp_len);
    if(errcode != MBED_ERROR_NONE){
        goto err;
    }
    printf("[FIDO] end of command handling of action %d\n", fido_ctx.fido_action);
    dump_ephemeral();
    /* Now, in case of a REGISTER, use a possible existing template */
    if((fido_ctx.valid == true) && (fido_ctx.fido_action == U2F_FIDO_REGISTER)) {
        printf("[FIDO] REGISTER action posthook\n");
        /* sending set_metadata request, specifying set mode */
        if (fido_ctx.metadata_exist == true) {
            msgbuf.mtext.u8[0] = STORAGE_MODE_NEW_FROM_TEMPLATE;
        } else {
            msgbuf.mtext.u8[0] = STORAGE_MODE_NEW_FROM_SCRATCH;
        }
        msgbuf.mtype = MAGIC_STORAGE_SET_METADATA;
        msg_size = 1;
        if (unlikely(msgsnd(get_storage_msq(), &msgbuf, msg_size, 0) == -1)) {
            printf("[fido] failed when transmitting set_meta to storage: errno=%d\n", errno);
            goto err;
        }
        /* then sending the associated identifiers */
        msgbuf.mtype = MAGIC_APPID_METADATA_IDENTIFIERS;
        memcpy(&msgbuf.mtext.u8[0], &fido_ctx.appid[0], FIDO_APPLICATION_PARAMETER_SIZE);
        memcpy(&msgbuf.mtext.u8[FIDO_APPLICATION_PARAMETER_SIZE], &fido_ctx.kh_hash, 32);
        msg_size = 64;
        if (unlikely(msgsnd(get_storage_msq(), &msgbuf, msg_size, 0) == -1)) {
            printf("[fido] failed when transmitting identifiers to storage: errno=%d\n", errno);
            goto err;
        }
        /* and close the transmission */
        msgbuf.mtype = MAGIC_APPID_METADATA_END;
        msg_size = 0;
        if (unlikely(msgsnd(get_storage_msq(), &msgbuf, msg_size, 0) == -1)) {
            printf("[fido] failed when transmitting end_of_set to storage: errno=%d\n", errno);
            goto err;
        }
    }

    /* here, whatever the command was, we can consider that it should be cleaned */
    clear_ephemeral_fido_ctx(&fido_ctx);

    /* return back content */

    log_printf("[FIDO] Send APDU_RESP_INIT to USB\n");
    mtype = MAGIC_APDU_RESP_INIT;
    msgsnd(usb_msq, &mtype, 0, 0);

    msgbuf.mtype = MAGIC_APDU_RESP_MSG_LEN;
    msgbuf.mtext.u16[0] = resp_len;
    log_printf("[FIDO] Send APDU_RESP_MSG_LEN to USB\n");
    msgsnd(usb_msq, &msgbuf, sizeof(uint16_t), 0);

    num_full_msg = resp_len / 64;
    residual_msg = resp_len % 64;
    offset = 0;
    for (i = 0; i < num_full_msg; ++i) {
        msgbuf.mtype = MAGIC_APDU_RESP_MSG;
        memcpy(&msgbuf.mtext.u8[0], &resp_buf[offset], msgsz);
        log_printf("[FIDO] Send APDU_RESP_MSG (pkt %d) to USB\n", i);
        msgsnd(usb_msq, &msgbuf, msgsz, 0);
        offset += msgsz;
    }
    if (residual_msg != 0) {
        msgbuf.mtype = MAGIC_APDU_RESP_MSG;
        memcpy(&msgbuf.mtext.u8[0], &resp_buf[offset], residual_msg);
        log_printf("[FIDO] Send APDU_RESP_MSG (pkt %d, residual) to USB\n", i);
        msgsnd(usb_msq, &msgbuf, residual_msg, 0);
        offset += residual_msg;
    }
    /* response transmission done, sending local call return from u2fapdu_handle_cmd() */
    msgbuf.mtype = MAGIC_CMD_RETURN;
    msgbuf.mtext.u8[0] = errcode;
    msgsnd(usb_msq, &msgbuf, 1, 0);

err:
    clear_ephemeral_fido_ctx(&fido_ctx);
    return errcode;
}

volatile bool button_pushed = false;


/*
 * Call for both register & authenticate
 */

bool handle_fido_event_backend(uint16_t timeout, const uint8_t appid[FIDO_APPLICATION_PARAMETER_SIZE], const uint8_t key_handle[FIDO_KEY_HANDLE_SIZE], u2f_fido_action action)
{
    /* wait half of duration and return ok by now */
    button_pushed = false;
    ssize_t len;


    printf("[FIDO] event arise, action=%d\n", action);
    /* Sanity checks */
    if (appid == NULL) {
        goto err;
    }
    if((action == U2F_FIDO_REGISTER) && (key_handle != NULL)){
        goto err;
    }
    if ((action == U2F_FIDO_AUTHENTICATE) && (key_handle == NULL)) {
        goto err;
    }
    if ((action == U2F_FIDO_CHECK_ONLY) && (key_handle == NULL)) {
        goto err;
    }
    if (fido_ctx.valid == true) {
        printf("a current context is already set!!! should not happen!\n");
        goto err;
    }
    struct msgbuf msgbuf = { 0 };

    log_printf("[fido] user presence, timeout is %d ms\n", timeout);
    /* first, get back info from storage, based on appid */

    memcpy(&fido_ctx.appid[0], &appid[0], FIDO_APPLICATION_PARAMETER_SIZE);
    fido_ctx.fido_action = action;
    request_data_membarrier();

    if (action == U2F_FIDO_CHECK_ONLY) {
        msgbuf.mtype = MAGIC_STORAGE_GET_METADATA_STATUS;
    }
    /* Ask GUI backend except when dealing with CHECK ONLY */
    if((action == U2F_FIDO_REGISTER) || (action == U2F_FIDO_AUTHENTICATE)){
        log_printf("[fido]sending USER_PRESENCE_REQ to u2fpin\n");
        /* send userpresence request to u2fPIN and wait for METADATA request in response */
        msgbuf.mtext.u16[0] = timeout;
        msgbuf.mtext.u16[1] = action;
        /* sending appid */
        msgbuf.mtype = MAGIC_USER_PRESENCE_REQ;
        msgsnd(get_u2fpin_msq(), &msgbuf, 2*sizeof(uint16_t), 0);
        /* waiting for get_metadata() as a response */
        log_printf("[fido] now waiting for get_metadata reception from u2fpin\n");
        /* receiving GET_METADATA from u2fpin.... */
        if ((len = msgrcv(get_u2fpin_msq(), &msgbuf, 64, MAGIC_STORAGE_GET_METADATA, 0)) == -1) {
            printf("[fido] failed to reveive from u2fpin: errno=%d\n", errno);
            goto err;
        }
    }


    /* setting appid and hash(KH) here :-) */
    memcpy(&msgbuf.mtext.u8[0], appid, 32);
    switch (action) {
        case U2F_FIDO_REGISTER:
            /* in case of register, we are looking for template service, for which
             * HASH(KH) = 0x0 */
            memset(&msgbuf.mtext.u8[32], 0x0, 32);
            memset(&fido_ctx.kh[0], 0x0, FIDO_KEY_HANDLE_SIZE);
            request_data_membarrier();
            break;
        case U2F_FIDO_CHECK_ONLY:
        case U2F_FIDO_AUTHENTICATE: {
            if(get_hash_from_kh(&msgbuf.mtext.u8[32], &key_handle[0])){
                goto err;
            }
            memcpy(&fido_ctx.kh[0], &key_handle[0], FIDO_KEY_HANDLE_SIZE);
            memcpy(&fido_ctx.kh_hash[0], &msgbuf.mtext.u8[32], 32);
            request_data_membarrier();
            break;
        }
        default:
            goto err;
            /* This action should not happen! */
            break;
    }
    /* here, we have, in CHECK_ONLY case, a msgbuf typed GET_METADATA_STATUS and containing
     * the appid and the KH hash.
     * In REGISTER or AUTHENTICATE case, the msgbuf is typed GET_METADATA and contains the same
     * fields
     * From now on, in check only, we can work alone, in register and authenticase case, we
     * handle the communication between u2fpin and storage as a proxy */

    /* transfering the request to storage */
    len = 64;
    msgsnd(get_storage_msq(), &msgbuf, len, 0);


    /* in CHECK only, we react to the slot status only */
    if (action == U2F_FIDO_CHECK_ONLY) {
        if ((len = msgrcv(get_storage_msq(), &msgbuf, 1, MAGIC_APPID_METADATA_STATUS, 0)) == -1) {
            printf("[fido] failed to reveive from storage: errno=%d\n", errno);
            goto err;
        }
        if (len != 1)  {
            /* XXX: invalid response len */
            goto err;
        }
        button_pushed = false;
        switch (msgbuf.mtext.u8[0]) {
            case 0x0:
                /* kept false */
                break;
            case 0xff:
                button_pushed = true;
                break;
            default:
                /* kept false */
                break;
        }
        goto err;
    }
    /* in register or authenticate, we handle the communication as a proxy */
    if((action == U2F_FIDO_REGISTER) || (action == U2F_FIDO_AUTHENTICATE)){
        /* transmit back all receiving requests from storage directly to u2fpin */
        bool transmission_finished = false;
        while (!transmission_finished) {
            /* reading any msg from storage */
            if ((len = msgrcv(get_storage_msq(), &msgbuf, 64, 0, 0)) == -1) {
                printf("[fido] failed to reveive from storage: errno=%d\n", errno);
                goto err;
            }
            if(action == U2F_FIDO_CHECK_ONLY){
                /* In CHECK ONLY mode, this is it, storage is OK and we can sefely continue! */
                return true;
            }
            if (msgbuf.mtype == MAGIC_APPID_METADATA_CTR) {
                /* here we steal the CTR to avoid to get it back again from storage,
                 * thanks to our proxy position */
                set_u32_with_membarrier(&fido_ctx.ctr, msgbuf.mtext.u32[0]);
                set_bool_with_membarrier(&fido_ctx.valid, true);
            }
            if (msgbuf.mtype == MAGIC_APPID_METADATA_END) {
                transmission_finished = true;
            }
            if (msgsnd(get_u2fpin_msq(), &msgbuf, len, 0) == -1) {
                printf("[fido] failed when transmitting to u2fpin: errno=%d\n", errno);
            }
            if (msgbuf.mtype == MAGIC_APPID_METADATA_STATUS) {
                if (msgbuf.mtext.u8[0] == 0xff) {
                    fido_ctx.metadata_exist = true;
                }
                else{
                    fido_ctx.metadata_exist = false;
                }
             }
        }
        /* ... and wait for u2fpin acknowledge */
        log_printf("[fido] waiting for User presence ACK to FIDO\n");
        msgrcv(get_u2fpin_msq(), &msgbuf, 2, MAGIC_USER_PRESENCE_ACK, 0);
        log_printf("[fido] user backend returned with %x!\n", msgbuf.mtext.u16[0]);
        if (msgbuf.mtext.u16[0] == 0x4242) {
            button_pushed = true;
        }
    }
err:
    request_data_membarrier();
    printf("[fido] end of triggered event\n");
    dump_ephemeral();

    return button_pushed;
}
