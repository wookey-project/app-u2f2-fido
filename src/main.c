#include "libc/syscall.h"
#include "libc/stdio.h"
#include "libc/time.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/malloc.h"
#include "libc/sys/msg.h"
#include "libc/errno.h"

#include "autoconf.h"
#include "libfido.h"
#include "libu2f2.h"
#include "libu2fapdu.h"
#include "generated/led0.h"
#include "generated/led1.h"
#include "generated/dfu_button.h"
#include "main.h"
#include "handlers.h"

#include "libtoken_auth.h"
#include "libfido.h"
#include "generated/bsram_keybag.h"


static token_channel curr_token_channel = { .channel_initialized = 0, .secure_channel = 0, .IV = { 0 }, .first_IV = { 0 }, .AES_key = { 0 }, .HMAC_key = { 0 }, .pbkdf2_iterations = 0, .platform_salt_len = 0 };

static token_channel *fido_get_token_channel(void)
{
    return &curr_token_channel;
}

/*****************************************************************************************************/
/*****************************************************************************************************/
/*****************************************************************************************************/
/************************** Interactions with the AUTH token applet FIDO part ************************/
/**** Handle the tokens callbacks ****/
int callback_fido_register(const uint8_t *app_data, uint16_t app_data_len, uint8_t *key_handle, uint16_t *key_handle_len, uint8_t *ecdsa_priv_key, uint16_t *ecdsa_priv_key_len){
	if((key_handle_len == NULL) || (ecdsa_priv_key_len == NULL)){
		goto err;
	}
	unsigned int _key_handle_len = *key_handle_len;
	unsigned int _ecdsa_priv_key_len = *ecdsa_priv_key_len;
	if(auth_token_fido_register(fido_get_token_channel(), app_data, app_data_len, key_handle, &_key_handle_len, ecdsa_priv_key, &_ecdsa_priv_key_len)){
		goto err;
	}
	if(_key_handle_len > (unsigned int)0xFFFF){
		goto err;
	}
	*key_handle_len = _key_handle_len;
	if(_ecdsa_priv_key_len > (unsigned int)0xFFFF){
		goto err;
	}
	*ecdsa_priv_key_len = _ecdsa_priv_key_len;

	return 0;
err:
	if(key_handle_len != NULL){
		*key_handle_len = 0;
	}
	if(ecdsa_priv_key_len != NULL){
		*ecdsa_priv_key_len = 0;
	}
	return -1;
}

int callback_fido_authenticate(const uint8_t *app_data, uint16_t app_data_len, const uint8_t *key_handle, uint16_t key_handle_len, uint8_t *ecdsa_priv_key, uint16_t *ecdsa_priv_key_len, uint8_t check_only){
	unsigned int _ecdsa_priv_key_len = 0;

	if((check_only == 0) && (ecdsa_priv_key_len == NULL)){
		goto err;
	}
	if(check_only != 0){
		if(auth_token_fido_authenticate(fido_get_token_channel(), app_data, app_data_len, key_handle, key_handle_len, NULL, NULL, check_only)){
			goto err;
		}
	}
	else{
		_ecdsa_priv_key_len = *ecdsa_priv_key_len;
		if(auth_token_fido_authenticate(fido_get_token_channel(), app_data, app_data_len, key_handle, key_handle_len, ecdsa_priv_key, &_ecdsa_priv_key_len, check_only)){
			goto err;
		}
		if(_ecdsa_priv_key_len > (unsigned int)0xFFFF){
			goto err;
		}
		*ecdsa_priv_key_len = _ecdsa_priv_key_len;
	}

	return 0;
err:
	if(ecdsa_priv_key_len != NULL){
		*ecdsa_priv_key_len = 0;
	}
	return -1;
}

/***********************************************************/
#ifdef CONFIG_APP_FIDO_USE_BKUP_SRAM
/* Map and unmap the Backup SRAM */
static volatile bool bsram_keybag_is_mapped = false;
static volatile int  dev_bsram_keybag_desc = 0;
static int bsram_keybag_init(void){
    const char *name = "bsram-keybag";
    e_syscall_ret ret = 0;

    device_t dev;
    memset((void*)&dev, 0, sizeof(device_t));
    strncpy(dev.name, name, sizeof (dev.name));
    dev.address = bsram_keybag_dev_infos.address;
    dev.size = bsram_keybag_dev_infos.size;
    dev.map_mode = DEV_MAP_VOLUNTARY;

    dev.irq_num = 0;
    dev.gpio_num = 0;
    int dev_bsram_keybag_desc_ = dev_bsram_keybag_desc;
    ret = sys_init(INIT_DEVACCESS, &dev, (int*)&dev_bsram_keybag_desc_);
    if(ret != SYS_E_DONE){
        printf("Error: Backup SRAM keybag, sys_init error!\n");
        goto err;
    }
    dev_bsram_keybag_desc = dev_bsram_keybag_desc_;

    return 0;
err:
    return -1;
}

static int bsram_keybag_map(void){
    if(bsram_keybag_is_mapped == false){
        e_syscall_ret ret;
        ret = sys_cfg(CFG_DEV_MAP, dev_bsram_keybag_desc);
        if (ret != SYS_E_DONE) {
            printf("Unable to map Backup SRAM keybag!\n");
            goto err;
        }
        bsram_keybag_is_mapped = true;
    }

    return 0;
err:
    return -1;
}

static int bsram_keybag_unmap(void){
    if(bsram_keybag_is_mapped){
        e_syscall_ret ret;
        ret = sys_cfg(CFG_DEV_UNMAP, dev_bsram_keybag_desc);
        if (ret != SYS_E_DONE) {
            printf("Unable to unmap Backup SRAM keybag!\n");
            goto err;
        }
        bsram_keybag_is_mapped = false;
    }

    return 0;
err:
    return -1;
}
#endif


int u2fpin_msq = 0;
int get_u2fpin_msq(void) {
    return u2fpin_msq;
}

/* Cached credentials */
char global_user_pin[32] = { 0 };
unsigned int global_user_pin_len = 0;
char global_pet_pin[32] = { 0 };
unsigned int global_pet_pin_len = 0;

unsigned char sdpwd[16] = { 0 };

int auth_token_request_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action)
{
    msg_mtext_union_t data = { 0 };
    size_t data_len = sizeof(msg_mtext_union_t);

printf("===> auth_token_request_pin\n");
    if(action == TOKEN_PIN_AUTHENTICATE){
        if(pin_type == TOKEN_PET_PIN){
            if (exchange_data(u2fpin_msq, MAGIC_PETPIN_INSERT, MAGIC_PETPIN_INSERTED, NULL/*data_sent*/, 0/*data_sent_len*/, &data, &data_len) != MBED_ERROR_NONE) {
                printf("failed while requesting PetPIN for confirm unlock! erro=%d\n", errno);
                goto err;
            }
            /* FIXME */
            data_len = strlen(&data.c[0]);
            if (data_len > sizeof(global_pet_pin)){
                goto err;
            }
            memcpy(global_pet_pin, &data.c[0], data_len);
            global_pet_pin_len = data_len;
            if(data_len > *pin_len){
                goto err;
            }
            *pin_len = data_len;
            memcpy(pin, &data.c[0], data_len);
printf("==> PET PIN = %s\n", global_pet_pin);
        }
        else if(pin_type == TOKEN_USER_PIN){
            if (exchange_data(u2fpin_msq, MAGIC_USERPIN_INSERT, MAGIC_USERPIN_INSERTED, NULL/*data_sent*/, 0/*data_sent_len*/, &data, &data_len) != MBED_ERROR_NONE) {
                printf("failed while requesting UserPIN for confirm unlock! erro=%d\n", errno);
                goto err;
            }
            /* FIXME */
            data_len = strlen(&data.c[0]);
            if (data_len > sizeof(global_user_pin)){
                goto err;
            }
            memcpy(global_user_pin, &data.c[0], data_len);
            global_user_pin_len = data_len;
            if(data_len > *pin_len){
                goto err;
            }
            *pin_len = data_len;
            memcpy(pin, &data.c[0], data_len);
printf("==> User PIN = %s\n", global_user_pin);
        }
        else{
            goto err;
        }
    }
    else if(action == TOKEN_PIN_MODIFY){
        /* FIXME: TODO: */
        goto err;
    }
    else{
        goto err;
    }

    return 0;
err:
    return -1;
}

int auth_token_acknowledge_pin(__attribute__((unused)) token_ack_state ack, __attribute__((unused)) token_pin_types pin_type, __attribute__((unused)) token_pin_actions action, __attribute__((unused)) uint32_t remaining_tries)
{
printf("===> auth_token_acknowledge_pin\n");
    /* FIXME: TODO: */
    return 0;
}

int auth_token_request_pet_name(__attribute__((unused)) char *pet_name,  __attribute__((unused))unsigned int *pet_name_len)
{
printf("===> auth_token_request_pet_name\n");
    /* FIXME: TODO: */
    return 0;
}

int auth_token_request_pet_name_confirmation(const char *pet_name, unsigned int pet_name_len)
{
    msg_mtext_union_t data = { 0 };
    size_t data_len = sizeof(msg_mtext_union_t);
printf("===> auth_token_request_pet_name_confirmation\n");

    if(pet_name == NULL){
        goto err;
    }
    strncpy(&data.c[0], pet_name, pet_name_len);
printf("==> PETNAME = %s\n", &data.c[0]);
    if (exchange_data(u2fpin_msq, MAGIC_PASSPHRASE_CONFIRM, MAGIC_PASSPHRASE_RESULT, &data, data_len, &data, &data_len) != MBED_ERROR_NONE) {
        printf("failed while requesting U2FPIN for confirm unlock! erro=%d\n", errno);
        goto err;
    }
    if (data.u8[0] != 0xff) {
        printf("Invalid passphrase !!!\n");
        goto err;
    }

    return 0;
err:
    return -1;
}

void smartcard_removal_action(void){
    /* Check if smartcard has been removed, and reboot if yes */
    if((curr_token_channel.card.type != SMARTCARD_UNKNOWN) && !SC_is_smartcard_inserted(&(curr_token_channel.card))){
        SC_smartcard_lost(&(curr_token_channel.card));
        sys_reset();
    }
}

device_t    up;
int    desc_up = 0;

int parser_msq = 0;

static volatile bool token_initialized = false;
mbed_error_t unlock_u2f2(void)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    /* unlocking u2f2 is made of multiple steps:
     * 1/ ask u2fpin for 'backend_ready'
     */

    if (send_signal_with_acknowledge(u2fpin_msq, MAGIC_IS_BACKEND_READY, MAGIC_BACKEND_IS_READY) != MBED_ERROR_NONE) {
        printf("failed while requesting PIN for confirm unlock! erro=%d\n", errno);
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }

    /*********************************************
     * AUTH token communication, to get key from it
     *********************************************/
#ifdef CONFIG_APP_FIDO_USE_BKUP_SRAM
    /* Map the Backup SRAM to get our keybags*/
    if(bsram_keybag_map()){
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
#endif
    unsigned char MASTER_secret[32] = {0};
    unsigned char MASTER_secret_h[32] = {0};

    /* Register smartcard removal handler */
    curr_token_channel.card.type = SMARTCARD_CONTACT;
    /* Register our callback */
    ADD_LOC_HANDLER(smartcard_removal_action)
    SC_register_user_handler_action(&(curr_token_channel.card), smartcard_removal_action);
    curr_token_channel.card.type = SMARTCARD_UNKNOWN;

    /* Token callbacks */
    cb_token_callbacks auth_token_callbacks = {
        .request_pin                   = auth_token_request_pin,
        .acknowledge_pin               = auth_token_acknowledge_pin,
        .request_pet_name              = auth_token_request_pet_name,
        .request_pet_name_confirmation = auth_token_request_pet_name_confirmation
    };
    /* Register our calbacks */
    ADD_LOC_HANDLER(auth_token_request_pin)
    ADD_LOC_HANDLER(auth_token_acknowledge_pin)
    ADD_LOC_HANDLER(auth_token_request_pet_name)
    ADD_LOC_HANDLER(auth_token_request_pet_name_confirmation)
    if(auth_token_exchanges(&curr_token_channel, &auth_token_callbacks, MASTER_secret, sizeof(MASTER_secret), MASTER_secret_h, sizeof(MASTER_secret_h), sdpwd, sizeof(sdpwd), NULL, 0))
    {
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }

#if CONFIG_SMARTCARD_DEBUG
    printf("key received:\n");
    hexdump(MASTER_secret, 32);
    printf("hash received:\n");
    hexdump(MASTER_secret_h, 32);
#endif
    /* ... and acknowledge frontend
     */
   token_initialized = true;

err:
    return errcode;
}

/*********************************************************
 * Utility functions
 */

void wink_up(void)
{
    uint8_t ret;
    ret = sys_cfg(CFG_GPIO_SET, (uint8_t) up.gpios[0].kref.val, 1);
    if (ret != SYS_E_DONE) {
        printf ("sys_cfg(): failed\n");
    }
    ret = sys_cfg(CFG_GPIO_SET, (uint8_t) up.gpios[1].kref.val, 1);
    if (ret != SYS_E_DONE) {
        printf ("sys_cfg(): failed\n");
    }
}

void wink_down(void)
{
    uint8_t ret;
    ret = sys_cfg(CFG_GPIO_SET, (uint8_t) up.gpios[0].kref.val, 0);
    if (ret != SYS_E_DONE) {
        printf ("sys_cfg(): failed\n");
    }
    ret = sys_cfg(CFG_GPIO_SET, (uint8_t) up.gpios[1].kref.val, 0);
    if (ret != SYS_E_DONE) {
        printf ("sys_cfg(): failed\n");
    }
}


/*********************************************************
 * Hardware-related declarations (backend handling)
 */

static mbed_error_t declare_userpresence_backend(void)
{
    uint8_t ret;
    /* Button + LEDs */
    memset (&up, 0, sizeof (up));

    strncpy (up.name, "UsPre", sizeof (up.name));
    up.gpio_num = 2; /* Number of configured GPIO */

    up.gpios[0].kref.port = led0_dev_infos.gpios[LED0_BASE].port;
    up.gpios[0].kref.pin = led0_dev_infos.gpios[LED0_BASE].pin;
    up.gpios[0].mask     = GPIO_MASK_SET_MODE | GPIO_MASK_SET_PUPD |
                                 GPIO_MASK_SET_TYPE | GPIO_MASK_SET_SPEED;
    up.gpios[0].mode     = GPIO_PIN_OUTPUT_MODE;
    up.gpios[0].pupd     = GPIO_PULLDOWN;
    up.gpios[0].type     = GPIO_PIN_OTYPER_PP;
    up.gpios[0].speed    = GPIO_PIN_HIGH_SPEED;


    up.gpios[1].kref.port = led1_dev_infos.gpios[LED0_BASE].port;
    up.gpios[1].kref.pin = led1_dev_infos.gpios[LED0_BASE].pin;
    up.gpios[1].mask     = GPIO_MASK_SET_MODE | GPIO_MASK_SET_PUPD |
                                 GPIO_MASK_SET_TYPE | GPIO_MASK_SET_SPEED;
    up.gpios[1].mode     = GPIO_PIN_OUTPUT_MODE;
    up.gpios[1].pupd     = GPIO_PULLDOWN;
    up.gpios[1].type     = GPIO_PIN_OTYPER_PP;
    up.gpios[1].speed    = GPIO_PIN_HIGH_SPEED;


    ret = sys_init(INIT_DEVACCESS, &up, &desc_up);
    if (ret == SYS_E_DONE) {
        return MBED_ERROR_NONE;
    }
    return MBED_ERROR_UNKNOWN;
}


/*
 * Entrypoint
 */
int _main(uint32_t task_id)
{
    task_id = task_id;
    e_syscall_ret ret = 0;
    char *wellcome_msg = "hello, I'm USB HID frontend";
    //uint8_t ret;

    printf("%s\n", wellcome_msg);
    wmalloc_init();

    //declare_userpresence_backend();
    int parser_msq = 0;

    /* Posix SystemV message queue init */
    printf("initialize Posix SystemV message queue with USB task\n");
    parser_msq = msgget("parser", IPC_CREAT | IPC_EXCL);
    if (parser_msq == -1) {
        printf("error while requesting SysV message queue. Errno=%x\n", errno);
        goto err;
    }
    u2fpin_msq = msgget("u2fpin", IPC_CREAT | IPC_EXCL);
    if (u2fpin_msq == -1) {
        printf("error while requesting SysV message queue. Errno=%x\n", errno);
        goto err;
    }


    /* declaring devices... */
    token_initialized = false;
    /* 2/ initiate iso7816 communication with auth token (wait for smartcard if needed)
     */
    int tokenret = 0;
    tokenret = token_early_init(TOKEN_MAP_AUTO);
    switch (tokenret) {
        case 0:
            printf("Smartcard early init done\n");
            break;
        case 1:
            printf("error while declaring GPIOs\n");
            goto err;
            break;
        case 2:
            printf("error while declaring USART\n");
            goto err;
            break;
#if 0
        // PTH: this return value does not exist in the call graph. Only declarative part here
        case 3:
            printf("error while init smartcard\n");
            break;
#endif
        default:
            printf("unknown error while init smartcard\n");
            goto err;
    }
#ifdef CONFIG_APP_FIDO_USE_BKUP_SRAM
    if(bsram_keybag_init()){
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
#endif

    printf("set init as done\n");
    ret = sys_init(INIT_DONE);
    printf("sys_init returns %s !\n", strerror(ret));



    /*U2FAPDU & FIDO are handled here, direct callback access */

    /* TODO callbacks protection */
    ADD_LOC_HANDLER(handle_userpresence_backend);
    u2f_fido_initialize(handle_userpresence_backend);

    /*******************************************
     * End of init sequence, let's initialize devices
     *******************************************/

    /* wait for requests from USB task */
    int msqr;
    msg_mtext_union_t mbuf = { 0 };
    printf("[FIDO] parser_msq is %d\n", parser_msq);

    // FIX: temp: get back MAGIC_IS_BACKEND_READY, and acknowledge
    /* transmitting 'backend ready?' to backend fido app, and requesting PIN in the meantime (prehook) for AUTH */

    ADD_LOC_HANDLER(unlock_u2f2);
    handle_signal(parser_msq, MAGIC_IS_BACKEND_READY, MAGIC_BACKEND_IS_READY, unlock_u2f2);
    // END FIX

    while(token_initialized == false){};

    size_t msgsz = 64;
    do {
        msqr = msgrcv(parser_msq, &mbuf, msgsz, MAGIC_WINK_REQ, IPC_NOWAIT);
        if (msqr >= 0) {
            /* Wink request received */
            log_printf("[FIDO] received MAGIC_WINK_REQ from USB\n");
            /* check for other waiting msg before sleeping */
            handle_wink(1000, parser_msq);

            goto endloop;
        }
        msqr = msgrcv(parser_msq, &mbuf, msgsz, MAGIC_APDU_CMD_INIT, IPC_NOWAIT);
        if (msqr >= 0) {
            /* APDU message handling eceived */
            log_printf("[FIDO] received MAGIC_APDU_CMD_INIT from USB\n");
            /* and stard handling cmd */
            handle_fido_request(parser_msq);
            /* check for other waiting msg before sleeping */
            goto endloop;
        }
        /* no message received ? As FIDO is a slave task, sleep for a moment... */
        sys_sleep(500, SLEEP_MODE_INTERRUPTIBLE);
endloop:
        continue;
    } while (1);

err:
    printf("Going to error state!\n");
    return 1;
}
