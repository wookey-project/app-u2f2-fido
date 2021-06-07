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

#include "libc/random.h"

#include "libtoken_auth.h"
#include "libfido.h"
#include "generated/bsram_keybag.h"

//#define UNSAFE_LOCAL_KEY_HANDLE_GENERATION
#include "AUTH/FIDO/attestation_key.der.h"
#include "AUTH/FIDO/fido_hmac.bin.h"

static token_channel curr_token_channel = { .channel_initialized = 0, .secure_channel = 0, .IV = { 0 }, .first_IV = { 0 }, .AES_key = { 0 }, .HMAC_key = { 0 }, .pbkdf2_iterations = 0, .platform_salt_len = 0 };

static token_channel *fido_get_token_channel(void)
{
    return &curr_token_channel;
}


/* We save our secure channel mounting keys */
unsigned char decrypted_token_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE] = { 0 };
unsigned char decrypted_platform_priv_key_data[EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE] = { 0 };
unsigned char decrypted_platform_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE] = { 0 };
databag saved_decrypted_keybag[] = {
    { .data = decrypted_token_pub_key_data, .size = sizeof(decrypted_token_pub_key_data) },
    { .data = decrypted_platform_priv_key_data, .size = sizeof(decrypted_platform_priv_key_data) },
    { .data = decrypted_platform_pub_key_data, .size = sizeof(decrypted_platform_pub_key_data) },
};


/*****************************************************************************************************/
/*****************************************************************************************************/
/*****************************************************************************************************/
/************************** Interactions with the AUTH token applet FIDO part ************************/
/**** Open a FIDO session by sending our sectret ***/
#ifndef UNSAFE_LOCAL_KEY_HANDLE_GENERATION
unsigned char fido_attestation_privkey[FIDO_PRIV_KEY_SIZE] = { 0 };

int fido_open_session(void)
{
	uint8_t pkey[SHA256_DIGEST_SIZE];
        sha256_context sha256_ctx;
	unsigned int hpriv_key_len = (FIDO_PRIV_KEY_SIZE / 2);

	/* The FIDO derivation secret on our end is the hash of our decrypted platform keys */
        sha256_init(&sha256_ctx);
        sha256_update(&sha256_ctx, (const uint8_t*)saved_decrypted_keybag[0].data, saved_decrypted_keybag[0].size);
        sha256_update(&sha256_ctx, (const uint8_t*)saved_decrypted_keybag[1].data, saved_decrypted_keybag[1].size);
        sha256_update(&sha256_ctx, (const uint8_t*)saved_decrypted_keybag[2].data, saved_decrypted_keybag[2].size);
        sha256_final(&sha256_ctx, pkey);
	if(fido_get_token_channel()->channel_initialized != 1){
		goto err;
	}
	if(auth_token_fido_send_pkey(fido_get_token_channel(), pkey, sizeof(pkey), fido_hmac, sizeof(fido_hmac), fido_attestation_privkey + (FIDO_PRIV_KEY_SIZE / 2), &hpriv_key_len)){
		goto err;
	}
	/* Copy other half private key */
	memcpy(fido_attestation_privkey, fido_attestation_halfprivkey, FIDO_PRIV_KEY_SIZE / 2);
	return 0;
err:
	return -1;
}

#endif

#define MAX_RETRIES 10
int wrap_auth_token_exchanges(token_channel *channel, cb_token_callbacks *callbacks, bool do_use_saved_pins);

/**** Handle the tokens callbacks ****/
int callback_fido_register(const uint8_t *app_data, uint16_t app_data_len, uint8_t *key_handle, uint16_t *key_handle_len, uint8_t *ecdsa_priv_key, uint16_t *ecdsa_priv_key_len){
	if((key_handle_len == NULL) || (ecdsa_priv_key_len == NULL)){
		goto err;
	}
	unsigned int retries_reg = 0;
	unsigned int retries_wrap = 0;
	unsigned int _key_handle_len = *key_handle_len;
	unsigned int _ecdsa_priv_key_len = *ecdsa_priv_key_len;
	while(auth_token_fido_register(fido_get_token_channel(), app_data, app_data_len, key_handle, &_key_handle_len, ecdsa_priv_key, &_ecdsa_priv_key_len)){
		if(retries_reg > MAX_RETRIES){
			goto err;
		}
		retries_reg++;
	        /* Reinitialize our token */
                token_zeroize_secure_channel(fido_get_token_channel());
	        while(wrap_auth_token_exchanges(fido_get_token_channel(), NULL, true)){
		        printf("[APP FIDO] token reinit failed ...\n");
  	                if(retries_wrap > MAX_RETRIES){
			    goto err;
		        }
  	 	        retries_wrap++;
                }
                _key_handle_len = *key_handle_len;
                _ecdsa_priv_key_len = *ecdsa_priv_key_len;
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
	bool check_result = false;

	unsigned int retries_auth = 0;
	unsigned int retries_wrap = 0;

	if((check_only == 0) && (ecdsa_priv_key_len == NULL)){
		goto err;
	}
	if(check_only != 0){
		while(auth_token_fido_authenticate(fido_get_token_channel(), app_data, app_data_len, key_handle, key_handle_len, NULL, NULL, check_only, &check_result)){
 		        if(retries_auth > MAX_RETRIES){
			    goto err;
  		        }
 		        retries_auth++;
   		        /* Reinitialize our token */
        	        token_zeroize_secure_channel(fido_get_token_channel());
      		        while(wrap_auth_token_exchanges(fido_get_token_channel(), NULL, true)){
		            printf("[APP FIDO] token reinit failed ...\n");
  		            if(retries_wrap > MAX_RETRIES){
		                goto err;
  		             }
  		            retries_wrap++;
                       }
		}
	}
	else{
		_ecdsa_priv_key_len = *ecdsa_priv_key_len;
		while(auth_token_fido_authenticate(fido_get_token_channel(), app_data, app_data_len, key_handle, key_handle_len, ecdsa_priv_key, &_ecdsa_priv_key_len, check_only, &check_result)){
 		        if(retries_auth > MAX_RETRIES){
			    goto err;
  		        }
 		        retries_auth++;
 		        /* Reinitialize our token */
        	        token_zeroize_secure_channel(fido_get_token_channel());
      		        while(wrap_auth_token_exchanges(fido_get_token_channel(), NULL, true)){
		            printf("[APP FIDO] token reinit failed ...\n");
  		            if(retries_wrap > MAX_RETRIES){
			        goto err;
  		            }
  		            retries_wrap++;
                        }
  		        _ecdsa_priv_key_len = *ecdsa_priv_key_len;
		}
		if(_ecdsa_priv_key_len > (unsigned int)0xFFFF){
			goto err;
		}
		*ecdsa_priv_key_len = _ecdsa_priv_key_len;
	}

        if(check_result == false){
            /* Something wrong happened when checking */
            goto err;
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
int storage_msq = 0;
int get_storage_msq(void) {
    return storage_msq;
}



/* Cached credentials */
char global_user_pin[32] = { 0 };
volatile unsigned int global_user_pin_len = 0;
char global_pet_pin[32] = { 0 };
volatile unsigned int global_pet_pin_len = 0;
volatile bool use_saved_pins = false;

unsigned char sdpwd[16] = { 0 };

int auth_token_request_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action)
{
    msg_mtext_union_t data = { 0 };
    size_t data_len = sizeof(msg_mtext_union_t);

    if(use_saved_pins == true){
        if(pin_type == TOKEN_PET_PIN){
            if(global_pet_pin_len > *pin_len){
                goto err;
            }
            memcpy(pin, global_pet_pin, global_pet_pin_len);
            *pin_len = global_pet_pin_len;
        }
        else if(pin_type == TOKEN_USER_PIN){
            if(global_user_pin_len > *pin_len){
                goto err;
            }
            memcpy(pin, global_user_pin, global_user_pin_len);
            *pin_len = global_user_pin_len;
        }
        else{
            goto err;
        }
        return 0;
    }

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
    /* FIXME: TODO: */
    return 0;
}

int auth_token_request_pet_name(__attribute__((unused)) char *pet_name,  __attribute__((unused))unsigned int *pet_name_len)
{
    /* FIXME: TODO: */
    return 0;
}

int auth_token_request_pet_name_confirmation(const char *pet_name, unsigned int pet_name_len)
{
    msg_mtext_union_t data = { 0 };
    size_t data_len = 0;
    if(pet_name == NULL){
        goto err;
    }
    if(use_saved_pins == true){
        return 0;
    }
    strncpy(&data.c[0], pet_name, pet_name_len);
    data_len = pet_name_len;
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
    printf("smartcard removed !!!\n");
    /* Check if smartcard has been removed, and reboot if yes */
    if((fido_get_token_channel()->card.type != SMARTCARD_UNKNOWN) && !SC_is_smartcard_inserted(&(fido_get_token_channel()->card))){
        SC_smartcard_lost(&(fido_get_token_channel()->card));
        sys_reset();
    }
}


unsigned char MASTER_secret[32] = {0};
unsigned char MASTER_secret_h[32] = {0};

static volatile bool token_initialized = false;

int wrap_auth_token_exchanges(token_channel *channel, cb_token_callbacks *callbacks, bool do_use_saved_pins)
{
    token_initialized = false;

    use_saved_pins = do_use_saved_pins;

    /*********************************************
     * AUTH token communication, to get key from it
     *********************************************/
#ifdef CONFIG_APP_FIDO_USE_BKUP_SRAM
    /* Map the Backup SRAM to get our keybags*/
    if(bsram_keybag_map()){
        goto err;
    }
#endif

    /* Register smartcard removal handler */
    channel->card.type = SMARTCARD_CONTACT;
    /* Register our callback */
    ADD_LOC_HANDLER(smartcard_removal_action)
    SC_register_user_handler_action(&(channel->card), smartcard_removal_action);
    channel->card.type = SMARTCARD_UNKNOWN;

    /* Token default callbacks */
    cb_token_callbacks auth_token_callbacks = {
        .request_pin                   = auth_token_request_pin,
        .acknowledge_pin               = auth_token_acknowledge_pin,
        .request_pet_name              = auth_token_request_pet_name,
        .request_pet_name_confirmation = auth_token_request_pet_name_confirmation
    };

    cb_token_callbacks *cb;
    if(callbacks == NULL){
        cb = &auth_token_callbacks;
        /* Register our calbacks */
        ADD_LOC_HANDLER(auth_token_request_pin)
        ADD_LOC_HANDLER(auth_token_acknowledge_pin)
        ADD_LOC_HANDLER(auth_token_request_pet_name)
        ADD_LOC_HANDLER(auth_token_request_pet_name_confirmation)
    }
    else{
        cb = callbacks;
    }
    unsigned int retries = 0;
again:
    memset(MASTER_secret, 0, sizeof(MASTER_secret));
    memset(MASTER_secret_h, 0,  sizeof(MASTER_secret_h));
    memset(sdpwd, 0, sizeof(sdpwd));
    if(auth_token_exchanges(channel, cb, MASTER_secret, sizeof(MASTER_secret), MASTER_secret_h, sizeof(MASTER_secret_h), sdpwd, sizeof(sdpwd), saved_decrypted_keybag, sizeof(saved_decrypted_keybag)/sizeof(databag)))
    {
        retries++;
        if(retries > 4){
            goto err;
        }
        goto again;
    }
    /* Less retries for better reactivity */
    channel->error_recovery_max_send_retries = 2;

#if CONFIG_SMARTCARD_DEBUG
    printf("key received:\n");
    hexdump(MASTER_secret, 32);
    printf("hash received:\n");
    hexdump(MASTER_secret_h, 32);
    printf("sdpwd received:\n");
    hexdump(sdpwd, 16);
#endif

#ifndef UNSAFE_LOCAL_KEY_HANDLE_GENERATION
    /* Open FIDO session with token */
    if(fido_open_session()){
        printf("[FIDO] cannot open FIDO session with the token\n");
        goto err;
    }
#endif

    token_initialized = true;
    do_use_saved_pins = false;

    return 0;
err:
    do_use_saved_pins = false;
    return -1;
}



device_t    up;
int    desc_up = 0;

int parser_msq = 0;

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

    if(wrap_auth_token_exchanges(fido_get_token_channel(), NULL, false)){
        printf("[FIDO APP] failed when discussing with the token\n");
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
    /* ... and acknowledge frontend
     */
    struct msgbuf msgbuf = { 0 };
    msgbuf.mtype = MAGIC_TOKEN_UNLOCKED;
    msgsnd(u2fpin_msq, &msgbuf, 0, 0);

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
}

void wink_down(void)
{
    uint8_t ret;
    ret = sys_cfg(CFG_GPIO_SET, (uint8_t) up.gpios[0].kref.val, 0);
    if (ret != SYS_E_DONE) {
        printf ("sys_cfg(): failed\n");
    }
}


mbed_error_t handle_storage_assets(void)
{
    mbed_error_t errcode = MBED_ERROR_UNKNOWN;
    int msqr;
    struct msgbuf msgbuf = { 0 };
    printf("starting storage assets sync with storage app\n");

    /* waiting for get_assets request from storage */
    if ((msqr = msgrcv(storage_msq, &msgbuf, 0, MAGIC_STORAGE_GET_ASSETS, 0)) < 0) {
        printf("[fido storage] failed while waiting for get_assets request from storage, errno=%d\n", errno);
        errcode = MBED_ERROR_INTR;
        goto err;
    }

    /* and returning successively.... */
    /* 1. AES master key from which encryption & integrity keys are generated */
    msgbuf.mtype = MAGIC_STORAGE_SET_ASSETS_MASTERKEY;
    // fix add AES enc key
    memcpy(&msgbuf.mtext.u8[0], &MASTER_secret[0], 32);
    msqr = msgsnd(storage_msq, &msgbuf, 32, 0);
    if (msqr < 0) {
        printf("[fido storage] failed to send back AES enc key to storage, errno=%d\n", errno);
        errcode = MBED_ERROR_INTR;
        goto err;
    }

    /* 2. Anti-rollback counter */
    msgbuf.mtype = MAGIC_STORAGE_SET_ASSETS_ROLLBK;
    // Get back the rollback counter from the smartcard
    unsigned int counter_len = 8;
    if(auth_token_fido_get_replay_counter(fido_get_token_channel(), &msgbuf.mtext.u8[0], &counter_len)){
        printf("[fido storage] failed to get the global rollback counter from smartcard\n");
        errcode = MBED_ERROR_INTR;
        goto err;
    }
    msqr = msgsnd(storage_msq, &msgbuf, 8, 0);
    if (msqr < 0) {
        printf("[fido storage] failed to send back AES enc key to storage, errno=%d\n", errno);
        errcode = MBED_ERROR_INTR;
        goto err;
    }
    // Now wait for acknowledge and new counter
    size_t msgsz = 8;
    if ((msqr = msgrcv(storage_msq, &msgbuf, msgsz, MAGIC_STORAGE_SD_ROLLBK_COUNTER, 0)) < 0) {
        printf("[fido storage] failed while trying to receive anti-rollback counter, errno=%d\n", errno);
        errcode = MBED_ERROR_INTR;
        goto err;
    }
    if (msqr < 8) {
        printf("[fido storage] received rollback counter too small: %d bytes\n", msqr);
        errcode = MBED_ERROR_INTR;
        goto err;
    }
    /* Now set the new counter */
    if(auth_token_fido_set_replay_counter(fido_get_token_channel(), &msgbuf.mtext.u8[0], 8)){
        printf("[fido storage] failed to set the global rollback counter in smartcard\n");
        errcode = MBED_ERROR_INTR;
        goto err;
    }
    errcode = MBED_ERROR_NONE;
err:
    return errcode;

}


/*
 * Entrypoint
 */
int _main(uint32_t task_id)
{
    /* [RB] NOTE: we switch random generation to non secure here mainly
     * for *performance* reasons! This should however not have much impact
     * on security, since we still rely on the platform TRNG.
     */
    random_secure = SEC_RANDOM_NONSECURE;

    task_id = task_id;
    e_syscall_ret ret = 0;
    char *wellcome_msg = "hello, I'm USB HID frontend";
    //uint8_t ret;

    printf("%s\n", wellcome_msg);
    wmalloc_init();

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
    storage_msq = msgget("storage", IPC_CREAT | IPC_EXCL);
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
        default:
            printf("unknown error while init smartcard\n");
            goto err;
    }
#ifdef CONFIG_APP_FIDO_USE_BKUP_SRAM
    if(bsram_keybag_init()){
        goto err;
    }
#endif

    printf("set init as done\n");
    ret = sys_init(INIT_DONE);
    printf("sys_init returns %s !\n", strerror(ret));



    /*U2FAPDU & FIDO are handled here, direct callback access */

    /* TODO callbacks protection */
    ADD_LOC_HANDLER(handle_fido_event_backend);
    ADD_LOC_HANDLER(handle_fido_post_crypto_event_backend);
    u2f_fido_initialize(handle_fido_event_backend, handle_fido_post_crypto_event_backend);

    /*******************************************
     * End of init sequence, let's initialize devices
     *******************************************/

    /* wait for requests from USB task */
    int msqr;
    struct msgbuf mbuf = { 0 };
    printf("[FIDO] parser_msq is %d\n", parser_msq);

    // FIX: temp: get back MAGIC_IS_BACKEND_READY, and acknowledge
    /* transmitting 'backend ready?' to backend fido app, and requesting PIN in the meantime (prehook) for AUTH */

    ADD_LOC_HANDLER(unlock_u2f2);
    handle_signal(parser_msq, MAGIC_IS_BACKEND_READY, MAGIC_BACKEND_IS_READY, unlock_u2f2);
    // END FIX

    while(token_initialized == false){};
    /* handle for storage assets request from storage */
    if (handle_storage_assets() != MBED_ERROR_NONE) {
        printf("[FIDO] failed to inform properly storage with cryptographic assets, leaving\n");
        goto err;
    }



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
