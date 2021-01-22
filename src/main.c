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
#include "libu2fapdu.h"
#include "generated/led0.h"
#include "generated/led1.h"
#include "generated/dfu_button.h"
#include "main.h"
#include "handlers.h"


device_t    up;
int    desc_up = 0;


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
    up.gpio_num = 3; /* Number of configured GPIO */

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


    up.gpios[2].kref.port = dfu_button_dev_infos.gpios[DFU_BUTTON_BASE].port;
    up.gpios[2].kref.pin = dfu_button_dev_infos.gpios[DFU_BUTTON_BASE].pin;
    up.gpios[2].mask     = GPIO_MASK_SET_MODE | GPIO_MASK_SET_PUPD |
                                 GPIO_MASK_SET_TYPE | GPIO_MASK_SET_SPEED |
                                 GPIO_MASK_SET_EXTI;
    up.gpios[2].mode     = GPIO_PIN_INPUT_MODE;
    up.gpios[2].pupd     = GPIO_PULLDOWN;
    up.gpios[2].type     = GPIO_PIN_OTYPER_PP;
    up.gpios[2].speed    = GPIO_PIN_LOW_SPEED;
    up.gpios[2].exti_trigger = GPIO_EXTI_TRIGGER_RISE;
    up.gpios[2].exti_lock    = GPIO_EXTI_UNLOCKED;
    up.gpios[2].exti_handler = (user_handler_t) exti_button_handler;

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
    char *wellcome_msg = "hello, I'm USB HID frontend";
    uint8_t ret;

    printf("%s\n", wellcome_msg);

    declare_userpresence_backend();
    int usb_msq = 0;

    /* Posix SystemV message queue init */
    printf("initialize Posix SystemV message queue with USB task\n");
    usb_msq = msgget("usb", IPC_CREAT | IPC_EXCL);
    if (usb_msq == -1) {
        printf("error while requesting SysV message queue. Errno=%x\n", errno);
        goto err;
    }

    ret = sys_init(INIT_DONE);

    if (ret != 0) {
        printf("failure while leaving init mode !!! err:%d\n", ret);
    }
    printf("sys_init DONE returns %x !\n", ret);

    /*
     * Let's declare a keyboard
     */
    //fido_declare(usbxdci_handler);

    /*U2FAPDU & FIDO are handled here, direct callback access */

    u2fapdu_register_callback(u2f_fido_handle_cmd);
    /* TODO callbacks protection */
    u2f_fido_initialize(handle_userpresence_backend);

    /*******************************************
     * End of init sequence, let's initialize devices
     *******************************************/

    /* wait for requests from USB task */
    int msqr;
    msg_mtext_union_t mbuf = { 0 };
    size_t msgsz = 64;
    printf("[FIDO] usb_msq is %d\n", usb_msq);
    do {
        msqr = msgrcv(usb_msq, &mbuf, msgsz, MAGIC_WINK_REQ, IPC_NOWAIT);
        if (msqr >= 0) {
            /* Wink request received */
            log_printf("[FIDO] received MAGIC_WINK_REQ from USB\n");
            /* check for other waiting msg before sleeping */
            handle_wink(1000, usb_msq);

            goto endloop;
        }
        msqr = msgrcv(usb_msq, &mbuf, msgsz, MAGIC_APDU_CMD_INIT, IPC_NOWAIT);
        if (msqr >= 0) {
            /* APDU message handling eceived */
            log_printf("[FIDO] received MAGIC_APDU_CMD_INIT from USB\n");
            /* and stard handling cmd */
            handle_apdu_request(usb_msq);
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
