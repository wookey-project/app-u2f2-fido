#ifndef HANDLERS_H_
#define HANDLERS_H_

#include "libc/types.h"
#include "libu2f2.h"

/*
 * Local handlers to FIDO events
 */
mbed_error_t handle_wink(uint16_t timeout_ms, int usb_msq);

mbed_error_t handle_fido_request(int usb_msq);

bool handle_fido_post_crypto_event_backend(uint16_t timeout, const uint8_t appid[FIDO_APPLICATION_PARAMETER_SIZE], const uint8_t key_handle[FIDO_KEY_HANDLE_SIZE], u2f_fido_action action, bool *existing);

bool handle_fido_event_backend(uint16_t timeout, const uint8_t appid[FIDO_APPLICATION_PARAMETER_SIZE], const uint8_t key_handle[FIDO_KEY_HANDLE_SIZE], u2f_fido_action action, bool *existing);

/*
 * Low level handlers (HW events)
 */
void exti_button_handler (void);

#endif/*HANDLERS_H_*/
