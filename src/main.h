#ifndef MAIN_H_
#define MAIN_H_

#define FIDO_DEBUG 0

#if FIDO_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif


int get_u2fpin_msq(void);

int get_storage_msq(void);

/* exported utilities */
void wink_up(void);
void wink_down(void);

#endif/*MAIN_H_*/
