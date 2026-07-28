#ifndef XUBE_MODULES_CRYPTO_THREADING_ALT_H
#define XUBE_MODULES_CRYPTO_THREADING_ALT_H

#include <zephyr/kernel.h>

typedef struct k_mutex mbedtls_platform_mutex_t;
typedef struct k_condvar mbedtls_platform_condition_variable_t;

#endif