#ifndef MASKS_ON_OFF_H
#define MASKS_ON_OFF_H

#include <stdint.h>
#include <libopencm3/stm32/rng.h>
#include <stdbool.h>

uint32_t random_uint32_(void);
#define random_uint32() (rng_get_random_blocking())
#define random_uint64() (((uint64_t)rng_get_random_blocking()) | ((uint64_t)rng_get_random_blocking()) << 32)


#endif