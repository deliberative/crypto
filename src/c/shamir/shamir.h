#ifndef split_H
#define split_H

#include <stddef.h>
#include <stdint.h>

#define FIELD 256

int interpolate(const size_t SHARES_LEN, const uint8_t points[SHARES_LEN * 2]);

int evaluate(const size_t threshold, const uint8_t coefficients[threshold],
             const int x);

#endif
