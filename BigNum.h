#ifndef BIGNUM_H
#define BIGNUM_H

#include <stddef.h>
#include <stdint.h>

#include <stdio.h>

typedef struct
{
    int s;              // sign of number
    size_t n;           // number of parts
    uint8_t *p;         // pointer to part
}
large_num;


#endif // BIGNUM_H