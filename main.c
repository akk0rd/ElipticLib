#define MBEDTLS_BIGNUM_C

#include <stdio.h>
#include "bignum.h"

int main()
{
    printf("%i",mbedtls_mpi_self_test(0));
}