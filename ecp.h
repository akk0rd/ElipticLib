#ifndef MBEDTLS_ECP_H
#define MBEDTLS_ECP_H
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_SELF_TEST
#include "bignum.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    mbedtls_mpi X;          /*!<  the point's X coordinate  */
    mbedtls_mpi Y;          /*!<  the point's Y coordinate  */
    mbedtls_mpi Z;          /*!<  the point's Z coordinate  */
}
mbedtls_ecp_point;

typedef struct
{
    mbedtls_mpi P;              /*!<  prime modulus of the base field               */
    mbedtls_mpi A;              /*!<  1. A in the equation, or 2. (A + 2) / 4       */
    mbedtls_mpi B;              /*!<  1. B in the equation, or 2. unused            */
    mbedtls_ecp_point G;        /*!<  generator of the (sub)group used              */
    mbedtls_mpi N;              /*!<  1. the order of G, or 2. unused               */
    size_t pbits;       /*!<  number of bits in P                           */
    size_t nbits;       /*!<  number of bits in 1. P, or 2. private keys    */
    unsigned int h;     /*!<  internal: 1 if the constants are static       */
    int (*modp)(mbedtls_mpi *); /*!<  function for fast reduction mod P             */
    mbedtls_ecp_point *T;       /*!<  pre-computed points for ecp_mul_comb()        */
    size_t T_size;      /*!<  number for pre-computed points                */
}
mbedtls_ecp_group;

#if !defined(MBEDTLS_ECP_MAX_BITS)
#define MBEDTLS_ECP_MAX_BITS     521   /**< Maximum bit size of groups */
#endif

#if !defined(MBEDTLS_ECP_WINDOW_SIZE)
#define MBEDTLS_ECP_WINDOW_SIZE    6 
#endif 

void mbedtls_ecp_point_init( mbedtls_ecp_point *pt );

void mbedtls_ecp_group_init( mbedtls_ecp_group *grp );

void mbedtls_ecp_point_free( mbedtls_ecp_point *pt );

void mbedtls_ecp_group_free( mbedtls_ecp_group *grp );

int mbedtls_ecp_copy( mbedtls_ecp_point *P, const mbedtls_ecp_point *Q );

int mbedtls_ecp_group_copy( mbedtls_ecp_group *dst, const mbedtls_ecp_group *src );

int mbedtls_ecp_set_zero( mbedtls_ecp_point *pt );

int mbedtls_ecp_group_load( mbedtls_ecp_group *grp );

int mbedtls_ecp_mul( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
             const mbedtls_mpi *m, const mbedtls_ecp_point *P);

int mbedtls_ecp_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* ecp.h */
