#define MBEDTLS_BIGNUM_C

#include <stdio.h>
#include "ecp.h"
#include "bignum.h"

#define BYTES_TO_T_UINT_8( a, b, c, d, e, f, g, h ) \
    ( (mbedtls_mpi_uint) a <<  0 ) |                          \
    ( (mbedtls_mpi_uint) b <<  8 ) |                          \
    ( (mbedtls_mpi_uint) c << 16 ) |                          \
    ( (mbedtls_mpi_uint) d << 24 ) |                          \
    ( (mbedtls_mpi_uint) e << 32 ) |                          \
    ( (mbedtls_mpi_uint) f << 40 ) |                          \
    ( (mbedtls_mpi_uint) g << 48 ) |                          \
    ( (mbedtls_mpi_uint) h << 56 )

#define BYTES_TO_T_UINT_4( a, b, c, d )             \
    BYTES_TO_T_UINT_8( a, b, c, d, 0, 0, 0, 0 )

#define BYTES_TO_T_UINT_2( a, b )                   \
    BYTES_TO_T_UINT_8( a, b, 0, 0, 0, 0, 0, 0 )

static const mbedtls_mpi_uint secp192r1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp192r1_b[] = {
    BYTES_TO_T_UINT_8( 0xB1, 0xB9, 0x46, 0xC1, 0xEC, 0xDE, 0xB8, 0xFE ),
    BYTES_TO_T_UINT_8( 0x49, 0x30, 0x24, 0x72, 0xAB, 0xE9, 0xA7, 0x0F ),
    BYTES_TO_T_UINT_8( 0xE7, 0x80, 0x9C, 0xE5, 0x19, 0x05, 0x21, 0x64 ),
};
static const mbedtls_mpi_uint secp192r1_gx[] = {
    BYTES_TO_T_UINT_8( 0x12, 0x10, 0xFF, 0x82, 0xFD, 0x0A, 0xFF, 0xF4 ),
    BYTES_TO_T_UINT_8( 0x00, 0x88, 0xA1, 0x43, 0xEB, 0x20, 0xBF, 0x7C ),
    BYTES_TO_T_UINT_8( 0xF6, 0x90, 0x30, 0xB0, 0x0E, 0xA8, 0x8D, 0x18 ),
};
static const mbedtls_mpi_uint secp192r1_gy[] = {
    BYTES_TO_T_UINT_8( 0x11, 0x48, 0x79, 0x1E, 0xA1, 0x77, 0xF9, 0x73 ),
    BYTES_TO_T_UINT_8( 0xD5, 0xCD, 0x24, 0x6B, 0xED, 0x11, 0x10, 0x63 ),
    BYTES_TO_T_UINT_8( 0x78, 0xDA, 0xC8, 0xFF, 0x95, 0x2B, 0x19, 0x07 ),
};
static const mbedtls_mpi_uint secp192r1_n[] = {
    BYTES_TO_T_UINT_8( 0x31, 0x28, 0xD2, 0xB4, 0xB1, 0xC9, 0x6B, 0x14 ),
    BYTES_TO_T_UINT_8( 0x36, 0xF8, 0xDE, 0x99, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};

/*
 * Create an MPI from embedded constants
 * (assumes len is an exact multiple of sizeof mbedtls_mpi_uint)
 */
static inline void ecp_mpi_load( mbedtls_mpi *X, const mbedtls_mpi_uint *p, size_t len )
{
    X->s = 1;
    X->n = len / sizeof( mbedtls_mpi_uint );
    X->p = (mbedtls_mpi_uint *) p;
}

/*
 * Set an MPI to static value 1
 */
static inline void ecp_mpi_set1( mbedtls_mpi *X )
{
    static mbedtls_mpi_uint one[] = { 1 };
    X->s = 1;
    X->n = 1;
    X->p = one;
}

/*
 * Make group available from embedded constants
 */
static int ecp_group_load( mbedtls_ecp_group *grp,
                           const mbedtls_mpi_uint *p,  size_t plen,
                           const mbedtls_mpi_uint *a,  size_t alen,
                           const mbedtls_mpi_uint *b,  size_t blen,
                           const mbedtls_mpi_uint *gx, size_t gxlen,
                           const mbedtls_mpi_uint *gy, size_t gylen,
                           const mbedtls_mpi_uint *n,  size_t nlen)
{
    ecp_mpi_load( &grp->P, p, plen );
    if( a != NULL )
        ecp_mpi_load( &grp->A, a, alen );
    ecp_mpi_load( &grp->B, b, blen );
    ecp_mpi_load( &grp->N, n, nlen );

    ecp_mpi_load( &grp->G.X, gx, gxlen );
    ecp_mpi_load( &grp->G.Y, gy, gylen );
    ecp_mpi_set1( &grp->G.Z );

    grp->pbits = mbedtls_mpi_bitlen( &grp->P );
    grp->nbits = mbedtls_mpi_bitlen( &grp->N );

    grp->h = 1;

    return( 0 );
}
/**
 * Gx = 188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
 * Gy = 07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
 * Gz = 01
 * P  = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
 * A 
 * B  = 64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
 * 
 * 
 */

int mest( int verbose )
{
    
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_mpi m;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &P );
    mbedtls_mpi_init( &m );

    ecp_group_load(&grp,
                secp192r1_p, sizeof(secp192r1_p),
                NULL, 0,
                secp192r1_b, sizeof(secp192r1_b),
                secp192r1_gx, sizeof(secp192r1_gx),
                secp192r1_gy, sizeof(secp192r1_gy),
                secp192r1_n, sizeof(secp192r1_n)
                 );

    mbedtls_mpi_lset( &m, 2 );
    mbedtls_ecp_mul( &grp, &P, &m, &grp.G, NULL, NULL );

    mbedtls_mpi_write_file(NULL, &P.X, 16, NULL );
    mbedtls_mpi_write_file(NULL, &P.Y, 16, NULL );
    mbedtls_mpi_write_file(NULL, &P.Z, 16, NULL );
    //mbedtls_mpi_write_file(NULL, &grp.G.X, 16, NULL );
    //mbedtls_mpi_write_file(NULL, &grp.G.Y, 16, NULL );
    //mbedtls_mpi_write_file(NULL, &grp.G.Z, 16, NULL );
    //mbedtls_mpi_write_file(NULL, &grp.P, 16, NULL );
    //mbedtls_mpi_write_file(NULL, &grp.A, 16, NULL );
    //mbedtls_mpi_write_file(NULL, &grp.B, 16, NULL );
    //mbedtls_mpi_write_file(NULL, &grp.N, 16, NULL );

    return( 0 );
}


int main()
{
    //printf("%i",mest(0));
    //printf("%i\n",mbedtls_mpi_self_test(0));
    printf("%i\n",mbedtls_ecp_self_test(0));
}