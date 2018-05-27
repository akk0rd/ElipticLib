#define MBEDTLS_BIGNUM_C

#include <stdio.h>
#include "ecp.h"
#include "bignum.h"
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

    mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP192R1 );

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
    printf("%i\n",mbedtls_mpi_self_test(0));
    printf("%i\n",mbedtls_ecp_self_test(0));
}