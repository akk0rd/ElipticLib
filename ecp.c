#include "ecp.h"

#include <string.h>

#include <stdlib.h>
#include <stdio.h>

static unsigned long add_count, dbl_count, mul_count;

typedef enum
{
    ECP_TYPE_NONE = 0,
    ECP_TYPE_SHORT_WEIERSTRASS,    /* y^2 = x^3 + a x + b      */
    ECP_TYPE_MONTGOMERY,           /* y^2 = x^3 + a x^2 + x    */
} ecp_curve_type;

static inline ecp_curve_type ecp_get_type( const mbedtls_ecp_group *grp )
{
    if( grp->G.X.p == NULL )
        return( ECP_TYPE_NONE );

    if( grp->G.Y.p == NULL )
        return( ECP_TYPE_MONTGOMERY );
    else
        return( ECP_TYPE_SHORT_WEIERSTRASS );
}

void mbedtls_ecp_point_init( mbedtls_ecp_point *pt )
{
    if( pt == NULL )
        return;

    mbedtls_mpi_init( &pt->X );
    mbedtls_mpi_init( &pt->Y );
    mbedtls_mpi_init( &pt->Z );
}

void mbedtls_ecp_group_init( mbedtls_ecp_group *grp )
{
    if( grp == NULL )
        return;

    memset( grp, 0, sizeof( mbedtls_ecp_group ) );
}

void mbedtls_ecp_point_free( mbedtls_ecp_point *pt )
{
    if( pt == NULL )
        return;

    mbedtls_mpi_free( &( pt->X ) );
    mbedtls_mpi_free( &( pt->Y ) );
    mbedtls_mpi_free( &( pt->Z ) );
}

void mbedtls_ecp_group_free( mbedtls_ecp_group *grp )
{
    if( grp == NULL )
        return;

    if( grp->h != 1 )
    {
        mbedtls_mpi_free( &grp->P );
        mbedtls_mpi_free( &grp->A );
        mbedtls_mpi_free( &grp->B );
        mbedtls_ecp_point_free( &grp->G );
        mbedtls_mpi_free( &grp->N );
    }

    free( grp->T );
}


int mbedtls_ecp_copy( mbedtls_ecp_point *P, const mbedtls_ecp_point *Q )
{
    int ret;

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &P->X, &Q->X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &P->Y, &Q->Y ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &P->Z, &Q->Z ) );

cleanup:
    return( ret );
}

int mbedtls_ecp_set_zero( mbedtls_ecp_point *pt )
{
    int ret;

    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->X , 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->Y , 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->Z , 0 ) );

cleanup:
    return( ret );
}

static int ecp_modp( mbedtls_mpi *N, const mbedtls_ecp_group *grp )
{
    return( mbedtls_mpi_mod_mpi( N, N, &grp->P ) );
}

#if defined(MBEDTLS_SELF_TEST)
#define INC_MUL_COUNT   mul_count++;
#else
#define INC_MUL_COUNT
#endif

#define MOD_MUL( N )    do { MBEDTLS_MPI_CHK( ecp_modp( &N, grp ) ); INC_MUL_COUNT }  while( 0 )

#define MOD_SUB( N )    while( N.s < 0 && mbedtls_mpi_cmp_int( &N, 0 ) != 0 ) MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &N, &N, &grp->P ) )

#define MOD_ADD( N )    while( mbedtls_mpi_cmp_mpi( &N, &grp->P ) >= 0 ) MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( &N, &N, &grp->P ) )

static int ecp_normalize_jac( const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt )
{
    int ret;
    mbedtls_mpi Zi, ZZi;

    if( mbedtls_mpi_cmp_int( &pt->Z, 0 ) == 0 )
        return( 0 );

    mbedtls_mpi_init( &Zi ); mbedtls_mpi_init( &ZZi );

     // X = X / Z^2  mod p
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &Zi,      &pt->Z,     &grp->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ZZi,     &Zi,        &Zi     ) ); MOD_MUL( ZZi );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &pt->X,   &pt->X,     &ZZi    ) ); MOD_MUL( pt->X );

     // Y = Y / Z^3  mod p
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &pt->Y,   &pt->Y,     &ZZi    ) ); MOD_MUL( pt->Y );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &pt->Y,   &pt->Y,     &Zi     ) ); MOD_MUL( pt->Y );

    // Z = 1
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->Z, 1 ) );

cleanup:

    mbedtls_mpi_free( &Zi ); mbedtls_mpi_free( &ZZi );

    return( ret );
}


static int ecp_normalize_jac_many( const mbedtls_ecp_group *grp,
                                   mbedtls_ecp_point *T[], size_t t_len )
{
    int ret;
    size_t i;
    mbedtls_mpi *c, u, Zi, ZZi;

    if( t_len < 2 )
        return( ecp_normalize_jac( grp, *T ) );

    if( ( c = calloc( t_len, sizeof( mbedtls_mpi ) ) ) == NULL )
        return( -1 );

    mbedtls_mpi_init( &u ); mbedtls_mpi_init( &Zi ); mbedtls_mpi_init( &ZZi );

    /*
     * c[i] = Z_0 * ... * Z_i
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &c[0], &T[0]->Z ) );
    for( i = 1; i < t_len; i++ )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &c[i], &c[i-1], &T[i]->Z ) );
        MOD_MUL( c[i] );
    }

    /*
     * u = 1 / (Z_0 * ... * Z_n) mod P
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &u, &c[t_len-1], &grp->P ) );

    for( i = t_len - 1; ; i-- )
    {
        /*
         * Zi = 1 / Z_i mod p
         * u = 1 / (Z_0 * ... * Z_i) mod P
         */
        if( i == 0 ) {
            MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &Zi, &u ) );
        }
        else
        {
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &Zi, &u, &c[i-1]  ) ); MOD_MUL( Zi );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &u,  &u, &T[i]->Z ) ); MOD_MUL( u );
        }

        /*
         * proceed as in normalize()
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ZZi,     &Zi,      &Zi  ) ); MOD_MUL( ZZi );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T[i]->X, &T[i]->X, &ZZi ) ); MOD_MUL( T[i]->X );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T[i]->Y, &T[i]->Y, &ZZi ) ); MOD_MUL( T[i]->Y );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T[i]->Y, &T[i]->Y, &Zi  ) ); MOD_MUL( T[i]->Y );

        /*
         * Post-precessing: reclaim some memory by shrinking coordinates
         * - not storing Z (always 1)
         * - shrinking other coordinates, but still keeping the same number of
         *   limbs as P, as otherwise it will too likely be regrown too fast.
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( &T[i]->X, grp->P.n ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( &T[i]->Y, grp->P.n ) );
        mbedtls_mpi_free( &T[i]->Z );

        if( i == 0 )
            break;
    }

cleanup:

    mbedtls_mpi_free( &u ); mbedtls_mpi_free( &Zi ); mbedtls_mpi_free( &ZZi );
    for( i = 0; i < t_len; i++ )
        mbedtls_mpi_free( &c[i] );
    free( c );

    return( ret );
}

/*
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid
 */
static int ecp_safe_invert_jac( const mbedtls_ecp_group *grp,
                            mbedtls_ecp_point *Q,
                            unsigned char inv )
{
    int ret;
    unsigned char nonzero;
    mbedtls_mpi mQY;

    mbedtls_mpi_init( &mQY );

    /* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &mQY, &grp->P, &Q->Y ) );
    nonzero = mbedtls_mpi_cmp_int( &Q->Y, 0 ) != 0;
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &Q->Y, &mQY, inv & nonzero ) );

cleanup:
    mbedtls_mpi_free( &mQY );

    return( ret );
}

static int ecp_double_jac( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                           const mbedtls_ecp_point *P )
{
    int ret;
    mbedtls_mpi M, S, T, U;

#if defined(MBEDTLS_SELF_TEST)
    dbl_count++;
#endif

    mbedtls_mpi_init( &M ); mbedtls_mpi_init( &S ); mbedtls_mpi_init( &T ); mbedtls_mpi_init( &U );

    // A = -3 
    if( grp->A.p == NULL )
    {
        // M = 3(X + Z^2)(X - Z^2)
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S,  &P->Z,  &P->Z   ) ); MOD_MUL( S );
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &T,  &P->X,  &S      ) ); MOD_ADD( T );
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &U,  &P->X,  &S      ) ); MOD_SUB( U );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S,  &T,     &U      ) ); MOD_MUL( S );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( &M,  &S,     3       ) ); MOD_ADD( M );
    }
    else
    {
        // M = 3.X^2
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S,  &P->X,  &P->X   ) ); MOD_MUL( S );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( &M,  &S,     3       ) ); MOD_ADD( M );

        /* Optimize away for "koblitz" curves with A = 0 */
        if( mbedtls_mpi_cmp_int( &grp->A, 0 ) != 0 )
        {
            /* M += A.Z^4 */
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S,  &P->Z,  &P->Z   ) ); MOD_MUL( S );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T,  &S,     &S      ) ); MOD_MUL( T );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S,  &T,     &grp->A ) ); MOD_MUL( S );
            MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &M,  &M,     &S      ) ); MOD_ADD( M );
        }
    }

    /* S = 4.X.Y^2 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T,  &P->Y,  &P->Y   ) ); MOD_MUL( T );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &T,  1               ) ); MOD_ADD( T );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S,  &P->X,  &T      ) ); MOD_MUL( S );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &S,  1               ) ); MOD_ADD( S );

    /* U = 8.Y^4 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &U,  &T,     &T      ) ); MOD_MUL( U );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &U,  1               ) ); MOD_ADD( U );

    /* T = M^2 - 2.S */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T,  &M,     &M      ) ); MOD_MUL( T );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T,  &T,     &S      ) ); MOD_SUB( T );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T,  &T,     &S      ) ); MOD_SUB( T );

    /* S = M(S - T) - U */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &S,  &S,     &T      ) ); MOD_SUB( S );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S,  &S,     &M      ) ); MOD_MUL( S );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &S,  &S,     &U      ) ); MOD_SUB( S );

    /* U = 2.Y.Z */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &U,  &P->Y,  &P->Z   ) ); MOD_MUL( U );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &U,  1               ) ); MOD_ADD( U );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->X, &T ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Y, &S ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Z, &U ) );

cleanup:
    mbedtls_mpi_free( &M ); mbedtls_mpi_free( &S ); mbedtls_mpi_free( &T ); mbedtls_mpi_free( &U );

    return( ret );
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Special cases: (1) P or Q is zero, (2) R is zero, (3) P == Q.
 * None of these cases can happen as intermediate step in ecp_mul_comb():
 * - at each step, P, Q and R are multiples of the base point, the factor
 *   being less than its order, so none of them is zero;
 * - Q is an odd multiple of the base point, P an even multiple,
 *   due to the choice of precomputed points in the modified comb method.
 * So branches for these cases do not leak secret information.
 *
 * We accept Q->Z being unset (saving memory in tables) as meaning 1.
 *
 * Cost: 1A := 8M + 3S
 */
static int ecp_add_mixed( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                          const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q )
{
    int ret;
    mbedtls_mpi T1, T2, T3, T4, X, Y, Z;

#if defined(MBEDTLS_SELF_TEST)
    add_count++;
#endif

    /*
     * Trivial cases: P == 0 or Q == 0 (case 1)
     */
    if( mbedtls_mpi_cmp_int( &P->Z, 0 ) == 0 )
        return( mbedtls_ecp_copy( R, Q ) );

    if( Q->Z.p != NULL && mbedtls_mpi_cmp_int( &Q->Z, 0 ) == 0 )
        return( mbedtls_ecp_copy( R, P ) );

    /*
     * Make sure Q coordinates are normalized
     */
    if( Q->Z.p != NULL && mbedtls_mpi_cmp_int( &Q->Z, 1 ) != 0 )
        return( -1 );

    mbedtls_mpi_init( &T1 ); mbedtls_mpi_init( &T2 ); mbedtls_mpi_init( &T3 ); mbedtls_mpi_init( &T4 );
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T1,  &P->Z,  &P->Z ) );  MOD_MUL( T1 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T2,  &T1,    &P->Z ) );  MOD_MUL( T2 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T1,  &T1,    &Q->X ) );  MOD_MUL( T1 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T2,  &T2,    &Q->Y ) );  MOD_MUL( T2 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T1,  &T1,    &P->X ) );  MOD_SUB( T1 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T2,  &T2,    &P->Y ) );  MOD_SUB( T2 );

    if( mbedtls_mpi_cmp_int( &T1, 0 ) == 0 )
    {
        if( mbedtls_mpi_cmp_int( &T2, 0 ) == 0 )
        {
            ret = ecp_double_jac( grp, R, P );
            goto cleanup;
        }
        else
        {
            ret = mbedtls_ecp_set_zero( R );
            goto cleanup;
        }
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &Z,   &P->Z,  &T1   ) );  MOD_MUL( Z  );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T3,  &T1,    &T1   ) );  MOD_MUL( T3 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T4,  &T3,    &T1   ) );  MOD_MUL( T4 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T3,  &T3,    &P->X ) );  MOD_MUL( T3 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( &T1,  &T3,    2     ) );  MOD_ADD( T1 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &X,   &T2,    &T2   ) );  MOD_MUL( X  );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &X,   &X,     &T1   ) );  MOD_SUB( X  );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &X,   &X,     &T4   ) );  MOD_SUB( X  );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T3,  &T3,    &X    ) );  MOD_SUB( T3 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T3,  &T3,    &T2   ) );  MOD_MUL( T3 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T4,  &T4,    &P->Y ) );  MOD_MUL( T4 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &Y,   &T3,    &T4   ) );  MOD_SUB( Y  );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->X, &X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Y, &Y ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Z, &Z ) );

cleanup:

    mbedtls_mpi_free( &T1 ); mbedtls_mpi_free( &T2 ); mbedtls_mpi_free( &T3 ); mbedtls_mpi_free( &T4 );
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z );

    return( ret );
}

/*
 * Check and define parameters used by the comb method (see below for details)
 */
#if MBEDTLS_ECP_WINDOW_SIZE < 2 || MBEDTLS_ECP_WINDOW_SIZE > 7
#error "MBEDTLS_ECP_WINDOW_SIZE out of bounds"
#endif

/* d = ceil( n / w ) */
#define COMB_MAX_D      ( MBEDTLS_ECP_MAX_BITS + 1 ) / 2

/* number of precomputed points */
#define COMB_MAX_PRE    ( 1 << ( MBEDTLS_ECP_WINDOW_SIZE - 1 ) )

/*
 * Compute the representation of m that will be used with our comb method.
 *
 * The basic comb method is described in GECC 3.44 for example. We use a
 * modified version that provides resistance to SPA by avoiding zero
 * digits in the representation as in [3]. We modify the method further by
 * requiring that all K_i be odd, which has the small cost that our
 * representation uses one more K_i, due to carries.
 *
 * Also, for the sake of compactness, only the seven low-order bits of x[i]
 * are used to represent K_i, and the msb of x[i] encodes the the sign (s_i in
 * the paper): it is set if and only if if s_i == -1;
 *
 * Calling conventions:
 * - x is an array of size d + 1
 * - w is the size, ie number of teeth, of the comb, and must be between
 *   2 and 7 (in practice, between 2 and MBEDTLS_ECP_WINDOW_SIZE)
 * - m is the MPI, expected to be odd and such that bitlength(m) <= w * d
 *   (the result will be incorrect if these assumptions are not satisfied)
 */
static void ecp_comb_fixed( unsigned char x[], size_t d,
                            unsigned char w, const mbedtls_mpi *m )
{
    size_t i, j;
    unsigned char c, cc, adjust;

    memset( x, 0, d+1 );

    /* First get the classical comb values (except for x_d = 0) */
    for( i = 0; i < d; i++ )
        for( j = 0; j < w; j++ )
            x[i] |= mbedtls_mpi_get_bit( m, i + d * j ) << j;

    /* Now make sure x_1 .. x_d are odd */
    c = 0;
    for( i = 1; i <= d; i++ )
    {
        /* Add carry and update it */
        cc   = x[i] & c;
        x[i] = x[i] ^ c;
        c = cc;

        /* Adjust if needed, avoiding branches */
        adjust = 1 - ( x[i] & 0x01 );
        c   |= x[i] & ( x[i-1] * adjust );
        x[i] = x[i] ^ ( x[i-1] * adjust );
        x[i-1] |= adjust << 7;
    }
}

static int ecp_precompute_comb( const mbedtls_ecp_group *grp,
                                mbedtls_ecp_point T[], const mbedtls_ecp_point *P,
                                unsigned char w, size_t d )
{
    int ret;
    unsigned char i, k;
    size_t j;
    mbedtls_ecp_point *cur, *TT[COMB_MAX_PRE - 1];

    MBEDTLS_MPI_CHK( mbedtls_ecp_copy( &T[0], P ) );

    k = 0;
    for( i = 1; i < ( 1U << ( w - 1 ) ); i <<= 1 )
    {
        cur = T + i;
        MBEDTLS_MPI_CHK( mbedtls_ecp_copy( cur, T + ( i >> 1 ) ) );
        for( j = 0; j < d; j++ )
            MBEDTLS_MPI_CHK( ecp_double_jac( grp, cur, cur ) );

        TT[k++] = cur;
    }

    MBEDTLS_MPI_CHK( ecp_normalize_jac_many( grp, TT, k ) );

    k = 0;
    for( i = 1; i < ( 1U << ( w - 1 ) ); i <<= 1 )
    {
        j = i;
        while( j-- )
        {
            MBEDTLS_MPI_CHK( ecp_add_mixed( grp, &T[i + j], &T[j], &T[i] ) );
            TT[k++] = &T[i + j];
        }
    }

    MBEDTLS_MPI_CHK( ecp_normalize_jac_many( grp, TT, k ) );

cleanup:
    return( ret );
}

static int ecp_select_comb( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                            const mbedtls_ecp_point T[], unsigned char t_len,
                            unsigned char i )
{
    int ret;
    unsigned char ii, j;

    ii =  ( i & 0x7Fu ) >> 1;

    /* Read the whole table to thwart cache-based timing attacks */
    for( j = 0; j < t_len; j++ )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &R->X, &T[j].X, j == ii ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &R->Y, &T[j].Y, j == ii ) );
    }

    /* Safely invert result if i is "negative" */
    MBEDTLS_MPI_CHK( ecp_safe_invert_jac( grp, R, i >> 7 ) );

cleanup:
    return( ret );
}

/*
 * Core multiplication algorithm for the (modified) comb method.
 * This part is actually common with the basic comb method (GECC 3.44)
 *
 * Cost: d A + d D + 1 R
 */
static int ecp_mul_comb_core( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                              const mbedtls_ecp_point T[], unsigned char t_len,
                              const unsigned char x[], size_t d)
{
    int ret;
    mbedtls_ecp_point Txi;
    size_t i;

    mbedtls_ecp_point_init( &Txi );

    /* Start with a non-zero point and randomize its coordinates */
    i = d;
    MBEDTLS_MPI_CHK( ecp_select_comb( grp, R, T, t_len, x[i] ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->Z, 1 ) );

    while( i-- != 0 )
    {
        MBEDTLS_MPI_CHK( ecp_double_jac( grp, R, R ) );
        MBEDTLS_MPI_CHK( ecp_select_comb( grp, &Txi, T, t_len, x[i] ) );
        MBEDTLS_MPI_CHK( ecp_add_mixed( grp, R, R, &Txi ) );
    }

cleanup:
    mbedtls_ecp_point_free( &Txi );

    return( ret );
}

/*
 * Multiplication using the comb method,
 * for curves in short Weierstrass form
 */
static int ecp_mul_comb( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         const mbedtls_mpi *m, const mbedtls_ecp_point *P )
{
    int ret;
    unsigned char w, m_is_odd, p_eq_g, pre_len, i;
    size_t d;
    unsigned char k[COMB_MAX_D + 1];
    mbedtls_ecp_point *T;
    mbedtls_mpi M, mm;

    mbedtls_mpi_init( &M );
    mbedtls_mpi_init( &mm );

    /* we need N to be odd to trnaform m in an odd number, check now */
    if( mbedtls_mpi_get_bit( &grp->N, 0 ) != 1 )
        return( -1 );

    /*
     * Minimize the number of multiplications, that is minimize
     * 10 * d * w + 18 * 2^(w-1) + 11 * d + 7 * w, with d = ceil( nbits / w )
     * (see costs of the various parts, with 1S = 1M)
     */
    w = grp->nbits >= 384 ? 5 : 4;

    /*
     * If P == G, pre-compute a bit more, since this may be re-used later.
     * Just adding one avoids upping the cost of the first mul too much,
     * and the memory cost too.
     */
    p_eq_g = 0;


    /*
     * Make sure w is within bounds.
     * (The last test is useful only for very small curves in the test suite.)
     */
    if( w > MBEDTLS_ECP_WINDOW_SIZE )
        w = MBEDTLS_ECP_WINDOW_SIZE;
    if( w >= grp->nbits )
        w = 2;

    /* Other sizes that depend on w */
    pre_len = 1U << ( w - 1 );
    d = ( grp->nbits + w - 1 ) / w;

    /*
     * Prepare precomputed points: if P == G we want to
     * use grp->T if already initialized, or initialize it.
     */
    T = p_eq_g ? grp->T : NULL;

    if( T == NULL )
    {
        T = calloc( pre_len, sizeof( mbedtls_ecp_point ) );
        if( T == NULL )
        {
            ret = -1;
            goto cleanup;
        }

        MBEDTLS_MPI_CHK( ecp_precompute_comb( grp, T, P, w, d ) );

        if( p_eq_g )
        {
            grp->T = T;
            grp->T_size = pre_len;
        }
    }

    /*
     * Make sure M is odd (M = m or M = N - m, since N is odd)
     * using the fact that m * P = - (N - m) * P
     */
    m_is_odd = ( mbedtls_mpi_get_bit( m, 0 ) == 1 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &M, m ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &mm, &grp->N, m ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &M, &mm, ! m_is_odd ) );

    /*
     * Go for comb multiplication, R = M * P
     */
    ecp_comb_fixed( k, d, w, &M );
    MBEDTLS_MPI_CHK( ecp_mul_comb_core( grp, R, T, pre_len, k, d) );

    /*
     * Now get m * P from M * P and normalize it
     */
    MBEDTLS_MPI_CHK( ecp_safe_invert_jac( grp, R, ! m_is_odd ) );
    MBEDTLS_MPI_CHK( ecp_normalize_jac( grp, R ) );

cleanup:

    if( T != NULL && ! p_eq_g )
    {
        for( i = 0; i < pre_len; i++ )
            mbedtls_ecp_point_free( &T[i] );
        free( T );
    }

    mbedtls_mpi_free( &M );
    mbedtls_mpi_free( &mm );

    if( ret != 0 )
        mbedtls_ecp_point_free( R );

    return( ret );
}

/*
 * For Montgomery curves, we do all the internal arithmetic in projective
 * coordinates. Import/export of points uses only the x coordinates, which is
 * internaly represented as X / Z.
 *
 * For scalar multiplication, we'll use a Montgomery ladder.
 */

/*
 * Normalize Montgomery x/z coordinates: X = X/Z, Z = 1
 * Cost: 1M + 1I
 */
static int ecp_normalize_mxz( const mbedtls_ecp_group *grp, mbedtls_ecp_point *P )
{
    int ret;

    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &P->Z, &P->Z, &grp->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &P->X, &P->X, &P->Z ) ); MOD_MUL( P->X );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &P->Z, 1 ) );

cleanup:
    return( ret );
}

/*
 * Double-and-add: R = 2P, S = P + Q, with d = X(P - Q),
 * for Montgomery curves in x/z coordinates.
 *
 * http://www.hyperelliptic.org/EFD/g1p/auto-code/montgom/xz/ladder/mladd-1987-m.op3
 * with
 * d =  X1
 * P = (X2, Z2)
 * Q = (X3, Z3)
 * R = (X4, Z4)
 * S = (X5, Z5)
 * and eliminating temporary variables tO, ..., t4.
 *
 * Cost: 5M + 4S
 */
static int ecp_double_add_mxz( const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *R, mbedtls_ecp_point *S,
                               const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q,
                               const mbedtls_mpi *d )
{
    int ret;
    mbedtls_mpi A, AA, B, BB, E, C, D, DA, CB;

    mbedtls_mpi_init( &A ); mbedtls_mpi_init( &AA ); mbedtls_mpi_init( &B );
    mbedtls_mpi_init( &BB ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &C );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &DA ); mbedtls_mpi_init( &CB );

    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &A,    &P->X,   &P->Z ) ); MOD_ADD( A    );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &AA,   &A,      &A    ) ); MOD_MUL( AA   );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &B,    &P->X,   &P->Z ) ); MOD_SUB( B    );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &BB,   &B,      &B    ) ); MOD_MUL( BB   );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &E,    &AA,     &BB   ) ); MOD_SUB( E    );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &C,    &Q->X,   &Q->Z ) ); MOD_ADD( C    );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &D,    &Q->X,   &Q->Z ) ); MOD_SUB( D    );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &DA,   &D,      &A    ) ); MOD_MUL( DA   );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &CB,   &C,      &B    ) ); MOD_MUL( CB   );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &S->X, &DA,     &CB   ) ); MOD_MUL( S->X );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S->X, &S->X,   &S->X ) ); MOD_MUL( S->X );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &S->Z, &DA,     &CB   ) ); MOD_SUB( S->Z );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S->Z, &S->Z,   &S->Z ) ); MOD_MUL( S->Z );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S->Z, d,       &S->Z ) ); MOD_MUL( S->Z );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &R->X, &AA,     &BB   ) ); MOD_MUL( R->X );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &R->Z, &grp->A, &E    ) ); MOD_MUL( R->Z );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &R->Z, &BB,     &R->Z ) ); MOD_ADD( R->Z );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &R->Z, &E,      &R->Z ) ); MOD_MUL( R->Z );

cleanup:
    mbedtls_mpi_free( &A ); mbedtls_mpi_free( &AA ); mbedtls_mpi_free( &B );
    mbedtls_mpi_free( &BB ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &C );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &DA ); mbedtls_mpi_free( &CB );

    return( ret );
}

/*
 * Multiplication with Montgomery ladder in x/z coordinates,
 * for curves in Montgomery form
 */
static int ecp_mul_mxz( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P )
{
    int ret;
    size_t i;
    unsigned char b;
    mbedtls_ecp_point RP;
    mbedtls_mpi PX;

    mbedtls_ecp_point_init( &RP ); mbedtls_mpi_init( &PX );

    /* Save PX and read from P before writing to R, in case P == R */
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &PX, &P->X ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_copy( &RP, P ) );

    /* Set R to zero in modified x/z coordinates */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->X, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->Z, 0 ) );
    mbedtls_mpi_free( &R->Y );

    /* RP.X might be sligtly larger than P, so reduce it */
    MOD_ADD( RP.X );

    /* Loop invariant: R = result so far, RP = R + P */
    i = mbedtls_mpi_bitlen( m ); /* one past the (zero-based) most significant bit */
    while( i-- > 0 )
    {
        b = mbedtls_mpi_get_bit( m, i );
        /*
         *  if (b) R = 2R + P else R = 2R,
         * which is:
         *  if (b) double_add( RP, R, RP, R )
         *  else   double_add( R, RP, R, RP )
         * but using safe conditional swaps to avoid leaks
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_swap( &R->X, &RP.X, b ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_swap( &R->Z, &RP.Z, b ) );
        MBEDTLS_MPI_CHK( ecp_double_add_mxz( grp, R, &RP, R, &RP, &PX ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_swap( &R->X, &RP.X, b ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_swap( &R->Z, &RP.Z, b ) );
    }

    MBEDTLS_MPI_CHK( ecp_normalize_mxz( grp, R ) );

cleanup:
    mbedtls_ecp_point_free( &RP ); mbedtls_mpi_free( &PX );

    return( ret );
}

/*
 * Multiplication R = m * P
 */
int mbedtls_ecp_mul( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
             const mbedtls_mpi *m, const mbedtls_ecp_point *P)
{
    int ret;

    if( ecp_get_type( grp ) == ECP_TYPE_MONTGOMERY )
        return( ecp_mul_mxz( grp, R, m, P) );

    if( ecp_get_type( grp ) == ECP_TYPE_SHORT_WEIERSTRASS )
        return( ecp_mul_comb( grp, R, m, P) );
    return( -1 );
}

/*
 * Checkup routine
 */
int mbedtls_ecp_self_test( int verbose )
{
    int ret;
    size_t i;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, P;
    mbedtls_mpi m;
    unsigned long add_c_prev, dbl_c_prev, mul_c_prev;
    /* exponents especially adapted for secp192r1 */
    const char *exponents[] =
    {
        "000000000000000000000000000000000000000000000001", /* one */
        "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22830", /* N - 1 */
        "5EA6F389A38B8BC81E767753B15AA5569E1782E30ABE7D25", /* random */
        "400000000000000000000000000000000000000000000000", /* one and zeros */
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", /* all ones */
        "555555555555555555555555555555555555555555555555", /* 101010... */
    };

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &R );
    mbedtls_ecp_point_init( &P );
    mbedtls_mpi_init( &m );

    mbedtls_ecp_group_load( &grp);

    if( verbose != 0 )
        printf( "  ECP test #1 (constant op_count, base point G): " );

    /* Do a dummy multiplication first to trigger precomputation */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &m, 2 ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &grp, &P, &m, &grp.G) );

    add_count = 0;
    dbl_count = 0;
    mul_count = 0;
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &m, 16, exponents[0] ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &grp, &R, &m, &grp.G ) );

    for( i = 1; i < sizeof( exponents ) / sizeof( exponents[0] ); i++ )
    {
        add_c_prev = add_count;
        dbl_c_prev = dbl_count;
        mul_c_prev = mul_count;
        add_count = 0;
        dbl_count = 0;
        mul_count = 0;

        MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &m, 16, exponents[i] ) );
        MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &grp, &R, &m, &grp.G ) );

        if( add_count != add_c_prev ||
            dbl_count != dbl_c_prev ||
            mul_count != mul_c_prev )
        {
            if( verbose != 0 )
                printf( "failed (%u)\n", (unsigned int) i );

            ret = 1;
            goto cleanup;
        }
    }

    if( verbose != 0 )
        printf( "passed\n" );

    if( verbose != 0 )
        printf( "  ECP test #2 (constant op_count, other point): " );
    /* We computed P = 2G last time, use it */

    add_count = 0;
    dbl_count = 0;
    mul_count = 0;
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &m, 16, exponents[0] ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &grp, &R, &m, &P ) );

    for( i = 1; i < sizeof( exponents ) / sizeof( exponents[0] ); i++ )
    {
        add_c_prev = add_count;
        dbl_c_prev = dbl_count;
        mul_c_prev = mul_count;
        add_count = 0;
        dbl_count = 0;
        mul_count = 0;

        MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &m, 16, exponents[i] ) );
        MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &grp, &R, &m, &P ) );

        if( add_count != add_c_prev ||
            dbl_count != dbl_c_prev ||
            mul_count != mul_c_prev )
        {
            if( verbose != 0 )
                printf( "failed (%u)\n", (unsigned int) i );

            ret = 1;
            goto cleanup;
        }
    }

    if( verbose != 0 )
        printf( "passed\n" );

cleanup:

    if( ret < 0 && verbose != 0 )
        printf( "Unexpected error, return code = %08X\n", ret );

    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &R );
    mbedtls_ecp_point_free( &P );
    mbedtls_mpi_free( &m );

    if( verbose != 0 )
        printf( "\n" );

    return( ret );
}
