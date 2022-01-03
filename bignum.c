/*
 *  Multi-precision integer library
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  This MPI implementation is based on:
 *
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf
 *  http://www.stillhq.com/extracted/gnupg-api/mpi/
 *  http://math.libtomcrypt.com/files/tommath.pdf
 */

#include "polarssl/config.h"

#if defined(POLARSSL_BIGNUM_C)

#include "polarssl/bignum.h"
#include "polarssl/bn_mul.h"

//#include <gnuk-malloc.h>
#include <stdlib.h>

#define ciL    (sizeof(t_uint))         /* chars in limb  */
#define biL    (ciL << 3)               /* bits  in limb  */
#define biH    (ciL << 2)               /* half limb size */

/*
 * Convert between bits/chars and number of limbs
 */
#define BITS_TO_LIMBS(i)  (((i) + biL - 1) / biL)
#define CHARS_TO_LIMBS(i) (((i) + ciL - 1) / ciL)

/*
 * Initialize one MPI
 */
void mpi_init( mpi *X )
{
    if( X == NULL )
        return;

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Unallocate one MPI
 */
void mpi_free( mpi *X )
{
    if( X == NULL )
        return;

    if( X->p != NULL )
    {
        memset( X->p, 0, X->n * ciL );
        free( X->p );
    }

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Enlarge to the specified number of limbs
 */
int mpi_grow( mpi *X, size_t nblimbs )
{
    t_uint *p;

    if( nblimbs > POLARSSL_MPI_MAX_LIMBS )
        return( POLARSSL_ERR_MPI_MALLOC_FAILED );

    if( X->n < nblimbs )
    {
        if( ( p = (t_uint *) malloc( nblimbs * ciL ) ) == NULL )
            return( POLARSSL_ERR_MPI_MALLOC_FAILED );

        memset( p, 0, nblimbs * ciL );

        if( X->p != NULL )
        {
            memcpy( p, X->p, X->n * ciL );
            memset( X->p, 0, X->n * ciL );
            free( X->p );
        }

        X->n = nblimbs;
        X->p = p;
    }

    return( 0 );
}

/*
 * Copy the contents of Y into X
 */
int mpi_copy( mpi *X, const mpi *Y )
{
    int ret;
    size_t i;

    if( X == Y )
        return( 0 );

    for( i = Y->n - 1; i > 0; i-- )
        if( Y->p[i] != 0 )
            break;
    i++;

    X->s = Y->s;

    MPI_CHK( mpi_grow( X, i ) );

    memset( X->p, 0, X->n * ciL );
    memcpy( X->p, Y->p, i * ciL );

cleanup:

    return( ret );
}

/*
 * Swap the contents of X and Y
 */
void mpi_swap( mpi *X, mpi *Y )
{
    mpi T;

    memcpy( &T,  X, sizeof( mpi ) );
    memcpy(  X,  Y, sizeof( mpi ) );
    memcpy(  Y, &T, sizeof( mpi ) );
}

/*
 * Set value from integer
 */
int mpi_lset( mpi *X, t_sint z )
{
    int ret;

    MPI_CHK( mpi_grow( X, 1 ) );
    memset( X->p, 0, X->n * ciL );

    X->p[0] = ( z < 0 ) ? -z : z;
    X->s    = ( z < 0 ) ? -1 : 1;

cleanup:

    return( ret );
}

/*
 * Get a specific bit
 */
int mpi_get_bit( const mpi *X, size_t pos )
{
    if( X->n * biL <= pos )
        return( 0 );

    return ( X->p[pos / biL] >> ( pos % biL ) ) & 0x01;
}

/*
 * Set a bit to a specific value of 0 or 1
 */
int mpi_set_bit( mpi *X, size_t pos, unsigned char val )
{
    int ret = 0;
    size_t off = pos / biL;
    size_t idx = pos % biL;

    if( val != 0 && val != 1 )
        return POLARSSL_ERR_MPI_BAD_INPUT_DATA;
        
    if( X->n * biL <= pos )
    {
        if( val == 0 )
            return ( 0 );

        MPI_CHK( mpi_grow( X, off + 1 ) );
    }

    X->p[off] = ( X->p[off] & ~( 0x01 << idx ) ) | ( val << idx );

cleanup:
    
    return( ret );
}

/*
 * Return the number of least significant bits
 */
size_t mpi_lsb( const mpi *X )
{
    size_t i, j, count = 0;

    for( i = 0; i < X->n; i++ )
        for( j = 0; j < biL; j++, count++ )
            if( ( ( X->p[i] >> j ) & 1 ) != 0 )
                return( count );

    return( 0 );
}

#if !defined(POLARSSL_HAVE_UDBL)
/*
 * Count leading zero bits in a given integer
 */
static size_t int_clz( const t_uint x )
{
    size_t j;
    t_uint mask = (t_uint) 1 << (biL - 1);

    for( j = 0; j < biL; j++ )
    {
        if( x & mask ) break;

        mask >>= 1;
    }

    return j;
}
#endif

/*
 * Return the number of most significant bits
 */
size_t mpi_msb( const mpi *X )
{
    size_t i, j;

    for( i = X->n - 1; i > 0; i-- )
        if( X->p[i] != 0 )
            break;

    for( j = biL; j > 0; j-- )
        if( ( ( X->p[i] >> ( j - 1 ) ) & 1 ) != 0 )
            break;

    return( ( i * biL ) + j );
}

/*
 * Return the total size in bytes
 */
size_t mpi_size( const mpi *X )
{
    return( ( mpi_msb( X ) + 7 ) >> 3 );
}

/*
 * Convert an ASCII character to digit value
 */
static int mpi_get_digit( t_uint *d, int radix, char c )
{
    *d = 255;

    if( c >= 0x30 && c <= 0x39 ) *d = c - 0x30;
    if( c >= 0x41 && c <= 0x46 ) *d = c - 0x37;
    if( c >= 0x61 && c <= 0x66 ) *d = c - 0x57;

    if( *d >= (t_uint) radix )
        return( POLARSSL_ERR_MPI_INVALID_CHARACTER );

    return( 0 );
}

/*
 * Import from an ASCII string
 */
int mpi_read_string( mpi *X, int radix, const char *s )
{
    int ret;
    size_t i, j, slen, n;
    t_uint d;
    mpi T;

    if( radix < 2 || radix > 16 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    mpi_init( &T );

    slen = strlen( s );

    if( radix == 16 )
    {
        n = BITS_TO_LIMBS( slen << 2 );

        MPI_CHK( mpi_grow( X, n ) );
        MPI_CHK( mpi_lset( X, 0 ) );

        for( i = slen, j = 0; i > 0; i--, j++ )
        {
            if( i == 1 && s[i - 1] == '-' )
            {
                X->s = -1;
                break;
            }

            MPI_CHK( mpi_get_digit( &d, radix, s[i - 1] ) );
            X->p[j / (2 * ciL)] |= d << ( (j % (2 * ciL)) << 2 );
        }
    }
    else
    {
        MPI_CHK( mpi_lset( X, 0 ) );

        for( i = 0; i < slen; i++ )
        {
            if( i == 0 && s[i] == '-' )
            {
                X->s = -1;
                continue;
            }

            MPI_CHK( mpi_get_digit( &d, radix, s[i] ) );
            MPI_CHK( mpi_mul_int( &T, X, radix ) );

            if( X->s == 1 )
            {
                MPI_CHK( mpi_add_int( X, &T, d ) );
            }
            else
            {
                MPI_CHK( mpi_sub_int( X, &T, d ) );
            }
        }
    }

cleanup:

    mpi_free( &T );

    return( ret );
}

/*
 * Helper to write the digits high-order first
 */
static int mpi_write_hlp( mpi *X, int radix, char **p )
{
    int ret;
    t_uint r;

    if( radix < 2 || radix > 16 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    MPI_CHK( mpi_mod_int( &r, X, radix ) );
    MPI_CHK( mpi_div_int( X, NULL, X, radix ) );

    if( mpi_cmp_int( X, 0 ) != 0 )
        MPI_CHK( mpi_write_hlp( X, radix, p ) );

    if( r < 10 )
        *(*p)++ = (char)( r + 0x30 );
    else
        *(*p)++ = (char)( r + 0x37 );

cleanup:

    return( ret );
}

/*
 * Export into an ASCII string
 */
int mpi_write_string( const mpi *X, int radix, char *s, size_t *slen )
{
    int ret = 0;
    size_t n;
    char *p;
    mpi T;

    if( radix < 2 || radix > 16 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    n = mpi_msb( X );
    if( radix >=  4 ) n >>= 1;
    if( radix >= 16 ) n >>= 1;
    n += 3;

    if( *slen < n )
    {
        *slen = n;
        return( POLARSSL_ERR_MPI_BUFFER_TOO_SMALL );
    }

    p = s;
    mpi_init( &T );

    if( X->s == -1 )
        *p++ = '-';

    if( radix == 16 )
    {
        int c;
        size_t i, j, k;

        for( i = X->n, k = 0; i > 0; i-- )
        {
            for( j = ciL; j > 0; j-- )
            {
                c = ( X->p[i - 1] >> ( ( j - 1 ) << 3) ) & 0xFF;

                if( c == 0 && k == 0 && ( i + j + 3 ) != 0 )
                    continue;

                *(p++) = "0123456789ABCDEF" [c / 16];
                *(p++) = "0123456789ABCDEF" [c % 16];
                k = 1;
            }
        }
    }
    else
    {
        MPI_CHK( mpi_copy( &T, X ) );

        if( T.s == -1 )
            T.s = 1;

        MPI_CHK( mpi_write_hlp( &T, radix, &p ) );
    }

    *p++ = '\0';
    *slen = p - s;

cleanup:

    mpi_free( &T );

    return( ret );
}

#if defined(POLARSSL_FS_IO)
/*
 * Read X from an opened file
 */
int mpi_read_file( mpi *X, int radix, FILE *fin )
{
    t_uint d;
    size_t slen;
    char *p;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[ POLARSSL_MPI_RW_BUFFER_SIZE ];

    memset( s, 0, sizeof( s ) );
    if( fgets( s, sizeof( s ) - 1, fin ) == NULL )
        return( POLARSSL_ERR_MPI_FILE_IO_ERROR );

    slen = strlen( s );
    if( slen == sizeof( s ) - 2 )
        return( POLARSSL_ERR_MPI_BUFFER_TOO_SMALL );

    if( s[slen - 1] == '\n' ) { slen--; s[slen] = '\0'; }
    if( s[slen - 1] == '\r' ) { slen--; s[slen] = '\0'; }

    p = s + slen;
    while( --p >= s )
        if( mpi_get_digit( &d, radix, *p ) != 0 )
            break;

    return( mpi_read_string( X, radix, p + 1 ) );
}

/*
 * Write X into an opened file (or stdout if fout == NULL)
 */
int mpi_write_file( const char *p, const mpi *X, int radix, FILE *fout )
{
    int ret;
    size_t n, slen, plen;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[ POLARSSL_MPI_RW_BUFFER_SIZE ];

    n = sizeof( s );
    memset( s, 0, n );
    n -= 2;

    MPI_CHK( mpi_write_string( X, radix, s, (size_t *) &n ) );

    if( p == NULL ) p = "";

    plen = strlen( p );
    slen = strlen( s );
    s[slen++] = '\r';
    s[slen++] = '\n';

    if( fout != NULL )
    {
        if( fwrite( p, 1, plen, fout ) != plen ||
            fwrite( s, 1, slen, fout ) != slen )
            return( POLARSSL_ERR_MPI_FILE_IO_ERROR );
    }
    else
        printf( "%s%s", p, s );

cleanup:

    return( ret );
}
#endif /* POLARSSL_FS_IO */

/*
 * Import X from unsigned binary data, big endian
 */
int mpi_read_binary( mpi *X, const unsigned char *buf, size_t buflen )
{
    int ret;
    size_t i, j, n;

    for( n = 0; n < buflen; n++ )
        if( buf[n] != 0 )
            break;

    MPI_CHK( mpi_grow( X, CHARS_TO_LIMBS( buflen - n ) ) );
    MPI_CHK( mpi_lset( X, 0 ) );

    for( i = buflen, j = 0; i > n; i--, j++ )
        X->p[j / ciL] |= ((t_uint) buf[i - 1]) << ((j % ciL) << 3);

cleanup:

    return( ret );
}

/*
 * Export X into unsigned binary data, big endian
 */
int mpi_write_binary( const mpi *X, unsigned char *buf, size_t buflen )
{
    size_t i, j, n;

    n = mpi_size( X );

    if( buflen < n )
        return( POLARSSL_ERR_MPI_BUFFER_TOO_SMALL );

    memset( buf, 0, buflen );

    for( i = buflen - 1, j = 0; n > 0; i--, j++, n-- )
        buf[i] = (unsigned char)( X->p[j / ciL] >> ((j % ciL) << 3) );

    return( 0 );
}

/*
 * Left-shift: X <<= count
 */
int mpi_shift_l( mpi *X, size_t count )
{
    int ret;
    size_t i, v0, t1;
    t_uint r0 = 0, r1;

    v0 = count / (biL    );
    t1 = count & (biL - 1);

    i = mpi_msb( X ) + count;

    if( X->n * biL < i )
        MPI_CHK( mpi_grow( X, BITS_TO_LIMBS( i ) ) );

    ret = 0;

    /*
     * shift by count / limb_size
     */
    if( v0 > 0 )
    {
        for( i = X->n; i > v0; i-- )
            X->p[i - 1] = X->p[i - v0 - 1];

        for( ; i > 0; i-- )
            X->p[i - 1] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( t1 > 0 )
    {
        for( i = v0; i < X->n; i++ )
        {
            r1 = X->p[i] >> (biL - t1);
            X->p[i] <<= t1;
            X->p[i] |= r0;
            r0 = r1;
        }
    }

cleanup:

    return( ret );
}

/*
 * Right-shift: X >>= count
 */
int mpi_shift_r( mpi *X, size_t count )
{
    size_t i, v0, v1;
    t_uint r0 = 0, r1;

    v0 = count /  biL;
    v1 = count & (biL - 1);

    if( v0 > X->n || ( v0 == X->n && v1 > 0 ) )
        return mpi_lset( X, 0 );

    /*
     * shift by count / limb_size
     */
    if( v0 > 0 )
    {
        for( i = 0; i < X->n - v0; i++ )
            X->p[i] = X->p[i + v0];

        for( ; i < X->n; i++ )
            X->p[i] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( v1 > 0 )
    {
        for( i = X->n; i > 0; i-- )
        {
            r1 = X->p[i - 1] << (biL - v1);
            X->p[i - 1] >>= v1;
            X->p[i - 1] |= r0;
            r0 = r1;
        }
    }

    return( 0 );
}

/*
 * Compare unsigned values
 */
static int mpi_cmp_abs_limbs (size_t n, const t_uint *p0, const t_uint *p1)
{
    size_t i, j;

    p0 += n;
    for( i = n; i > 0; i-- )
        if( *--p0 != 0 )
            break;

    p1 += n;
    for( j = n; j > 0; j-- )
        if( *--p1 != 0 )
            break;

    if( i == 0 && j == 0 )
        return( 0 );

    if( i > j ) return(  1 );
    if( j > i ) return( -1 );

    for( ; i > 0; i-- )
    {
        if( *p0 > *p1 ) return(  1 );
        if( *p0 < *p1 ) return( -1 );
        p0--; p1--;
    }

    return( 0 );
}

/*
 * Compare unsigned values
 */
int mpi_cmp_abs( const mpi *X, const mpi *Y )
{
    size_t i, j;

    for( i = X->n; i > 0; i-- )
        if( X->p[i - 1] != 0 )
            break;

    for( j = Y->n; j > 0; j-- )
        if( Y->p[j - 1] != 0 )
            break;

    if( i == 0 && j == 0 )
        return( 0 );

    if( i > j ) return(  1 );
    if( j > i ) return( -1 );

    for( ; i > 0; i-- )
    {
        if( X->p[i - 1] > Y->p[i - 1] ) return(  1 );
        if( X->p[i - 1] < Y->p[i - 1] ) return( -1 );
    }

    return( 0 );
}

/*
 * Compare signed values
 */
int mpi_cmp_mpi( const mpi *X, const mpi *Y )
{
    size_t i, j;

    for( i = X->n; i > 0; i-- )
        if( X->p[i - 1] != 0 )
            break;

    for( j = Y->n; j > 0; j-- )
        if( Y->p[j - 1] != 0 )
            break;

    if( i == 0 && j == 0 )
        return( 0 );

    if( i > j ) return(  X->s );
    if( j > i ) return( -Y->s );

    if( X->s > 0 && Y->s < 0 ) return(  1 );
    if( Y->s > 0 && X->s < 0 ) return( -1 );

    for( ; i > 0; i-- )
    {
        if( X->p[i - 1] > Y->p[i - 1] ) return(  X->s );
        if( X->p[i - 1] < Y->p[i - 1] ) return( -X->s );
    }

    return( 0 );
}

/*
 * Compare signed values
 */
int mpi_cmp_int( const mpi *X, t_sint z )
{
    mpi Y;
    t_uint p[1];

    *p  = ( z < 0 ) ? -z : z;
    Y.s = ( z < 0 ) ? -1 : 1;
    Y.n = 1;
    Y.p = p;

    return( mpi_cmp_mpi( X, &Y ) );
}

/*
 * Unsigned addition: X = |A| + |B|  (HAC 14.7)
 */
int mpi_add_abs( mpi *X, const mpi *A, const mpi *B )
{
    int ret;
    size_t i, j;
    t_uint *o, *p, c;

    if( X == B )
    {
        const mpi *T = A; A = X; B = T;
    }

    if( X != A )
        MPI_CHK( mpi_copy( X, A ) );
   
    /*
     * X should always be positive as a result of unsigned additions.
     */
    X->s = 1;

    for( j = B->n; j > 0; j-- )
        if( B->p[j - 1] != 0 )
            break;

    MPI_CHK( mpi_grow( X, j ) );

    o = B->p; p = X->p; c = 0;

    for( i = 0; i < j; i++, o++, p++ )
    {
        *p +=  c; c  = ( *p <  c );
        *p += *o; c += ( *p < *o );
    }

    while( c != 0 )
    {
        if( i >= X->n )
        {
            MPI_CHK( mpi_grow( X, i + 1 ) );
            p = X->p + i;
        }

        *p += c; c = ( *p < c ); i++; p++;
    }

cleanup:

    return( ret );
}

/*
 * Helper for mpi substraction
 */
static t_uint mpi_sub_hlp( size_t n, const t_uint *s, t_uint *d )
{
    size_t i;
    t_uint c, z;

    for( i = c = 0; i < n; i++, s++, d++ )
    {
        z = ( *d <  c );     *d -=  c;
        c = ( *d < *s ) + z; *d -= *s;
    }

    return c;
}

/*
 * Unsigned substraction: X = |A| - |B|  (HAC 14.9)
 */
int mpi_sub_abs( mpi *X, const mpi *A, const mpi *B )
{
    mpi TB;
    int ret;
    size_t n;
    t_uint *d;
    t_uint c, z;

    if( mpi_cmp_abs( A, B ) < 0 )
        return( POLARSSL_ERR_MPI_NEGATIVE_VALUE );

    mpi_init( &TB );

    if( X == B )
    {
        MPI_CHK( mpi_copy( &TB, B ) );
        B = &TB;
    }

    if( X != A )
        MPI_CHK( mpi_copy( X, A ) );

    /*
     * X should always be positive as a result of unsigned substractions.
     */
    X->s = 1;

    ret = 0;

    for( n = B->n; n > 0; n-- )
        if( B->p[n - 1] != 0 )
            break;

    c = mpi_sub_hlp( n, B->p, X->p );
    d = X->p + n;

    while( c != 0 )
    {
        z = ( *d < c ); *d -= c;
        c = z; d++;
    }

cleanup:

    mpi_free( &TB );

    return( ret );
}

/*
 * Signed addition: X = A + B
 */
int mpi_add_mpi( mpi *X, const mpi *A, const mpi *B )
{
    int ret, s = A->s;

    if( A->s * B->s < 0 )
    {
        if( mpi_cmp_abs( A, B ) >= 0 )
        {
            MPI_CHK( mpi_sub_abs( X, A, B ) );
            X->s =  s;
        }
        else
        {
            MPI_CHK( mpi_sub_abs( X, B, A ) );
            X->s = -s;
        }
    }
    else
    {
        MPI_CHK( mpi_add_abs( X, A, B ) );
        X->s = s;
    }

cleanup:

    return( ret );
}

/*
 * Signed substraction: X = A - B
 */
int mpi_sub_mpi( mpi *X, const mpi *A, const mpi *B )
{
    int ret, s = A->s;

    if( A->s * B->s > 0 )
    {
        if( mpi_cmp_abs( A, B ) >= 0 )
        {
            MPI_CHK( mpi_sub_abs( X, A, B ) );
            X->s =  s;
        }
        else
        {
            MPI_CHK( mpi_sub_abs( X, B, A ) );
            X->s = -s;
        }
    }
    else
    {
        MPI_CHK( mpi_add_abs( X, A, B ) );
        X->s = s;
    }

cleanup:

    return( ret );
}

/*
 * Signed addition: X = A + b
 */
int mpi_add_int( mpi *X, const mpi *A, t_sint b )
{
    mpi _B;
    t_uint p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _B.s = ( b < 0 ) ? -1 : 1;
    _B.n = 1;
    _B.p = p;

    return( mpi_add_mpi( X, A, &_B ) );
}

/*
 * Signed substraction: X = A - b
 */
int mpi_sub_int( mpi *X, const mpi *A, t_sint b )
{
    mpi _B;
    t_uint p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _B.s = ( b < 0 ) ? -1 : 1;
    _B.n = 1;
    _B.p = p;

    return( mpi_sub_mpi( X, A, &_B ) );
}

/*
 * Helper for mpi multiplication
 */
static
#if defined(__APPLE__) && defined(__arm__)
/*
 * Apple LLVM version 4.2 (clang-425.0.24) (based on LLVM 3.2svn)
 * appears to need this to prevent bad ARM code generation at -O3.
 */
__attribute__ ((noinline))
#endif
t_uint mpi_mul_hlp( size_t i, const t_uint *s, t_uint *d, t_uint b )
{
    t_uint c = 0, t = 0;

#if defined(MULADDC_1024_LOOP)
    MULADDC_1024_LOOP

    for( ; i > 0; i-- )
    {
        MULADDC_INIT
        MULADDC_CORE
        MULADDC_STOP
    }
#elif defined(MULADDC_HUIT)
    for( ; i >= 8; i -= 8 )
    {
        MULADDC_INIT
        MULADDC_HUIT
        MULADDC_STOP
    }

    for( ; i > 0; i-- )
    {
        MULADDC_INIT
        MULADDC_CORE
        MULADDC_STOP
    }
#else
    for( ; i >= 16; i -= 16 )
    {
        MULADDC_INIT
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE

        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_STOP
    }

    for( ; i >= 8; i -= 8 )
    {
        MULADDC_INIT
        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE

        MULADDC_CORE   MULADDC_CORE
        MULADDC_CORE   MULADDC_CORE
        MULADDC_STOP
    }

    for( ; i > 0; i-- )
    {
        MULADDC_INIT
        MULADDC_CORE
        MULADDC_STOP
    }
#endif

    t++;

    *d += c; c = ( *d < c );
    return c;
}

/*
 * Baseline multiplication: X = A * B  (HAC 14.12)
 */
int mpi_mul_mpi( mpi *X, const mpi *A, const mpi *B )
{
    int ret;
    size_t i, j, k;
    mpi TA, TB;

    mpi_init( &TA ); mpi_init( &TB );

    if( X == A ) { MPI_CHK( mpi_copy( &TA, A ) ); A = &TA; }
    if( X == B ) { MPI_CHK( mpi_copy( &TB, B ) ); B = &TB; }

    for( i = A->n; i > 0; i-- )
        if( A->p[i - 1] != 0 )
            break;

    for( j = B->n; j > 0; j-- )
        if( B->p[j - 1] != 0 )
            break;

    MPI_CHK( mpi_grow( X, i + j ) );
    MPI_CHK( mpi_lset( X, 0 ) );

    for(k = 0; k < j; k++ )
        mpi_mul_hlp( i, A->p, X->p + k, B->p[k]);

    X->s = A->s * B->s;

cleanup:

    mpi_free( &TB ); mpi_free( &TA );

    return( ret );
}

/*
 * Baseline multiplication: X = A * b
 */
int mpi_mul_int( mpi *X, const mpi *A, t_sint b )
{
    mpi _B;
    t_uint p[1];

    _B.s = 1;
    _B.n = 1;
    _B.p = p;
    p[0] = b;

    return( mpi_mul_mpi( X, A, &_B ) );
}

/*
 * Unsigned integer divide - 64bit dividend and 32bit divisor
 */
static t_uint int_div_int(t_uint u1, t_uint u0, t_uint d, t_uint *r)
{
#if defined(POLARSSL_HAVE_UDBL)
    t_udbl dividend, quotient;
#else
    const t_uint radix = (t_uint) 1 << biH;
    const t_uint uint_halfword_mask = ( (t_uint) 1 << biH ) - 1;
    t_uint d0, d1, q0, q1, rAX, r0, quotient;
    t_uint u0_msw, u0_lsw;
    size_t s;
#endif

    /*
     * Check for overflow
     */
    if(( 0 == d ) || ( u1 >= d ))
    {
        if (r != NULL) *r = (~0UL);

        return (~0UL);
    }

#if defined(POLARSSL_HAVE_UDBL)
    dividend  = (t_udbl) u1 << biL;
    dividend |= (t_udbl) u0;
    quotient = dividend / d;
    if( quotient > ( (t_udbl) 1 << biL ) - 1 )
        quotient = ( (t_udbl) 1 << biL ) - 1;

    if( r != NULL )
        *r = (t_uint)( dividend - (quotient * d ) );

    return (t_uint) quotient;
#else

    /*
     * Algorithm D, Section 4.3.1 - The Art of Computer Programming
     *   Vol. 2 - Seminumerical Algorithms, Knuth
     */

    /*
     * Normalize the divisor, d, and dividend, u0, u1
     */
    s = int_clz( d );
    d = d << s;

    u1 = u1 << s;
    u1 |= ( u0 >> ( biL - s ) ) & ( -(t_sint)s >> ( biL - 1 ) );
    u0 =  u0 << s;

    d1 = d >> biH;
    d0 = d & uint_halfword_mask;

    u0_msw = u0 >> biH;
    u0_lsw = u0 & uint_halfword_mask;

    /*
     * Find the first quotient and remainder
     */
    q1 = u1 / d1;
    r0 = u1 - d1 * q1;

    while( q1 >= radix || ( q1 * d0 > radix * r0 + u0_msw ) )
    {
        q1 -= 1;
        r0 += d1;

        if ( r0 >= radix ) break;
    }

    rAX = (u1 * radix) + (u0_msw - q1 * d);
    q0 = rAX / d1;
    r0 = rAX - q0 * d1;

    while( q0 >= radix || ( q0 * d0 > radix * r0 + u0_lsw ) )
    {
        q0 -= 1;
        r0 += d1;

        if ( r0 >= radix ) break;
    }

    if (r != NULL)
        *r = (rAX * radix + u0_lsw - q0 * d) >> s;

    quotient = q1 * radix + q0;

    return quotient;
#endif
}

/*
 * Division by mpi: A = Q * B + R  (HAC 14.20)
 */
int mpi_div_mpi( mpi *Q, mpi *R, const mpi *A, const mpi *B )
{
    int ret;
    size_t i, n, t, k;
    mpi X, Y, Z, T1, T2;

    if( mpi_cmp_int( B, 0 ) == 0 )
        return( POLARSSL_ERR_MPI_DIVISION_BY_ZERO );

    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );
    mpi_init( &T1 ); mpi_init( &T2 );

    if( mpi_cmp_abs( A, B ) < 0 )
    {
        if( Q != NULL ) MPI_CHK( mpi_lset( Q, 0 ) );
        if( R != NULL ) MPI_CHK( mpi_copy( R, A ) );
        return( 0 );
    }

    MPI_CHK( mpi_copy( &X, A ) );
    MPI_CHK( mpi_copy( &Y, B ) );
    X.s = Y.s = 1;

    MPI_CHK( mpi_grow( &Z, A->n + 2 ) );
    MPI_CHK( mpi_lset( &Z,  0 ) );
    MPI_CHK( mpi_grow( &T1, 2 ) );
    MPI_CHK( mpi_grow( &T2, 3 ) );

    k = mpi_msb( &Y ) % biL;
    if( k < biL - 1 )
    {
        k = biL - 1 - k;
        MPI_CHK( mpi_shift_l( &X, k ) );
        MPI_CHK( mpi_shift_l( &Y, k ) );
    }
    else k = 0;

    n = X.n - 1;
    t = Y.n - 1;
    MPI_CHK( mpi_shift_l( &Y, biL * (n - t) ) );

    while( mpi_cmp_mpi( &X, &Y ) >= 0 )
    {
        Z.p[n - t]++;
        mpi_sub_mpi( &X, &X, &Y );
    }
    mpi_shift_r( &Y, biL * (n - t) );

    for( i = n; i > t ; i-- )
    {
        if( X.p[i] >= Y.p[t] )
            Z.p[i - t - 1] = ~0UL;
        else
        {
            Z.p[i - t - 1] = int_div_int( X.p[i], X.p[i-1], Y.p[t], NULL);
        }

        Z.p[i - t - 1]++;
        do
        {
            Z.p[i - t - 1]--;

            MPI_CHK( mpi_lset( &T1, 0 ) );
            T1.p[0] = (t < 1) ? 0 : Y.p[t - 1];
            T1.p[1] = Y.p[t];
            MPI_CHK( mpi_mul_int( &T1, &T1, Z.p[i - t - 1] ) );

            MPI_CHK( mpi_lset( &T2, 0 ) );
            T2.p[0] = (i < 2) ? 0 : X.p[i - 2];
            T2.p[1] = (i < 1) ? 0 : X.p[i - 1];
            T2.p[2] = X.p[i];
        }
        while( mpi_cmp_mpi( &T1, &T2 ) > 0 );

        MPI_CHK( mpi_mul_int( &T1, &Y, Z.p[i - t - 1] ) );
        MPI_CHK( mpi_shift_l( &T1,  biL * (i - t - 1) ) );
        MPI_CHK( mpi_sub_mpi( &X, &X, &T1 ) );

        while( mpi_cmp_int( &X, 0 ) < 0 )
        {
            MPI_CHK( mpi_copy( &T1, &Y ) );
            MPI_CHK( mpi_shift_l( &T1, biL * (i - t - 1) ) );
            MPI_CHK( mpi_add_mpi( &X, &X, &T1 ) );
            Z.p[i - t - 1]--;
        }
    }

    if( Q != NULL )
    {
        mpi_copy( Q, &Z );
        Q->s = A->s * B->s;
    }

    if( R != NULL )
    {
        mpi_shift_r( &X, k );
        X.s = A->s;
        mpi_copy( R, &X );

        if( mpi_cmp_int( R, 0 ) == 0 )
            R->s = 1;
    }

cleanup:

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );
    mpi_free( &T1 ); mpi_free( &T2 );

    return( ret );
}

/*
 * Division by int: A = Q * b + R
 */
int mpi_div_int( mpi *Q, mpi *R, const mpi *A, t_sint b )
{
    mpi _B;
    t_uint p[1];

    p[0] = ( b < 0 ) ? -b : b;
    _B.s = ( b < 0 ) ? -1 : 1;
    _B.n = 1;
    _B.p = p;

    return( mpi_div_mpi( Q, R, A, &_B ) );
}

/*
 * Modulo: R = A mod B
 */
int mpi_mod_mpi( mpi *R, const mpi *A, const mpi *B )
{
    int ret;

    if( mpi_cmp_int( B, 0 ) < 0 )
        return POLARSSL_ERR_MPI_NEGATIVE_VALUE;

    MPI_CHK( mpi_div_mpi( NULL, R, A, B ) );

    while( mpi_cmp_int( R, 0 ) < 0 )
      MPI_CHK( mpi_add_mpi( R, R, B ) );

    while( mpi_cmp_mpi( R, B ) >= 0 )
      MPI_CHK( mpi_sub_mpi( R, R, B ) );

cleanup:

    return( ret );
}

/*
 * Modulo: r = A mod b
 */
int mpi_mod_int( t_uint *r, const mpi *A, t_sint b )
{
    size_t i;
    t_uint x, y, z;

    if( b == 0 )
        return( POLARSSL_ERR_MPI_DIVISION_BY_ZERO );

    if( b < 0 )
        return POLARSSL_ERR_MPI_NEGATIVE_VALUE;

    /*
     * handle trivial cases
     */
    if( b == 1 )
    {
        *r = 0;
        return( 0 );
    }

    if( b == 2 )
    {
        *r = A->p[0] & 1;
        return( 0 );
    }

    /*
     * general case
     */
    for( i = A->n, y = 0; i > 0; i-- )
    {
        x  = A->p[i - 1];
        y  = ( y << biH ) | ( x >> biH );
        z  = y / b;
        y -= z * b;

        x <<= biH;
        y  = ( y << biH ) | ( x >> biH );
        z  = y / b;
        y -= z * b;
    }

    /*
     * If A is negative, then the current y represents a negative value.
     * Flipping it to the positive side.
     */
    if( A->s < 0 && y != 0 )
        y = b - y;

    *r = y;

    return( 0 );
}

/*
 * Fast Montgomery initialization (thanks to Tom St Denis)
 */
static void mpi_montg_init( t_uint *mm, const mpi *N )
{
    t_uint x, m0 = N->p[0];

    x  = m0;
    x += ( ( m0 + 2 ) & 4 ) << 1;
    x *= ( 2 - ( m0 * x ) );

    if( biL >= 16 ) x *= ( 2 - ( m0 * x ) );
    if( biL >= 32 ) x *= ( 2 - ( m0 * x ) );
    if( biL >= 64 ) x *= ( 2 - ( m0 * x ) );

    *mm = ~x + 1;
}

/*
 * Montgomery multiplication: A = A * B * R^-1 mod N  (HAC 14.36)
 * A is placed at the upper half of D.
 */
static void mpi_montmul( size_t n, const t_uint *np, t_uint mm, t_uint *d,
                         const t_uint *bp )
{
    size_t i;
    t_uint u0, u1, c = 0;

    for( i = 0; i < n; i++ )
    {
        /*
         * T = (T + u0*B + u1*N) / 2^biL
         */
        u0 = d[n];
        d[n] = c;
        u1 = ( d[0] + u0 * bp[0] ) * mm;

        mpi_mul_hlp( n, bp, d, u0 );
        c = mpi_mul_hlp( n, np, d, u1 );
        d++;
    }

    /* prevent timing attacks */
    if( ((mpi_cmp_abs_limbs ( n, d, np ) >= 0) | c) )
        mpi_sub_hlp( n, np, d );
    else
        mpi_sub_hlp( n, d - n, d - n);
}

/*
 * Montgomery reduction: A = A * R^-1 mod N
 * A is placed at the upper half of D.
 */
static void mpi_montred( size_t n, const t_uint *np, t_uint mm, t_uint *d )
{
    size_t i, j;
    t_uint u0, u1, c = 0;

    for( i = 0; i < n; i++ )
    {
        /*
         * T = (T + u0 + u1*N) / 2^biL
         */
        u0 = d[n];
        d[n] = c;
        u1 = (d[0] + u0) * mm;

        d[0] += u0;
        c = (d[0] < u0);
        for (j = 1; j < n; j++)
          {
            d[j] += c; c = ( d[j] < c );
          }

        c = mpi_mul_hlp( n, np, d, u1 );
        d++;
    }

    /* prevent timing attacks */
    if( ((mpi_cmp_abs_limbs ( n, d, np ) >= 0) | c) )
        mpi_sub_hlp( n, np, d );
    else
        mpi_sub_hlp( n, d - n, d - n);
}

/*
 * Montgomery square: A = A * A * R^-1 mod N
 * A is placed at the upper half of D.
 *
 * n : number of limbs of N
 * np: pointer to limbs of bignum N
 * mm: m' = -N^(-1) mod b where b = 2^number-of-bit-in-limb
 * d (destination): the result [<-- temp -->][<--- A ---->]
 *                               lower part    upper part
 *                                   n-limb       n-limb
 */
static void mpi_montsqr( size_t n, const t_uint *np, t_uint mm, t_uint *d )
{
#if defined(POLARSSL_HAVE_ASM) && defined(__arm__)
  size_t i;
  register t_uint c = 0;

  for (i = 0; i < n; i++)
    {
      t_uint *wij = &d[i*2];
      t_uint *xj = &d[i+n];
      t_uint x_i;

      x_i = *xj;
      *xj++ = c;

#if defined(__ARM_FEATURE_DSP)
      asm (/* (C,R4,R5) := w_i_i + x_i*x_i; w_i_i := R5; */
           "mov    %[c], #0\n\t"
           "ldr    r5, [%[wij]]\n\t"          /* R5 := w_i_i; */
           "mov    r4, %[c]\n\t"
           "umlal  r5, r4, %[x_i], %[x_i]\n\t"
           "str    r5, [%[wij]], #4\n\t"
           "cmp    %[xj], %[x_max1]\n\t"
           "bhi    0f\n\t"
           "mov    r9, %[c]\n\t"  /* R9 := 0, the constant ZERO from here.  */
           "beq    1f\n"
   "2:\n\t"
           "ldmia  %[xj]!, { r7, r8 }\n\t"
           "ldmia  %[wij], { r5, r6 }\n\t"
           /* (C,R4,R5) := (C,R4) + w_i_j + 2*x_i*x_j; */
           "umaal  r5, r4, %[x_i], r7\n\t"
           "umlal  r5, %[c], %[x_i], r7\n\t"
           "umaal  r4, %[c], r9, r9\n\t"
           /* (C,R4,R6) := (C,R4) + w_i_j + 2*x_i*x_j; */
           "umaal  r6, r4, %[x_i], r8\n\t"
           "umlal  r6, %[c], %[x_i], r8\n\t"
           "umaal  r4, %[c], r9, r9\n\t"
           /**/
           "stmia  %[wij]!, { r5, r6 }\n\t"
           "cmp    %[xj], %[x_max1]\n\t"
           "bcc    2b\n\t"
           "bne    0f\n"
   "1:\n\t"
           /* (C,R4,R5) := (C,R4) + w_i_j + 2*x_i*x_j; */
           "ldr    r5, [%[wij]]\n\t"
           "ldr    r6, [%[xj]], #4\n\t"
           "umaal  r5, r4, %[x_i], r6\n\t"
           "umlal  r5, %[c], %[x_i], r6\n\t"
           "umaal  r4, %[c], r9, r9\n\t"
           "str    r5, [%[wij]], #4\n"
   "0:\n\t"
           "ldr    r5, [%[wij]]\n\t"
           "adds   r4, r4, r5\n\t"
           "adc    %[c], %[c], #0\n\t"
           "str    r4, [%[wij]]"
           : [c] "=&r" (c), [wij] "=r" (wij), [xj] "=r" (xj)
           : [x_i] "r" (x_i), [x_max1] "r" (&d[n*2-1]),
             "[wij]" (wij), "[xj]" (xj)
           : "r4", "r5", "r6", "r7", "r8", "r9", "memory", "cc");
#else
      asm (/* (C,R4,R5) := w_i_i + x_i*x_i; w_i_i := R5; */
           "mov    %[c], #0\n\t"
           "ldr    r5, [%[wij]]\n\t"          /* R5 := w_i_i; */
           "mov    r4, %[c]\n\t"
           "umlal  r5, r4, %[x_i], %[x_i]\n\t"
           "str    r5, [%[wij]], #4\n\t"
           "cmp    %[xj], %[x_max1]\n\t"
           "bhi    0f\n\t"
           "mov    r9, %[c]\n\t"  /* R9 := 0, the constant ZERO from here.  */
           "beq    1f\n"
   "2:\n\t"
           "ldmia  %[xj]!, { r7, r8 }\n\t"
           "ldmia  %[wij], { r5, r6 }\n\t"
           /* (C,R4,R5) := (C,R4) + w_i_j + 2*x_i*x_j; */
           "umull  r7, r12, %[x_i], r7\n\t"
           "adds   r5, r5, r4\n\t"
           "adc    r4, %[c], r9\n\t"
           "adds   r5, r5, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], r9, r9\n\t"
           "adds   r5, r5, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], %[c], r9\n\t"
           /* (C,R4,R6) := (C,R4) + w_i_j + 2*x_i*x_j; */
           "adds   r6, r6, r4\n\t"
           "adc    r4, %[c], r9\n\t"
           "umull  r7, r12, %[x_i], r8\n\t"
           "adds   r6, r6, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], r9, r9\n\t"
           "adds   r6, r6, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], %[c], r9\n\t"
           /**/
           "stmia  %[wij]!, { r5, r6 }\n\t"
           "cmp    %[xj], %[x_max1]\n\t"
           "bcc    2b\n\t"
           "bne    0f\n"
   "1:\n\t"
           /* (C,R4,R5) := (C,R4) + w_i_j + 2*x_i*x_j; */
           "ldr    r5, [%[wij]]\n\t"
           "ldr    r6, [%[xj]], #4\n\t"
           "adds   r5, r5, r4\n\t"
           "adc    r4, %[c], r9\n\t"
           "umull  r7, r12, %[x_i], r6\n\t"
           "adds   r5, r5, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], r9, r9\n\t"
           "adds   r5, r5, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], %[c], r9\n\t"
           "str    r5, [%[wij]], #4\n"
   "0:\n\t"
           "ldr    r5, [%[wij]]\n\t"
           "adds   r4, r4, r5\n\t"
           "adc    %[c], %[c], #0\n\t"
           "str    r4, [%[wij]]"
           : [c] "=&r" (c), [wij] "=r" (wij), [xj] "=r" (xj)
           : [x_i] "r" (x_i), [x_max1] "r" (&d[n*2-1]),
             "[wij]" (wij), "[xj]" (xj)
           : "r4", "r5", "r6", "r7", "r8", "r9", "r12", "memory", "cc");
#endif

        c += mpi_mul_hlp( n, np, &d[i], d[i] * mm );
    }

  d += n;

  /* prevent timing attacks */
  if( ((mpi_cmp_abs_limbs ( n, d, np ) >= 0) | c) )
      mpi_sub_hlp( n, np, d );
  else
      mpi_sub_hlp( n, d - n, d - n);
#else
  t_uint a_input[n];

  memcpy (a_input, &d[n], sizeof (a_input));
  mpi_montmul (n, np, mm, d, a_input);
#endif
}

/*
 * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
 */
#if MEMORY_SIZE >= 32
#define MAX_WSIZE 6
#elif MEMORY_SIZE >= 24
#define MAX_WSIZE 5
#else
#define MAX_WSIZE 4
#endif
int mpi_exp_mod( mpi *X, const mpi *A, const mpi *E, const mpi *N, mpi *_RR )
{
    int ret;
    size_t i = mpi_msb( E );
    size_t wsize = ( i > 1024 ) ? MAX_WSIZE :
      		   ( i > 671 ) ? 6 : ( i > 239 ) ? 5 :
                   ( i >  79 ) ? 4 : ( i >  23 ) ? 3 : 1;
    size_t wbits, one = 1;
    size_t nblimbs;
    size_t bufsize, nbits;
    t_uint ei, mm, state;
    mpi RR;
    t_uint d[N->n*2];
    t_uint w1[N->n];
    t_uint wn[(one << (wsize - 1))][N->n];

    if( mpi_cmp_int( N, 0 ) < 0 || ( N->p[0] & 1 ) == 0 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    if( mpi_cmp_int( E, 0 ) < 0 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    if( A->s == -1 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    /*
     * Init temps and window size
     */
    mpi_montg_init( &mm, N );

    /*
     * If 1st call, pre-compute R^2 mod N
     */
    if( _RR == NULL || _RR->p == NULL )
    {
        mpi T;

        mpi_init( &RR );
        T.s = 1; T.n = N->n * 2; T.p = d;
        memset (d, 0, 2 * N->n * ciL); /* Set D zero. */
        mpi_sub_hlp( N->n, N->p, d + N->n);
        MPI_CHK( mpi_mod_mpi( &RR, &T, N ) );
        MPI_CHK( mpi_grow( &RR, N->n ) );

        if( _RR != NULL )
            memcpy( _RR, &RR, sizeof( mpi ) );

        /* The condition of "the lower half of D is all zero" is kept. */
    }
    else {
        memcpy( &RR, _RR, sizeof( mpi ) );
        memset (d, 0, N->n * ciL); /* Set lower half of D zero. */
    }

    MPI_CHK( mpi_grow( X, N->n ) );

    /*
     * W[1] = A * R^2 * R^-1 mod N = A * R mod N
     */
    if( mpi_cmp_mpi( A, N ) >= 0 ) {
        mpi W1;
        W1.s = 1; W1.n = N->n; W1.p = d + N->n;
        mpi_mod_mpi( &W1, A, N );
    } else {
        memset (d + N->n, 0, N->n * ciL);
        memcpy (d + N->n, A->p, A->n * ciL);
    }

    mpi_montmul( N->n, N->p, mm, d, RR.p );
    memcpy (w1, d + N->n, N->n * ciL);

    {
        /*
         * W[1 << (wsize - 1)] = W[1] ^ ( 2 ^ (wsize - 1) )
         */
        for( i = 0; i < wsize - 1; i++ )
            mpi_montsqr( N->n, N->p, mm, d );
        memcpy (wn[0], d + N->n, N->n * ciL);

        /*
         * W[i] = W[i - 1] * W[1]
         */
        for( i = 1; i < (one << (wsize - 1)); i++ )
        {
            mpi_montmul( N->n, N->p, mm, d, w1 );
            memcpy (wn[i], d + N->n, N->n * ciL);
        }
    }

    /*
     * X = R^2 * R^-1 mod N = R mod N
     */
    memcpy (d + N->n, RR.p, N->n * ciL);
    mpi_montred( N->n, N->p, mm, d );

    nblimbs = E->n;
    bufsize = 0;
    nbits   = 0;
    wbits   = 0;
    state   = 0;

    while( 1 )
    {
        if( bufsize == 0 )
        {
            if( nblimbs-- == 0 )
                break;

            bufsize = sizeof( t_uint ) << 3;
        }

        bufsize--;

        ei = (E->p[nblimbs] >> bufsize) & 1;

        /*
         * skip leading 0s
         */
        if( ei == 0 && state == 0 )
            continue;

        if( ei == 0 && state == 1 )
        {
            /*
             * out of window, square X
             */
             mpi_montsqr( N->n, N->p, mm, d );
            continue;
        }

        /*
         * add ei to current window
         */
        state = 2;

        nbits++;
        wbits |= (ei << (wsize - nbits));

        if( nbits == wsize )
        {
            /*
             * X = X^wsize R^-1 mod N
             */
            for( i = 0; i < wsize; i++ )
                mpi_montsqr( N->n, N->p, mm, d );

            /*
             * X = X * W[wbits] R^-1 mod N
             */
            mpi_montmul( N->n, N->p, mm, d, wn[wbits - (one << (wsize - 1))]);

            state--;
            nbits = 0;
            wbits = 0;
        }
    }

    /*
     * process the remaining bits
     */
    for( i = 0; i < nbits; i++ )
    {
        mpi_montsqr( N->n, N->p, mm, d );

        wbits <<= 1;

        if( (wbits & (one << wsize)) != 0 )
            mpi_montmul( N->n, N->p, mm, d, w1);
    }

    /*
     * X = A^E * R * R^-1 mod N = A^E mod N
     */
    mpi_montred( N->n, N->p, mm, d );
    memcpy (X->p, d + N->n, N->n * ciL);

cleanup:

    if( _RR == NULL )
        mpi_free( &RR );

    return( ret );
}

/*
 * Greatest common divisor: G = gcd(A, B)  (HAC 14.54)
 */
int mpi_gcd( mpi *G, const mpi *A, const mpi *B )
{
    int ret;
    size_t lz, lzt;
    mpi TG, TA, TB;

    mpi_init( &TG ); mpi_init( &TA ); mpi_init( &TB );

    MPI_CHK( mpi_copy( &TA, A ) );
    MPI_CHK( mpi_copy( &TB, B ) );

    lz = mpi_lsb( &TA );
    lzt = mpi_lsb( &TB );

    if ( lzt < lz )
        lz = lzt;

    MPI_CHK( mpi_shift_r( &TA, lz ) );
    MPI_CHK( mpi_shift_r( &TB, lz ) );

    TA.s = TB.s = 1;

    while( mpi_cmp_int( &TA, 0 ) != 0 )
    {
        MPI_CHK( mpi_shift_r( &TA, mpi_lsb( &TA ) ) );
        MPI_CHK( mpi_shift_r( &TB, mpi_lsb( &TB ) ) );

        if( mpi_cmp_mpi( &TA, &TB ) >= 0 )
        {
            MPI_CHK( mpi_sub_abs( &TA, &TA, &TB ) );
            MPI_CHK( mpi_shift_r( &TA, 1 ) );
        }
        else
        {
            MPI_CHK( mpi_sub_abs( &TB, &TB, &TA ) );
            MPI_CHK( mpi_shift_r( &TB, 1 ) );
        }
    }

    MPI_CHK( mpi_shift_l( &TB, lz ) );
    MPI_CHK( mpi_copy( G, &TB ) );

cleanup:

    mpi_free( &TG ); mpi_free( &TA ); mpi_free( &TB );

    return( ret );
}

int mpi_fill_random( mpi *X, size_t size,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int ret;

    MPI_CHK( mpi_grow( X, CHARS_TO_LIMBS( size ) ) );
    MPI_CHK( mpi_lset( X, 0 ) );

    MPI_CHK( f_rng( p_rng, (unsigned char *) X->p, size ) );

cleanup:
    return( ret );
}

/*
 * Modular inverse: X = A^-1 mod N  (HAC 14.61 / 14.64)
 */
int mpi_inv_mod( mpi *X, const mpi *A, const mpi *N )
{
    int ret;
    mpi G, TA, TU, U1, U2, TB, TV, V1, V2;

    if( mpi_cmp_int( N, 0 ) <= 0 )
        return( POLARSSL_ERR_MPI_BAD_INPUT_DATA );

    mpi_init( &TA ); mpi_init( &TU ); mpi_init( &U1 ); mpi_init( &U2 );
    mpi_init( &G ); mpi_init( &TB ); mpi_init( &TV );
    mpi_init( &V1 ); mpi_init( &V2 );

    MPI_CHK( mpi_gcd( &G, A, N ) );

    if( mpi_cmp_int( &G, 1 ) != 0 )
    {
        ret = POLARSSL_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }

    MPI_CHK( mpi_mod_mpi( &TA, A, N ) );
    MPI_CHK( mpi_copy( &TU, &TA ) );
    MPI_CHK( mpi_copy( &TB, N ) );
    MPI_CHK( mpi_copy( &TV, N ) );

    MPI_CHK( mpi_lset( &U1, 1 ) );
    MPI_CHK( mpi_lset( &U2, 0 ) );
    MPI_CHK( mpi_lset( &V1, 0 ) );
    MPI_CHK( mpi_lset( &V2, 1 ) );

    do
    {
        while( ( TU.p[0] & 1 ) == 0 )
        {
            MPI_CHK( mpi_shift_r( &TU, 1 ) );

            if( ( U1.p[0] & 1 ) != 0 || ( U2.p[0] & 1 ) != 0 )
            {
                MPI_CHK( mpi_add_mpi( &U1, &U1, &TB ) );
                MPI_CHK( mpi_sub_mpi( &U2, &U2, &TA ) );
            }

            MPI_CHK( mpi_shift_r( &U1, 1 ) );
            MPI_CHK( mpi_shift_r( &U2, 1 ) );
        }

        while( ( TV.p[0] & 1 ) == 0 )
        {
            MPI_CHK( mpi_shift_r( &TV, 1 ) );

            if( ( V1.p[0] & 1 ) != 0 || ( V2.p[0] & 1 ) != 0 )
            {
                MPI_CHK( mpi_add_mpi( &V1, &V1, &TB ) );
                MPI_CHK( mpi_sub_mpi( &V2, &V2, &TA ) );
            }

            MPI_CHK( mpi_shift_r( &V1, 1 ) );
            MPI_CHK( mpi_shift_r( &V2, 1 ) );
        }

        if( mpi_cmp_mpi( &TU, &TV ) >= 0 )
        {
            MPI_CHK( mpi_sub_mpi( &TU, &TU, &TV ) );
            MPI_CHK( mpi_sub_mpi( &U1, &U1, &V1 ) );
            MPI_CHK( mpi_sub_mpi( &U2, &U2, &V2 ) );
        }
        else
        {
            MPI_CHK( mpi_sub_mpi( &TV, &TV, &TU ) );
            MPI_CHK( mpi_sub_mpi( &V1, &V1, &U1 ) );
            MPI_CHK( mpi_sub_mpi( &V2, &V2, &U2 ) );
        }
    }
    while( mpi_cmp_int( &TU, 0 ) != 0 );

    while( mpi_cmp_int( &V1, 0 ) < 0 )
        MPI_CHK( mpi_add_mpi( &V1, &V1, N ) );

    while( mpi_cmp_mpi( &V1, N ) >= 0 )
        MPI_CHK( mpi_sub_mpi( &V1, &V1, N ) );

    MPI_CHK( mpi_copy( X, &V1 ) );

cleanup:

    mpi_free( &TA ); mpi_free( &TU ); mpi_free( &U1 ); mpi_free( &U2 );
    mpi_free( &G ); mpi_free( &TB ); mpi_free( &TV );
    mpi_free( &V1 ); mpi_free( &V2 );

    return( ret );
}

#if defined(POLARSSL_GENPRIME)

static const int small_prime[] =
{
#if 0
        3,    5,    7,   11,   13,   17,   19,   23,
       29,   31,   37,   41,   43,   47,   53,   59,
       61,   67,   71,   73,   79,   83,   89,   97,
      101,  103,  107,  109,  113,  127,  131,  137,
      139,  149,  151,  157,  163,  167,  173,  179,
      181,  191,  193,  197,  199,  211,  223,  227,
      229,  233,  239,  241,  251,  257,  263,  269,
      271,  277,  281,  283,  293,  307,  311,  313,
      317,  331,  337,  347,  349,  353,  359,  367,
      373,  379,  383,  389,  397,  401,  409,  419,
      421,  431,  433,  439,  443,  449,  457,  461,
      463,  467,  479,  487,  491,  499,  503,  509,
      521,  523,  541,  547,  557,  563,  569,  571,
      577,  587,  593,  599,  601,  607,  613,  617,
      619,  631,  641,  643,  647,  653,  659,  661,
      673,  677,  683,  691,  701,
#else
       97,
#endif
                                    709,  719,  727,
      733,  739,  743,  751,  757,  761,  769,  773,
      787,  
#if 0
            797,
#endif
                  809,  811,  821,  823,  827,  829,
      839,  853,  857,  859,  863,  877,  881,  883,
      887,  907,  911,  919,  929,  937,  941,  947,
      953,  967,  971,  977,  983,  991,  997, 
#if 1
                                               1009, 
     1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051,
     1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103,
     1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171,
     1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229,
     1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289,
     1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327,
     1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427,
     1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471,
     1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523,
     1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579,
     1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621,
     1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697,
     1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753,
     1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823,
     1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879,
     1889,
#endif

     -103
};

/*
 * From Public domain code of JKISS RNG.
 *
 * Reference: David Jones, UCL Bioinformatics Group
 * Good Practice in (Pseudo) Random Number Generation for
 * Bioinformatics Applications
 *
 */
struct jkiss_state { uint32_t x, y, z, c; };
static struct jkiss_state jkiss_state_v;

int prng_seed (int (*f_rng)(void *, unsigned char *, size_t),
               void *p_rng)
{
  int ret;

  struct jkiss_state *s = &jkiss_state_v;

  MPI_CHK ( f_rng (p_rng, (unsigned char *)s, sizeof (struct jkiss_state)) );
  while (s->y == 0)
    MPI_CHK ( f_rng (p_rng, (unsigned char *)&s->y, sizeof (uint32_t)) );
  s->z |= 1;                    /* avoiding z=c=0 */

cleanup:
  return ret;
}

static uint32_t
jkiss (struct jkiss_state *s)
{
  uint64_t t;

  s->x = 314527869 * s->x + 1234567;
  s->y ^= s->y << 5;
  s->y ^= s->y >> 7;
  s->y ^= s->y << 22;
  t = 4294584393ULL * s->z + s->c;
  s->c = (uint32_t)(t >> 32);
  s->z = (uint32_t)t;

  return s->x + s->y + s->z;
}

static int mpi_fill_pseudo_random ( mpi *X, size_t size)
{
  int ret;
  uint32_t *p, *p_end;

  MPI_CHK( mpi_grow( X, CHARS_TO_LIMBS( size ) ) );
  MPI_CHK( mpi_lset( X, 0 ) );

  /* Assume little endian.  */
  p = (uint32_t *)X->p;
  p_end = (uint32_t *)(X->p + (size/sizeof (uint32_t)));
  while (p < p_end)
    *p++ = jkiss (&jkiss_state_v);

  if ((size%sizeof (uint32_t)))
    *p = jkiss (&jkiss_state_v) & ((1 << (8*(size % sizeof (uint32_t)))) - 1);

cleanup:
  return ret;
}

/*
 * Miller-Rabin primality test  (HAC 4.24)
 */
static
int mpi_is_prime( mpi *X)
{
    int ret, xs;
    size_t i, j, n, s;
    mpi W, R, T, A, RR;

    if( mpi_cmp_int( X, 0 ) == 0 ||
        mpi_cmp_int( X, 1 ) == 0 )
        return( POLARSSL_ERR_MPI_NOT_ACCEPTABLE );

    if( mpi_cmp_int( X, 2 ) == 0 )
        return( 0 );

    mpi_init( &W ); mpi_init( &R ); mpi_init( &T ); mpi_init( &A );
    mpi_init( &RR );

    xs = X->s; X->s = 1;
    ret = 0;

#if 0
    /*
     * test trivial factors first
     */
    if( ( X->p[0] & 1 ) == 0 )
        return( POLARSSL_ERR_MPI_NOT_ACCEPTABLE );
#endif

    for( i = 0; small_prime[i] > 0; i++ )
    {
        t_uint r;

        if( mpi_cmp_int( X, small_prime[i] ) <= 0 )
            return( 0 );

        MPI_CHK( mpi_mod_int( &r, X, small_prime[i] ) );

        if( r == 0 )
            return( POLARSSL_ERR_MPI_NOT_ACCEPTABLE );
    }

    /*
     * W = |X| - 1
     * R = W >> lsb( W )
     */
    MPI_CHK( mpi_sub_int( &W, X, 1 ) );
    s = mpi_lsb( &W );
    MPI_CHK( mpi_copy( &R, &W ) );
    MPI_CHK( mpi_shift_r( &R, s ) );
    i = mpi_msb( X );

    /* Fermat primality test with 2.  */
    mpi_lset (&T, 2);
    MPI_CHK( mpi_exp_mod( &T, &T, &W, X, &RR ) );
    if ( mpi_cmp_int (&T, 1) != 0)
      {
        ret = POLARSSL_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
      }


    /*
     * HAC, table 4.4
     */
    n = ( ( i >= 1300 ) ?  2 : ( i >=  850 ) ?  3 :
          ( i >=  650 ) ?  4 : ( i >=  350 ) ?  8 :
          ( i >=  250 ) ? 12 : ( i >=  150 ) ? 18 : 27 );

    for( i = 0; i < n; i++ )
    {
        /*
         * pick a random A, 1 < A < |X| - 1
         */
        MPI_CHK( mpi_fill_pseudo_random( &A, X->n * ciL ) );

        if( mpi_cmp_mpi( &A, &W ) >= 0 )
        {
            j = mpi_msb( &A ) - mpi_msb( &W );
            MPI_CHK( mpi_shift_r( &A, j + 1 ) );
        }
        A.p[0] |= 3;

        /*
         * A = A^R mod |X|
         */
        MPI_CHK( mpi_exp_mod( &A, &A, &R, X, &RR ) );

        if( mpi_cmp_mpi( &A, &W ) == 0 ||
            mpi_cmp_int( &A,  1 ) == 0 )
            continue;

        j = 1;
        while( j < s && mpi_cmp_mpi( &A, &W ) != 0 )
        {
            /*
             * A = A * A mod |X|
             */
            MPI_CHK( mpi_mul_mpi( &T, &A, &A ) );
            MPI_CHK( mpi_mod_mpi( &A, &T, X  ) );

            if( mpi_cmp_int( &A, 1 ) == 0 )
                break;

            j++;
        }

        /*
         * not prime if A != |X| - 1 or A == 1
         */
        if( mpi_cmp_mpi( &A, &W ) != 0 ||
            mpi_cmp_int( &A,  1 ) == 0 )
        {
            ret = POLARSSL_ERR_MPI_NOT_ACCEPTABLE;
            break;
        }
    }

cleanup:

    X->s = xs;

    mpi_free( &W ); mpi_free( &R ); mpi_free( &T ); mpi_free( &A );
    mpi_free( &RR );

    return( ret );
}


/*
 * Value M: multiply all primes up to 701 (except 97) and 797
 * (so that MAX_A will be convenient value)
 */
#ifdef __LP64__
#define M_LIMBS 16
#else
#define M_LIMBS 31
#endif
#define M_SIZE 122

static const t_uint limbs_M[] = { /* Little endian */
#ifdef __LP64__
  0x9344A6AB84EEB59EUL, 0xEC855CDAFF21529FUL,
  0x477E991E009BAB38UL, 0x2EEA23579F5B86F3UL, 
  0xAC17D30441D6502FUL, 0x38FF52B90A468A6DUL, 
  0x63630419FD42E5EFUL, 0x48CE17D091DB2572UL, 
  0x708AB00AE3B57D0EUL, 0xF8A9DE08CD723598UL, 
  0x731411374432C93BUL, 0x554DF2612779FAB3UL, 
  0xDEEBDA58953D2BA5UL, 0xD1D66F2F5F57D007UL, 
  0xB85C9607E84E9F2BUL, 0x000000000000401DUL
#else
  0x84EEB59E, 0x9344A6AB, 0xFF21529F, 0xEC855CDA,
  0x009BAB38, 0x477E991E, 0x9F5B86F3, 0x2EEA2357,
  0x41D6502F, 0xAC17D304, 0x0A468A6D, 0x38FF52B9,
  0xFD42E5EF, 0x63630419, 0x91DB2572, 0x48CE17D0,
  0xE3B57D0E, 0x708AB00A, 0xCD723598, 0xF8A9DE08,
  0x4432C93B, 0x73141137, 0x2779FAB3, 0x554DF261,
  0x953D2BA5, 0xDEEBDA58, 0x5F57D007, 0xD1D66F2F,
  0xE84E9F2B, 0xB85C9607, 0x0000401D
#endif
};

static const mpi M[1] = {{ 1, M_LIMBS, (t_uint *)limbs_M }};

/*
 * MAX_A : 2^1024 / M - 1
 */
#ifdef __LP64__
#define MAX_A_LIMBS 1
#else
#define MAX_A_LIMBS 2
#endif
#define MAX_A_FILL_SIZE  6
static const t_uint limbs_MAX_A[] = { /* Little endian */
#ifdef __LP64__
  0x0003FE2556A2B35FUL
#else
  0x56A2B35F, 0x0003FE25
#endif
};

static const mpi MAX_A[1] = {{ 1, MAX_A_LIMBS, (t_uint *)limbs_MAX_A }};

/*
 * Prime number generation
 *
 * Special version for 1024-bit only.  Ignores DH_FLAG.
 */
int mpi_gen_prime( mpi *X, size_t nbits, int dh_flag,
                   int (*f_rng)(void *, unsigned char *, size_t),
                   void *p_rng )
{
  int ret;
  mpi B[1], G[1];

  (void)dh_flag;
  if (nbits != 1024)
    return POLARSSL_ERR_MPI_BAD_INPUT_DATA;

  mpi_init ( B );  mpi_init ( G );

  /*
   * Get random value 1 to M-1 avoiding bias, and proceed when it is
   * coprime to all small primes.
   */
  do
    {
      MPI_CHK ( mpi_fill_random ( B, M_SIZE, f_rng, p_rng ) );
      B->p[0] |= 0x1;
      B->p[M_LIMBS - 1] &= 0x00007FFF;
      if (mpi_cmp_abs (B, M) >= 0)
        continue;

      MPI_CHK ( mpi_gcd ( G, B, M ) );
    }
  while (mpi_cmp_int ( G, 1 ) != 0);

  /*
   * Get random value avoiding bias, comput P with the value,
   * check if it's big enough, lastly, check if it's prime.
   */
  while (1)
    {
      MPI_CHK( mpi_fill_random( X, MAX_A_FILL_SIZE, f_rng, p_rng ) );
      MPI_CHK ( mpi_sub_abs (X, MAX_A, X) );

      MPI_CHK ( mpi_mul_mpi ( X, X, M ) );
      MPI_CHK ( mpi_add_abs ( X, X, B ) );
      if (X->n <= M_LIMBS || (X->p[M_LIMBS-1] & 0xc0000000) == 0)
        continue;
      ret = mpi_is_prime ( X );
      if (ret == 0 || ret != POLARSSL_ERR_MPI_NOT_ACCEPTABLE)
        break;
    }

cleanup:

  mpi_free ( B );  mpi_free ( G );

  return ret;
}

#endif

#if defined(POLARSSL_SELF_TEST)

#define GCD_PAIR_COUNT  3

static const int gcd_pairs[GCD_PAIR_COUNT][3] =
{
    { 693, 609, 21 },
    { 1764, 868, 28 },
    { 768454923, 542167814, 1 }
};

/*
 * Checkup routine
 */
int mpi_self_test( int verbose )
{
    int ret, i;
    mpi A, E, N, X, Y, U, V;

    mpi_init( &A ); mpi_init( &E ); mpi_init( &N ); mpi_init( &X );
    mpi_init( &Y ); mpi_init( &U ); mpi_init( &V );

    MPI_CHK( mpi_read_string( &A, 16,
        "EFE021C2645FD1DC586E69184AF4A31E" \
        "D5F53E93B5F123FA41680867BA110131" \
        "944FE7952E2517337780CB0DB80E61AA" \
        "E7C8DDC6C5C6AADEB34EB38A2F40D5E6" ) );

    MPI_CHK( mpi_read_string( &E, 16,
        "B2E7EFD37075B9F03FF989C7C5051C20" \
        "34D2A323810251127E7BF8625A4F49A5" \
        "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
        "5B5C25763222FEFCCFC38B832366C29E" ) );

    MPI_CHK( mpi_read_string( &N, 16,
        "0066A198186C18C10B2F5ED9B522752A" \
        "9830B69916E535C8F047518A889A43A5" \
        "94B6BED27A168D31D4A52F88925AA8F5" ) );

    MPI_CHK( mpi_mul_mpi( &X, &A, &N ) );

    MPI_CHK( mpi_read_string( &U, 16,
        "602AB7ECA597A3D6B56FF9829A5E8B85" \
        "9E857EA95A03512E2BAE7391688D264A" \
        "A5663B0341DB9CCFD2C4C5F421FEC814" \
        "8001B72E848A38CAE1C65F78E56ABDEF" \
        "E12D3C039B8A02D6BE593F0BBBDA56F1" \
        "ECF677152EF804370C1A305CAF3B5BF1" \
        "30879B56C61DE584A0F53A2447A51E" ) );

    if( verbose != 0 )
        printf( "  MPI test #1 (mul_mpi): " );

    if( mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n" );

    MPI_CHK( mpi_div_mpi( &X, &Y, &A, &N ) );

    MPI_CHK( mpi_read_string( &U, 16,
        "256567336059E52CAE22925474705F39A94" ) );

    MPI_CHK( mpi_read_string( &V, 16,
        "6613F26162223DF488E9CD48CC132C7A" \
        "0AC93C701B001B092E4E5B9F73BCD27B" \
        "9EE50D0657C77F374E903CDFA4C642" ) );

    if( verbose != 0 )
        printf( "  MPI test #2 (div_mpi): " );

    if( mpi_cmp_mpi( &X, &U ) != 0 ||
        mpi_cmp_mpi( &Y, &V ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n" );

    MPI_CHK( mpi_exp_mod( &X, &A, &E, &N, NULL ) );

    MPI_CHK( mpi_read_string( &U, 16,
        "36E139AEA55215609D2816998ED020BB" \
        "BD96C37890F65171D948E9BC7CBAA4D9" \
        "325D24D6A3C12710F10A09FA08AB87" ) );

    if( verbose != 0 )
        printf( "  MPI test #3 (exp_mod): " );

    if( mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n" );

#if defined(POLARSSL_GENPRIME)
    MPI_CHK( mpi_inv_mod( &X, &A, &N ) );

    MPI_CHK( mpi_read_string( &U, 16,
        "003A0AAEDD7E784FC07D8F9EC6E3BFD5" \
        "C3DBA76456363A10869622EAC2DD84EC" \
        "C5B8A74DAC4D09E03B5E0BE779F2DF61" ) );

    if( verbose != 0 )
        printf( "  MPI test #4 (inv_mod): " );

    if( mpi_cmp_mpi( &X, &U ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n" );
#endif

    if( verbose != 0 )
        printf( "  MPI test #5 (simple gcd): " );

    for ( i = 0; i < GCD_PAIR_COUNT; i++)
    {
        MPI_CHK( mpi_lset( &X, gcd_pairs[i][0] ) );
        MPI_CHK( mpi_lset( &Y, gcd_pairs[i][1] ) );

	    MPI_CHK( mpi_gcd( &A, &X, &Y ) );

	    if( mpi_cmp_int( &A, gcd_pairs[i][2] ) != 0 )
	    {
		    if( verbose != 0 )
			    printf( "failed at %d\n", i );

		    return( 1 );
	    }
    }

    if( verbose != 0 )
        printf( "passed\n" );

cleanup:

    if( ret != 0 && verbose != 0 )
        printf( "Unexpected error, return code = %08X\n", ret );

    mpi_free( &A ); mpi_free( &E ); mpi_free( &N ); mpi_free( &X );
    mpi_free( &Y ); mpi_free( &U ); mpi_free( &V );

    if( verbose != 0 )
        printf( "\n" );

    return( ret );
}

#endif

#endif
