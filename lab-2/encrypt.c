/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "encrypt.h"

typedef uint8_t aes_gf28_t;

aes_gf28_t xtime( aes_gf28_t  a);
aes_gf28_t sbox( aes_gf28_t a);
aes_gf28_t aes_gf28_mul( aes_gf28_t a, aes_gf28_t b);
aes_gf28_t aes_gf28_inv( aes_gf28_t a);
void aes_enc_exp_step( aes_gf28_t* rk, aes_gf28_t rc);
void aes_enc_rnd_key(aes_gf28_t* s, aes_gf28_t* rk);


int main( int argc, char* argv[] ) {
  uint8_t k[ 16 ] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
  uint8_t m[ 16 ] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
                      0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
  uint8_t c[ 16 ] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
                      0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
  uint8_t t[ 16 ];

  AES_KEY rk;

  printf("%d\n", xtime(255) );

  AES_set_encrypt_key( k, 128, &rk );
  AES_encrypt( m, t, &rk );

  if( !memcmp( t, c, 16 * sizeof( uint8_t ) ) ) {
    printf( "AES.Enc( k, m ) == c\n" );
  }
  else {
    printf( "AES.Enc( k, m ) != c\n" );
  }
}

aes_gf28_t xtime( aes_gf28_t  a){
  //multiplies a by indeterminant x under modulo p(x)
  //a = <1,0,0,0,1,1,1,0> = 1 + x4 + x5 + x6 = 1+16+32+64 = 113
  //a*x = x + x5 + x6 + x7 = <0,1,0,0,0,1,1,1> = 2+32+64+128 = 226
  //so is a logical shift left but need to deal with overflow
  //a*x*x = x2 + x6 + x7 + x8 = x2 + x6 + x7 + (x4 + x3 + x + 1) = 1 + x + x2 + x3 + x4 + x6 + x7 = 223
  //                            <0,0,1,0,0,0,1,1> xor <1,1,0,1,1,0,0,0>
  // x8 = x4 + x3 + x + 1
  //if x8th bit == 1, LSR xor 1B

  if((a & 0x80) == 0x80){
    return (0x1B ^ (a << 1));
  }
  else return (a << 1);
}

aes_gf28_t aes_gf28_mul( aes_gf28_t a, aes_gf28_t b) {
  aes_gf28_t t = 0;
  for (int i = 7; i >= 0; i--) {
    t = xtime(t);
    if((b >> i) & 1) {
      t ^= a;
    }
  }
  return t;
}

aes_gf28_t aes_gf28_inv( aes_gf28_t a){
  //uses Lagranges theorem
  aes_gf28_t pos0 = aes_gf28_mul(a,a);
  aes_gf28_t pos1 = aes_gf28_mul(pos0,a);
  pos0 = aes_gf28_mul( pos0, pos0 );
  pos1 = aes_gf28_mul( pos1, pos0 );
  pos0 = aes_gf28_mul( pos0, pos0 );
  pos0 = aes_gf28_mul( pos1, pos0 );
  pos0 = aes_gf28_mul( pos0, pos0 );
  pos0 = aes_gf28_mul( pos0, pos0 );
  pos1 = aes_gf28_mul( pos1, pos0 );
  pos0 = aes_gf28_mul( pos0, pos1 );
  pos0 = aes_gf28_mul( pos0, pos0 );
  return pos0;
}

aes_gf28_t sbox( aes_gf28_t a) {
  //sbox(a) = f(g(a))
  //g(a) = 1 / a (field inversion)
  //f = affine transformation
  //<1,1,0,0,0,1,1,0>
  aes_gf28_t gOfa = aes_gf28_inv(a);
  aes_gf28_t fOfa = (0x63)^gOfa^(gOfa<<1)^(gOfa<<2)^(gOfa<<3)^(gOfa<<4)^(gOfa>>7)^(gOfa>>6)
                    ^(gOfa>>5)^(gOfa>>4);
  return fOfa;
}

void aes_enc_exp_step( aes_gf28_t* rk, aes_gf28_t rc){
  //ith round means: i*4<= j <= ((i+1)*4)-1
  //j = 0 (mod 4) for all 1st column
  //in c accessing rk:
  //col 1, 0<=j<=3
  //col 2, 4<=j<=7
  //col 3, 8<=j<=11
  //col 4, 12<=j<=15

  //col 1
  rk[0] = rc ^ sbox(rk[13]) ^ rk[0];
  rk[1] = sbox(rk[14]) ^ rk[1];
  rk[2] = sbox(rk[15]) ^ rk[2];
  rk[3] = sbox(rk[12]) ^ rk[3];
  //col 2
  rk[4] = rk[0] ^ rk[4];
  rk[5] = rk[1] ^ rk[5];
  rk[6] = rk[2] ^ rk[6];
  rk[7] = rk[3] ^ rk[7];
  //col 3
  rk[8] = rk[4] ^ rk[8];
  rk[9] = rk[5] ^ rk[9];
  rk[10] = rk[6] ^ rk[10];
  rk[11] = rk[7] ^ rk[11];
  //col 4
  rk[12] = rk[8] ^ rk[12];
  rk[13] = rk[9] ^ rk[13];
  rk[14] = rk[10] ^ rk[14];
  rk[15] = rk[11] ^ rk[15];

}

void aes_enc_rnd_key(aes_gf28_t* s, aes_gf28_t* rk){

}
