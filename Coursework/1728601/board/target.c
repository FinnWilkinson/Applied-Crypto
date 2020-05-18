/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "target.h"

#define AES_ENC_RND_KEY_STEP(a,b,c,d) { \
  s[a] = s[a] ^ rk[a];                  \
  s[b] = s[b] ^ rk[b];                  \
  s[c] = s[c] ^ rk[c];                  \
  s[d] = s[d] ^ rk[d];                  \
}
#define AES_ENC_RND_SUB_STEP(a,b,c,d) { \
  s[a] = sbox(s[a]);                    \
  s[b] = sbox(s[b]);                    \
  s[c] = sbox(s[c]);                    \
  s[d] = sbox(s[d]);                    \
}
#define AES_ENC_RND_ROW_STEP(a,b,c,d,e,f,g,h) { \
  uint8_t a1 = s[a];                            \
  uint8_t b1 = s[b];                            \
  uint8_t c1 = s[c];                            \
  uint8_t d1 = s[d];                            \
  s[e] = a1;                                    \
  s[f] = b1;                                    \
  s[g] = c1;                                    \
  s[h] = d1;                                    \
}
#define AES_ENC_RND_MIX_STEP(a,b,c,d) { \
  uint8_t a1 = s[a];                    \
  uint8_t b1 = s[b];                    \
  uint8_t c1 = s[c];                    \
  uint8_t d1 = s[d];                    \
                                        \
  uint8_t a2 = xtime(a1);               \
  uint8_t b2 = xtime(b1);               \
  uint8_t c2 = xtime(c1);               \
  uint8_t d2 = xtime(d1);               \
                                        \
  uint8_t a3 = a1^a2;                   \
  uint8_t b3 = b1^b2;                   \
  uint8_t c3 = c1^c2;                   \
  uint8_t d3 = d1^d2;                   \
                                        \
  s[a] = a2^b3^c1^d1;                   \
  s[b] = a1^b2^c3^d1;                   \
  s[c] = a1^b1^c2^d3;                   \
  s[d] = a3^b1^c1^d2;                   \
}

uint8_t xtime( uint8_t  a);
uint8_t sbox( uint8_t a);
uint8_t aes_gf28_mul( uint8_t a, uint8_t b);
uint8_t aes_gf28_inv( uint8_t a);
void aes_enc_exp_step( uint8_t* rk, uint8_t rc);
void aes_enc_rnd_key(uint8_t* s, uint8_t* rk);
void aes_enc_rnd_sub(uint8_t* s);
void aes_enc_rnd_row(uint8_t* s);
void aes_enc_rnd_mix(uint8_t* s);
void aes_enc(uint8_t* c, uint8_t* m, uint8_t* k);
uint8_t hex2int(char c);
char int2hex(uint8_t c);

/** Read  an octet string (or sequence of bytes) from the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[out] r the destination octet string read
  * \return       the number of octets read
  */

int  octetstr_rd(       uint8_t* r, int n_r ) {
  int inputLength = 2 + 1 + 2*(n_r) + 1; //length + colon + data + terminator
  char x[inputLength];
  char temp;
  for (int i = 0; true; i++) {
    temp = scale_uart_rd( SCALE_UART_MODE_BLOCKING );
    if(temp == '\x0D'){
        x[i] = '\x00';
        break;
      }
    if(i < inputLength){
      x[i] = temp;
    }
  }

  int dataLength = hex2int(x[0])*16 + hex2int(x[1]);
  if(dataLength == 0) return 0;
  if(dataLength > n_r) dataLength = n_r;
  for(int i = 0; i < dataLength; i++){
    r[i] = hex2int(x[(2*i)+3])*16 + hex2int(x[(2*i)+4]);
  }
  return dataLength;
}

/** Write an octet string (or sequence of bytes) to   the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[in]  r the source      octet string written
  * \param[in]  n the number of octets written
  */

void octetstr_wr( const uint8_t* x, int n_x ) {
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, (int2hex( (n_x&0x000000F0)>>4 )) );
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, (int2hex(n_x&0x0000000F)) );
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, (':') );
  for(int i = 0; i < n_x; i++){
      scale_uart_wr( SCALE_UART_MODE_BLOCKING, int2hex( (x[i]&0xF0)>>4 ));
      scale_uart_wr( SCALE_UART_MODE_BLOCKING, int2hex( (x[i]&0x0F) ));
  }
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, '\x0D');
}

//converts from a character to equivalent integer
uint8_t hex2int(char c)
{
  if(c >= '0' && c <='9') return c - '0';
  if(c >= 'A' && c <= 'F') return c - 'A'+10;
  if(c >= 'a' && c <= 'f') return c - 'a'+10;
  return -1;
}

//converts from integer to equivalent hex character
char int2hex(uint8_t c)
{
  if(c >= 0 && c <=9) return c + '0';
  if(c >= 10 && c <= 15) return c + 'A' -10;
  return -1;
}

//multiplies a by indeterminant x under modulo p(x)
uint8_t xtime( uint8_t  a) {
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

//multiply two aes_gf28 together under field F(2^8)
uint8_t aes_gf28_mul( uint8_t a, uint8_t b) {
  uint8_t t = 0;
  for (int i = 7; i >= 0; i--) {
    t = xtime(t);
    if((b >> i) & 1) {
      t ^= a;
    }
  }
  return t;
}

uint8_t aes_gf28_inv( uint8_t a) {
  //uses Lagranges theorem
  uint8_t pos0 = aes_gf28_mul(a,a);
  uint8_t pos1 = aes_gf28_mul(pos0,a);
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

uint8_t sbox( uint8_t a) {
  //sbox(a) = f(g(a))
  //g(a) = 1 / a (field inversion)
  //f = affine transformation
  //<1,1,0,0,0,1,1,0>
  uint8_t gOfa = aes_gf28_inv(a);
  uint8_t fOfa = (0x63)^gOfa^(gOfa<<1)^(gOfa<<2)^(gOfa<<3)^(gOfa<<4)^(gOfa>>7)^(gOfa>>6)
                    ^(gOfa>>5)^(gOfa>>4);
  return fOfa;
}

void aes_enc_exp_step( uint8_t* rk, uint8_t rc) {
  //produces i-th+1 round key matrix
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

void aes_enc_rnd_key(uint8_t* s, uint8_t* rk) {
  //Add-RoundKey function using macro
  AES_ENC_RND_KEY_STEP(0,1,2,3); //col1
  AES_ENC_RND_KEY_STEP(4,5,6,7); //col2
  AES_ENC_RND_KEY_STEP(8,9,10,11); //col3
  AES_ENC_RND_KEY_STEP(12,13,14,15); //col4
}

void aes_enc_rnd_sub(uint8_t* s) {
  //Sub-Bytes function using macro
  AES_ENC_RND_SUB_STEP(0,1,2,3);
  AES_ENC_RND_SUB_STEP(4,5,6,7);
  AES_ENC_RND_SUB_STEP(8,9,10,11);
  AES_ENC_RND_SUB_STEP(12,13,14,15);
}

void aes_enc_rnd_row(uint8_t* s) {
  //Shift-Rows function using macro
  //row 0 doesnt change
  AES_ENC_RND_ROW_STEP(1,5,9,13,13,1,5,9); //row 1
  AES_ENC_RND_ROW_STEP(2,6,10,14,10,14,2,6); //row 2
  AES_ENC_RND_ROW_STEP(3,7,11,15,7,11,15,3); //row 3
}

void aes_enc_rnd_mix(uint8_t* s) {
  //Mix-Columns function using macro
  AES_ENC_RND_MIX_STEP(0,1,2,3);
  AES_ENC_RND_MIX_STEP(4,5,6,7);
  AES_ENC_RND_MIX_STEP(8,9,10,11);
  AES_ENC_RND_MIX_STEP(12,13,14,15);  
}

/** Initialise an AES-128 encryption, e.g., expand the cipher key k into round
  * keys, or perform randomised pre-computation in support of a countermeasure;
  * this can be left blank if no such initialisation is required, because the
  * same k and r will be passed as input to the encryption itself.
  *
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */
void aes_init(                               const uint8_t* k, const uint8_t* r ) {
  
  return;
}

/** Perform    an AES-128 encryption of a plaintext m under a cipher key k, to
  * yield the corresponding ciphertext c.
  *
  * \param[out] c   an   AES-128 ciphertext
  * \param[in]  m   an   AES-128 plaintext
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes     ( uint8_t* c, const uint8_t* m, const uint8_t* k, const uint8_t* r ) {
  memcpy(c, m, SIZEOF_BLK*sizeof(uint8_t));

  uint8_t key[SIZEOF_KEY];
  memcpy(key, k, SIZEOF_KEY*sizeof(uint8_t));
  uint8_t rc[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
  //1 initial round
  aes_enc_rnd_key(c, key);
  //Nr-1 iterated rounds with Nr = 10 for AES-128
  for (int i = 1; i < 10; i++) {
    aes_enc_rnd_sub(c);
    aes_enc_rnd_row(c);
    aes_enc_rnd_mix(c);
    aes_enc_exp_step(key, rc[i-1]);
    aes_enc_rnd_key(c, key);
  }
  //1 final round
  aes_enc_rnd_sub(c);
  aes_enc_rnd_row(c);
  aes_enc_exp_step(key, rc[9]);
  aes_enc_rnd_key(c, key);
  return;
}

/** Initialise the SCALE development board, then loop indefinitely, reading a
  * command then processing it:
  *
  * 1. If command is inspect, then
  *
  *    - write the SIZEOF_BLK parameter,
  *      i.e., number of bytes in an  AES-128 plaintext  m, or ciphertext c,
  *      to the UART,
  *    - write the SIZEOF_KEY parameter,
  *      i.e., number of bytes in an  AES-128 cipher key k,
  *      to the UART,
  *    - write the SIZEOF_RND parameter,
  *      i.e., number of bytes in the         randomness r.
  *      to the UART.
  *
  * 2. If command is encrypt, then
  *
  *    - read  an   AES-128 plaintext  m from the UART,
  *    - read  some         randomness r from the UART,
  *    - initalise the encryption,
  *    - set the trigger signal to 1,
  *    - execute   the encryption, producing the ciphertext
  *
  *      c = AES-128.Enc( m, k )
  *
  *      using the hard-coded cipher key k plus randomness r if/when need be,
  *    - set the trigger signal to 0,
  *    - write an   AES-128 ciphertext c to   the UART.
  */

int main( int argc, char* argv[] ) {
  scale_conf_t scale_conf = {
    .clock_type        = SCALE_CLOCK_TYPE_EXT,
    .clock_freq_source = SCALE_CLOCK_FREQ_16MHZ,
    .clock_freq_target = SCALE_CLOCK_FREQ_16MHZ,

    .tsc               = false
  };

  if( !scale_init( &scale_conf ) ) {
    return -1;
  }

  uint8_t cmd[ 1 ], c[ SIZEOF_BLK ], m[ SIZEOF_BLK ], k[ SIZEOF_KEY ] = {0xD3, 0x85, 0x33, 0x46, 0x02, 0x8B, 0x6E, 0x24, 0x86, 0x62, 0xE9, 0x95, 0xAB, 0x68, 0x7E, 0x25}/*{ 0xFC, 0x00, 0x24, 0xE2, 0x7B, 0x3A, 0x1A, 0x9A, 0x9D, 0xC5, 0xFC, 0xFF, 0xA1, 0x0A, 0x3F, 0xE7 }*/, r[ SIZEOF_RND ];

  while( true ) {
    if( 1 != octetstr_rd( cmd, 1 ) ) {
      break;
    }

    switch( cmd[ 0 ] ) {
      case COMMAND_INSPECT : {
        uint8_t t = SIZEOF_BLK;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_KEY;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_RND;
                    octetstr_wr( &t, 1 );

        break;
      }
      case COMMAND_ENCRYPT : {
        if( SIZEOF_BLK != octetstr_rd( m, SIZEOF_BLK ) ) {
          break;
        }
        if( SIZEOF_RND != octetstr_rd( r, SIZEOF_RND ) ) {
          break;
        }

        aes_init(       k, r );

        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  true );
        aes     ( c, m, k, r );
        scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );

                          octetstr_wr( c, SIZEOF_BLK );

        break;
      }
      default : {
        break;
      }
    }
  }

  return 0;
}
