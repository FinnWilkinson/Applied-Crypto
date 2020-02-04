/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "helloworld.h"

int octetstr_rd( uint8_t* r, int  n_r);
void reverse( uint8_t* input, uint8_t* output, int n);
void octetstr_wr( const uint8_t* x, int n_x);

int main( int argc, char* argv[] ) {
  // select a configuration st. the external 16 MHz oscillator is used
  scale_conf_t scale_conf = {
    .clock_type        = SCALE_CLOCK_TYPE_EXT,
    .clock_freq_source = SCALE_CLOCK_FREQ_16MHZ,
    .clock_freq_target = SCALE_CLOCK_FREQ_16MHZ,

    .tsc               = false
  };

  // initialise the development board
  if( !scale_init( &scale_conf ) ) {
    return -1;
  }

  char x[] = "hello world";
  uint8_t readIn[8] = {0,0,0,0,0,0,0,0};
  uint8_t* reversed;

  while( true ) {
    // read  the GPI     pin, and hence switch : t   <- GPI
    bool t = scale_gpio_rd( SCALE_GPIO_PIN_GPI        );
    // write the GPO     pin, and hence LED    : GPO <- t
             scale_gpio_wr( SCALE_GPIO_PIN_GPO, t     );

    // write the trigger pin, and hence LED    : TRG <- 1 (positive edge)
             scale_gpio_wr( SCALE_GPIO_PIN_TRG, true  );
    // delay for 500 ms = 1/2 s
    scale_delay_ms( 500 );
    // write the trigger pin, and hence LED    : TRG <- 0 (negative edge)
             scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );
    // delay for 500 ms = 1/2 s
    scale_delay_ms( 500 );

    int n = strlen( x );

    // write x = "hello world" to the UART
    /*for( int i = 0; i < n; i++ ) {
      scale_uart_wr( SCALE_UART_MODE_BLOCKING, x[ i ] );
    }*/

    octetstr_rd(readIn, 8);
    //reverse(readIn, reversed, size);
    //octetstr_wr(readIn, 8);
  }

  return 0;
}

int octetstr_rd( uint8_t* r, int  n_r){
  r[ 0 ] = scale_uart_rd( SCALE_UART_MODE_BLOCKING);
  scale_uart_wr( SCALE_UART_MODE_BLOCKING, (char) r[ 0 ] );
  return 0;
}

void reverse( uint8_t* input, uint8_t* output, int n){
  for(int i = 0; i < n; i++){
    //output[i] = input[n-1-i];
  }
}

void octetstr_wr( const uint8_t* x, int n_x)
{
    //for(int i = 0; i < n_x; i++){
      scale_uart_wr( SCALE_UART_MODE_BLOCKING, (char) x[ 0 ] );
    //}
}
