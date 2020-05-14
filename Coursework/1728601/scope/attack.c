#include  <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void attack( int argc, char* argv );

int main( int argc, char* argv[] ) {
    attack( argc, argv );
}

//Attack implementation, as invoked from main after checking command line
//arguments.
//
// \param[in] argc number of command line arguments
// \param[in] argv           command line arguments

void attack( int argc, char* argv )
{   int number_traces = 0;
    int number_samples = 0;
    uint8_t* plaintexts;
    uint8_t* ciphertexts;
    uint16_t* samples;
    printf("Loading in Data ...\n");
    traces_ld(argv[argc-1], number_traces, number_samples, plaintexts, ciphertexts, samples);
    printf("... Finished Loading\n");
}
  
//Load  a trace data set from an on-disk file.
// 
// \param[in] f the filename to load  trace data set from
// \return    t the number of traces
// \return    s the number of samples in each trace
// \return    M a t-by-16 matrix of AES-128  plaintexts
// \return    C a t-by-16 matrix of AES-128 ciphertexts
// \return    T a t-by-s  matrix of samples, i.e., the traces

void traces_ld(char* f, int* t, int* s, uint8_t* M, uint8_t* C, uint16_t* T) 
{
  fd = open( f, "rb" )

  def rd( x ) :
    ( r, ) = struct.unpack( x, fd.read( struct.calcsize( x ) ) ) ; return r

  t = rd( '<I' )
  s = rd( '<I' )

  M = numpy.zeros( ( t, 16 ), dtype = numpy.uint8 )
  C = numpy.zeros( ( t, 16 ), dtype = numpy.uint8 )
  T = numpy.zeros( ( t,  s ), dtype = numpy.int16 )

  for i in range( t ) :
    for j in range( 16 ) :
      M[ i, j ] = rd( '<B' )

  for i in range( t ) :
    for j in range( 16 ) :
      C[ i, j ] = rd( '<B' )

  for i in range( t ) :
    for j in range( s  ) :
      T[ i, j ] = rd( '<h' )

  fd.close()
}