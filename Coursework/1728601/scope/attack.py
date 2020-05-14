# Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
# which can be found via http://creativecommons.org (and should be included as 
# LICENSE.txt within the associated archive or repository).

import numpy, struct, sys, math, time

## Load  a trace data set from an on-disk file.
## 
## \param[in] f the filename to load  trace data set from
## \return    t the number of traces
## \return    s the number of samples in each trace
## \return    M a t-by-16 matrix of AES-128  plaintexts
## \return    C a t-by-16 matrix of AES-128 ciphertexts
## \return    T a t-by-s  matrix of samples, i.e., the traces

def traces_ld( f ) :
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

  return t, s, M, C, T

## Store a trace data set into an on-disk file.
## 
## \param[in] f the filename to store trace data set into
## \param[in] t the number of traces
## \param[in] s the number of samples in each trace
## \param[in] M a t-by-16 matrix of AES-128  plaintexts
## \param[in] C a t-by-16 matrix of AES-128 ciphertexts
## \param[in] T a t-by-s  matrix of samples, i.e., the traces

def traces_st( f, t, s, M, C, T ) :
  fd = open( f, "wb" )

  def wr( x, y ) :
    fd.write( struct.pack( x, y ) )

  wr( '<I', t   )
  wr( '<I', s   )

  for i in range( t ) :
    for j in range( 16 ) :
      wr( '<B', M[ i, j ] )

  for i in range( t ) :
    for j in range( 16 ) :
      wr( '<B', C[ i, j ] )

  for i in range( t ) :
    for j in range( s  ) :
      wr( '<h', T[ i, j ] )

  fd.close()

## Attack implementation, as invoked from main after checking command line
## arguments.
##
## \param[in] argc number of command line arguments
## \param[in] argv           command line arguments

def attack( argc, argv ):
  start_time = time.time()

  print("Loading in Data ...")
  number_traces, number_samples, plaintexts, ciphertexts, samples = traces_ld(argv[argc-1])
  print("Finished Loading\n")

  #set up needed constant values
  hamming_Weights = numpy.zeros(256, dtype=numpy.uint8 ) #hamming weight lookup table
  for i in range(0,256):
    hamming_Weights[i] = (getHammingWeight(i))
  key_Bytes = numpy.arange(0,256, dtype = numpy.uint8 ) #key hypothesis

  #initialise needed data arrays
  values = numpy.zeros( (number_traces,256) , dtype = numpy.uint8 ) #plaintext xor keyguess
  hype_Power_Values = numpy.zeros( (number_traces, 256) , dtype = numpy.uint8 ) #hypothetical power values
  correlation_results = numpy.zeros( (256, number_samples) ) #correlation values
  final_Key_Guess = numpy.zeros(16, dtype = numpy.uint8 ) #final key guess

  for i in range(0,16) :
    print("Making Guess for Key Byte {} ..." .format(i+1))
    #calc values of byte i (i-th message byte xor with each keybyte ) = V (size 1000x256)
    print("Forming Intermediate Values ...")
    for y in range(0, number_traces):
      for x in range(0, 256):
        values[y,x] = hamming_Weights[(plaintexts[y,i] ^ key_Bytes[x])]

    #H = hamming weight of each value in V
    print("Calculating Hamming Weights ...")
    hype_Power_Values = values

    #compare each column of H with each column of T and get correlation coeficient matrix R: h(i) with t(j) for i=1,..,K and j=1,..,T
    print("Calculating Correlation With Aquired Traces ...")
    max_Correlation_Val = 0
    max_correlation_index = -1
    for y in range(0, 10000):
      for x in range(0, 256):
        correlation_results[x,y] = calcCorrelationValue((hype_Power_Values[:,x]).astype(int), numpy.single(samples[:,y]).astype(int))
        if correlation_results[x,y] > max_Correlation_Val:
          max_Correlation_Val = correlation_results[x,y]
          max_correlation_index = x
    #value with highest correlation value's row = key value guess
    print(max_Correlation_Val)
    print(max_correlation_index)
    final_Key_Guess[i] = max_correlation_index
    print("Guess Made for Key Byte {}\n" .format(i+1))

  print("Time Elapsed : {} Seconds\n" .format(time.time()-start_time))
  numpy.set_printoptions(formatter={'int':hex})
  print("Secret Key Guess : {}" .format(final_Key_Guess))
  print("Plaintext Example : {}" .format(plaintexts[0,:]))
  print("Ciphertext Example : {}\n" .format(ciphertexts[0,:]))

  

#calulate the hamming weight of a number n
def getHammingWeight(n):
  c = 0
  while n:
    c += 1
    n &= n-1
  return c

#calculate the correlation value of the columns provided
# \param[in] h_col = hypothesis power value column
# \param[in] t_col = actual trace power value column
def calcCorrelationValue(h_col, t_col):
  h_mean = numpy.mean(h_col)
  t_mean = numpy.mean(t_col)
  
  h_col = numpy.subtract(h_col, h_mean)
  t_col = numpy.subtract(t_col, t_mean)

  covariance = numpy.sum(numpy.multiply(h_col, t_col))
  denominator = math.sqrt(numpy.sum(numpy.power(h_col, 2)) * numpy.sum(numpy.power(t_col, 2)))

  if denominator != 0:
    return covariance / denominator
  else:
    return 0

if ( __name__ == '__main__' ) :
  attack( len( sys.argv ), sys.argv )
