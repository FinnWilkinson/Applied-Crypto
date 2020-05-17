#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <openssl/aes.h>

void attack( int argc, char* argv[] );
void traces_ld(char* f, int* t, int* s, uint8_t** M, uint8_t** C, int16_t** T);
float calcCorrelationValue(uint8_t** values, int16_t** samples, int key_hype_number, int sample_number, int number_traces, int number_samples);
uint8_t sbox( uint8_t a); 
uint8_t xtime( uint8_t a);
uint8_t aes_gf28_mul( uint8_t a, uint8_t b);
uint8_t aes_gf28_inv( uint8_t a);

void check_key(uint8_t* plaintexts, uint8_t* ciphertexts, uint8_t* key);

int main( int argc, char* argv[] ) 
{
  attack( argc, argv );
}

//Attack implementation, as invoked from main after checking command line
//arguments.
//
// \param[in] argc number of command line arguments
// \param[in] argv           command line arguments

void attack( int argc, char* argv[] )
{  
  clock_t start, end;
  double cpu_time_used;
  int number_traces = 0;
  int number_samples = 0;
  uint8_t *plaintexts; //number_traces x 16 (width = 16 height = number_traces)
  uint8_t *ciphertexts; //number_traces x 16
  int16_t *samples; //number_traces x number_samples (width = samples, height = traces)

  start = clock();

  //Load in data
  printf("Loading in Data ...\n");
  traces_ld(argv[argc-1], &number_traces, &number_samples, &plaintexts, &ciphertexts, &samples);
  printf("... Finished Loading\n\n");

  //set up needed constant values
  uint8_t hamming_Weights[256], key_values[256];
  for(int i=0; i<256; i++){
    hamming_Weights[i] = __builtin_popcount(i);        // Hamming weight lookup table
    key_values[i] = i;                                 // Key Hypothesis' 
  }
  
  //Initialise needed data arrays
  uint8_t *values;                                      //Sbox result hypothetical power values
  values = malloc(number_traces * 256 * sizeof(uint8_t));
  uint8_t final_key_guess[16];                          //Secret Key guess
  //Main attack loop
  for(int i=0; i<16; i++){
    printf("Making Guess for Key Byte %d ...\n", i+1);

    printf("Calculating Hypothetical Power Usage ...\n");
    for(int y=0; y<number_traces; y++){
      for(int x=0; x<256; x++){
        values[(x*number_traces) + y] = hamming_Weights[sbox(plaintexts[(y*16) + i] ^ key_values[x])];
      }
    }

    printf("Calculating Correlation With Aquired Traces ...\n");
    float max_Correlation_Val = -1.0f;
    float min_Correlation_Val = 1.0f;
    int min_correlation_index = -1;
    int max_correlation_index = -1;
    float result = 0.0f;
    for(int y=0; y<number_samples; y++){
      for(int x=0; x<256; x++){
        result = calcCorrelationValue(&values, &samples, x, y, number_traces, number_samples);
        if (result > max_Correlation_Val){
          max_Correlation_Val = result;
          max_correlation_index = x;
        }
        else if (result < min_Correlation_Val){
          min_Correlation_Val = result;
          min_correlation_index = x;
        }
      }
    }
    
    //value with biggest correlation value's row = key value guess
    if(max_Correlation_Val > -min_Correlation_Val) final_key_guess[i] = max_correlation_index;
    else if(min_Correlation_Val < -max_Correlation_Val) final_key_guess[i] = min_correlation_index;

    printf("Guess Made for Key Byte %d\n\n", i+1);
  }

  end = clock();
  cpu_time_used = ((double) (end-start)) / CLOCKS_PER_SEC;
  printf("Time Elapsed : %f Seconds\n", cpu_time_used);

  printf("Secret Key Guess : {%x", final_key_guess[0]);
  for(int i=1; i<16; i++){
    printf(", %x", final_key_guess[i]);
  }
  printf("}\n\n");     

  check_key(plaintexts, ciphertexts, final_key_guess);
}

void check_key(uint8_t* plaintexts, uint8_t* ciphertexts, uint8_t* key)
{
  printf("Validating Key Guess ...\n");
  AES_KEY rk;
  AES_set_encrypt_key( key, 128, &rk );

  uint8_t output[16], plaintext_hold[16], ciphertext_hold[16];
  for(int i=0; i<1000; i++){
    memcpy(plaintext_hold, plaintexts + (i*16), 16*(sizeof(uint8_t)));
    memcpy(ciphertext_hold, ciphertexts + (i*16), 16*(sizeof(uint8_t)));
    //encrypt
    AES_encrypt(plaintext_hold, output, &rk);
    //check output
    for(int j=0; j<16; j++){
      if(output[j] != ciphertext_hold[j]){
        printf("Wrong Key. Failed at : %d\n", i);
        exit(0);
      }
    }
  }
  printf("Correct Key Guess!\n");
}
  
//Load  a trace data set from an on-disk file.
// 
// \param[in] f the filename to load  trace data set from
// \return    t the number of traces
// \return    s the number of samples in each trace
// \return    M a t-by-16 matrix of AES-128  plaintexts
// \return    C a t-by-16 matrix of AES-128 ciphertexts
// \return    T a t-by-s  matrix of samples, i.e., the traces

void traces_ld(char* f, int* t, int* s, uint8_t** M, uint8_t** C, int16_t** T) 
{
  FILE *data;
  data = fopen(f, "rb");

  //get number of traces and number of samples
  fread(t, 4, 1, data);
  fread(s, 4, 1, data);
  
  //Initialise matricies
  M[0] = malloc(t[0]*16*sizeof(uint8_t));
  C[0] = malloc(t[0]*16*sizeof(uint8_t));
  T[0] = malloc(t[0]*s[0]*sizeof(int16_t));

  //get Plaintexts
  fread(&M[0][0], 1, 16*t[0], data);

  //get Ciphertext
  fread(&C[0][0], 1, 16*t[0], data);

  //get trace data, stored in column major
  int16_t data_buffer[s[0]];
  for(int i=0; i<t[0]; i++){
    fread(data_buffer, 2, s[0], data);
    for(int j=0; j<s[0]; j++){
      T[0][i + (j*t[0])] = data_buffer[j];
    }
  }

  fclose(data);
  return;
}

//calculate the correlation value of the columns provided
float calcCorrelationValue(uint8_t** values, int16_t** samples, int key_hype_number, int sample_number, int number_traces, int number_samples)
{
  //calculate mean of each row (as both trace values and samples are in column major for speed)
  float values_mean = 0.0f;
  float samples_mean = 0.0f;
  for(int i=0; i<number_traces; i++){
    values_mean += values[0][(key_hype_number*number_traces) + i];
    samples_mean += samples[0][(sample_number*number_traces) + i];
  }
  values_mean /= number_traces;
  samples_mean /= number_traces;
  
  //calculate appropriate covariance and variances for Correlation Coefficient calculation
  float covariance = 0.0f;
  float var_values = 0.0f;
  float var_samples = 0.0f;
  for(int i=0; i<number_traces; i++){
    covariance += (values[0][(key_hype_number*number_traces) + i] - values_mean) * (samples[0][(sample_number*number_traces) + i] - samples_mean);
    var_values += (values[0][(key_hype_number*number_traces) + i] - values_mean) * (values[0][(key_hype_number*number_traces) + i] - values_mean);
    var_samples += (samples[0][(sample_number*number_traces) + i] - samples_mean) * (samples[0][(sample_number*number_traces) + i] - samples_mean);
  }

  return (covariance / (sqrt(var_values) * sqrt(var_samples)) );
}

//ALL CODE BELOW IS FOR S-BOX IMPLEMENTATION USED IN target.c PROGRAM
uint8_t sbox( uint8_t a) {
  uint8_t gOfa = aes_gf28_inv(a);
  uint8_t fOfa = (0x63)^gOfa^(gOfa<<1)^(gOfa<<2)^(gOfa<<3)^(gOfa<<4)^(gOfa>>7)^(gOfa>>6)
                    ^(gOfa>>5)^(gOfa>>4);
  return fOfa;
}

//multiplies a by indeterminant x under modulo p(x)
uint8_t xtime( uint8_t  a) {
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

