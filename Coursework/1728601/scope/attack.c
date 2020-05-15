#include  <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void attack( int argc, char* argv[] );
void traces_ld(char* f, int* t, int* s, uint8_t** M, uint8_t** C, int16_t** T);
float calcCorrelationValue(uint8_t* values, int16_t* samples , int key_hype_number, int sample_number);
uint8_t sbox( uint8_t a); 
uint8_t xtime( uint8_t a);
uint8_t aes_gf28_mul( uint8_t a, uint8_t b);
uint8_t aes_gf28_inv( uint8_t a);


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
  printf("... Finished Loading\n");

  //set up needed constant values
  uint8_t hamming_Weights[256], key_values[256];
  for(int i=0; i<256; i++){
    hamming_Weights[i] = __builtin_popcount(i);        // Hamming weight lookup table
    key_values[i] = i;                                 // Key Hypothesis' 
  }
  
  //Initialise needed data arrays
  uint8_t values[number_traces * 256];                  //Sbox result hypothetical power values
  float *correlation_values;                            //Corelation values
  correlation_values = malloc(256 * number_samples * sizeof(float));
  uint8_t final_key_guess[16];                            //Secret Key guess
  //Main attack loop
  for(int i=0; i<16; i++){
    printf("Making Guess for Key Byte %d ...\n", i+1);

    printf("Calculating Hypothetical Power Usage ...\n");
    for(int y=0; y<number_traces; y++){
      for(int x=0; x<256; x++){
        values[(y*256) + x] = hamming_Weights[sbox(plaintexts[(y*16) + i] ^ key_values[x])];
      }
    }

    printf("Calculating Correlation With Aquired Traces ...\n");
    float max_Correlation_Val = 0.0f;
    int max_correlation_index = -1;
    for(int y=0; y<number_samples; y++){
      for(int x=0; x<256; x++){
        //mend
        correlation_values[(y*256) + x] = calcCorrelationValue(values, samples, x, y);
        if (correlation_values[(y*256) + x] > max_Correlation_Val){
          max_Correlation_Val = correlation_values[(y*256) + x];
          max_correlation_index = x;
        }
      }
    }
    //value with highest correlation value's row = key value guess
    printf("%f\n", max_Correlation_Val);
    printf("%d\n", max_correlation_index);
    final_key_guess[i] = max_correlation_index;

    printf("Guess Made for Key Byte %d\n\n", i+1);
  }

  end = clock();
  cpu_time_used = ((double) (end-start)) / CLOCKS_PER_SEC;
  printf("Time Elapsed : %f Seconds\n", cpu_time_used);

  printf("Secret Key Guess : {%x", final_key_guess[0]);
  for(int i=1; i<16; i++){
    printf(", %x", final_key_guess[i]);
  }
  printf("}\n");

  printf("Plaintext Example : {%x", plaintexts[0]);
  for(int i=1; i<16; i++){
    printf(", %x", plaintexts[i]);
  }
  printf("}\n");
  
  printf("Ciphertext Example : {%x", ciphertexts[0]);
  for(int i=1; i<16; i++){
    printf(", %x", ciphertexts[i]);
  }
  printf("}\n");     
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
  uint8_t message_input[16];
  for(int i=0; i<t[0]; i++){
    fread(message_input, 16, 1, data);
    for(int j=0; j<16; j++){
      M[0][(i*16) + j] = message_input[j];
    }
  }

  //get Ciphertext
  uint8_t ciphertext_input[16];
  for(int i=0; i<t[0]; i++){
    fread(ciphertext_input, 16, 1, data);
    for(int j=0; j<16; j++){
      C[0][(i*16) + j] = ciphertext_input[j];
    }
  }

  //get trace data
  int16_t trace_input[s[0]];
  for(int i=0; i<t[0]; i++){
    fread(trace_input, s[0], 1, data);
    for(int j=0; j<s[0]; j++){
      T[0][(i*s[0]) + j] = ((int16_t)trace_input[j]);
    }
  }

  fclose(data);
  return;
}

//calculate the correlation value of the columns provided
// \param[in] h_col = hypothesis power value column
// \param[in] t_col = actual trace power value column
float calcCorrelationValue(uint8_t* values, int16_t* samples , int key_hype_number, int sample_number)
{

  return 0.0f;
}

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

