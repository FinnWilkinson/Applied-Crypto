#include  "rsa_implementation.h"

void rsa_keygen( mpz_t N, mpz_t e, mpz_t d, int lambda);
void l2r_1exp( mpz_t r, mpz_t x, mpz_t y, mpz_t N);
void rsa_enc( mpz_t c, mpz_t m, mpz_t e, mpz_t N);
void rsa_dec( mpz_t m, mpz_t c, mpz_t d, mpz_t N);

int main(int argc, char const *argv[]) {

  return 0;
}

void rsa_keygen( mpz_t N, mpz_t e, mpz_t d, int lambda){
  gmp_randstate_t state;
  gmp_randinit_default(state);
  mpz_t p; mpz_t q; mpz_t maxVal;
  mpz_init(p); mpz_init(q); mpz_init_set_str(maxVal, "18446744073709551616" ,10);

  //1. select random primes p and q (mpz_probab_prime_p for primality), max size 2^lambda
  while(mpz_probab_prime_p(p,50) !=2){
    mpz_urandomm(p, state, maxVal);
  }
  while(mpz_probab_prime_p(p,50) !=2){
    mpz_urandomm(q, state, maxVal);
  }

  //2. compute N= p*q
  mpz_mul(N, p, q);

  //3. compute totient(N)
  mpz_t totientN; mpz_init(totientN);
  mpz_mul(totientN, (p-1), (q-1));


  //4.select random e from Z(N)* s.t. gcd(e, totient(N)) = 1  (mpz_gcd)
  mpz_t gcdVal; mpz_init(gcdVal);

  while(1){
    mpz_urandomm(e, state, N);
    if(e != 0){
      mpz_gcd(gcdVal, e, totientN);
      if(gcdVal == 1){
        break;
      }
    }
  }

  //5. compute d=e^-1 (mod totient(N))  (mpz_invert)
  mpz_invert(d, e, totientN);
}

void l2r_1exp( mpz_t r, mpz_t x, mpz_t y, mpz_t N){

}

void rsa_enc( mpz_t c, mpz_t m, mpz_t e, mpz_t N){

}

void rsa_dec( mpz_t m, mpz_t c, mpz_t d, mpz_t N){

}
