#include  "rsa_implementation.h"

//not perfect implementation as generation of random parts is pseudo random and so is identical from
//run to run

void rsa_keygen( mpz_t N, mpz_t e, mpz_t d, int lambda);
void l2r_1exp( mpz_t r, mpz_t x, mpz_t y, mpz_t N);
void rsa_enc( mpz_t c, mpz_t m, mpz_t e, mpz_t N);
void rsa_dec( mpz_t m, mpz_t c, mpz_t d, mpz_t N);

int main(int argc, char const *argv[]) {
  mpz_t N; mpz_init(N);
  mpz_t e; mpz_init(e);
  mpz_t d; mpz_init(d);
  int lambda = 128;

  mpz_t m; mpz_init_set_str(m, "1212121212121212", 10);
  mpz_t c; mpz_init(c);

  rsa_keygen(N, e, d, lambda);
  gmp_printf("message : %Zd\n", m);
  rsa_enc(c, m, e, N);
  gmp_printf("ciphertext: %Zd\n", c);
  rsa_dec(m, c, d, N);
  gmp_printf("message : %Zd\n", m);



  return 0;
}

void rsa_keygen( mpz_t N, mpz_t e, mpz_t d, int lambda){
  gmp_randstate_t state; gmp_randinit_default(state);
  mpz_t seed; mpz_init_set_str(seed, "190457847393835782988496979420", 10);
  gmp_randseed(state, seed);
  mpz_t p; mpz_t q; mpz_t maxVal;
  mpz_init(p); mpz_init(q); mpz_init_set_str(maxVal, "18446744073709551616" ,10);
  //1. select random primes p and q (mpz_probab_prime_p for primality), max size 2^lambda
  while(mpz_probab_prime_p(p,50) ==0){
    mpz_urandomm(p, state, maxVal);
  }
  gmp_printf("p: %Zd\n", p);
  while(mpz_probab_prime_p(q,50) ==0){
    mpz_urandomm(q, state, maxVal);
  }
  gmp_printf("q: %Zd\n", q);

  //2. compute N= p*q
  mpz_mul(N, p, q);

  //3. compute totient(N)
  mpz_t totientN; mpz_init(totientN);
  mpz_sub_ui(p, p, 1);
  mpz_sub_ui(q, q, 1);
  mpz_mul(totientN, p, q);

  //4.select random e from Z(N)* s.t. gcd(e, totient(N)) = 1  (mpz_gcd)
  mpz_t gcdVal; mpz_init(gcdVal);

  while(1){
    mpz_urandomm(e, state, N);
    if(e != 0){
      mpz_gcd(gcdVal, e, totientN);
      if(mpz_cmp_si(gcdVal,1) == 0){
        break;
      }
    }
  }

  //5. compute d=e^-1 (mod totient(N))  (mpz_invert)
  mpz_invert(d, e, totientN);
}

void l2r_1exp( mpz_t r, mpz_t x, mpz_t y, mpz_t N){
  mpz_init_set_str(r, "1", 10);
  for (int i = mpz_sizeinbase(y, 2) - 1; i >=0; i--) {
    mpz_mul(r, r, r);
    mpz_mod(r, r, N);
    if(mpz_tstbit(y, i) == 1){
      mpz_mul(r, r, x);
      mpz_mod(r, r, N);
    }
  }
}

void rsa_enc( mpz_t c, mpz_t m, mpz_t e, mpz_t N){
  l2r_1exp(c, m, e, N);
}

void rsa_dec( mpz_t m, mpz_t c, mpz_t d, mpz_t N){
  l2r_1exp(m, c, d, N);
}
