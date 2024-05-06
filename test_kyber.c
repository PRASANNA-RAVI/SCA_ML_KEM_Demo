#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <math.h>
#include "api.h"
#include "reduce.h"
#include "kem.h"
#include "randombytes.h"
#include "params.h"

int16_t u_coeff, v_coeff;
int16_t u_poly_index,u_coeff_index;
uint8_t global_first_bit;
uint8_t global_message_oracle_value[KYBER_SYMBYTES];

int16_t secret_key_module[KYBER_K][KYBER_N];

extern unsigned int parallel_factor;

#define NTESTS 1

#if KYBER_K == 2

int16_t choice_u[6] = {207, 2, 106, 70, 106, 70};
int16_t choice_v[6] = {937, 729, 521, 521, -728, -728};

int zero_rep = 2;
int one_rep = 3;
int NO_CTS = 6;

int16_t oracle_responses[6][7] = {
                    {1, 1, 1, 1, 0, 0, 0},
                    {1, 1, 1, 0, 0, 0, 0},
                    {1, 1, 0, 0, 0, 0, 0},
                    {1, 0, 0, 0, 0, 0, 0},
                    {0, 0, 0, 0, 0, 1, 1},
                    {0, 0, 0, 0, 0, 0, 1}
                   };

#elif KYBER_K == 3

int16_t choice_u[4] = {207, 2, 106, 106};
int16_t choice_v[4] = {937, 729, 521, -728};

int zero_rep = 1;
int one_rep = 2;
int NO_CTS = 4;

int16_t oracle_responses[4][5] = {
                    {1, 1, 1, 0, 0},
                    {1, 1, 0, 0, 0},
                    {1, 0, 0, 0, 0},
                    {0, 0, 0, 0, 1}
                   };

#elif KYBER_K == 4

int16_t choice_u[4] = {104, 1, 53, 53};
int16_t choice_v[4] = {885, 781, 677, -780};

int zero_rep = 1;
int one_rep = 2;
int NO_CTS = 4;

int16_t oracle_responses[4][5] = {
                    {1, 1, 1, 0, 0},
                    {1, 1, 0, 0, 0},
                    {1, 0, 0, 0, 0},
                    {0, 0, 0, 0, 1}
                   };

#endif


#if KYBER_K == 2
  #define KYBER_DU 10
  #define KYBER_DV 4
#elif KYBER_K == 3
  #define KYBER_DU 10
  #define KYBER_DV 4
#elif KYBER_K == 4
  #define KYBER_DU 11
  #define KYBER_DV 5
#endif

static int test_kem_cca()
{

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss_a[CRYPTO_BYTES], ss_b[CRYPTO_BYTES];
  int i, j;


  //Generation of secret key sk and public key pk pair
  crypto_kem_keypair(pk, sk);

  // uint8_t bit_now;
  // uint8_t bit_now_start;
  uint8_t bit_now_array[parallel_factor][20];
  // uint8_t touched = 0;
  int16_t secret_coeff[KYBER_K][KYBER_N];
  int16_t secret_now[parallel_factor];

  int queries = 0;

  int sum_oracle_response_array_unique_identification[2*KYBER_ETA1 + 1];

  for(int rrr = 0; rrr < 2*KYBER_ETA1 + 1; rrr++)
  {
    int summm = 0;
    for(int ee = 0; ee < NO_CTS; ee++)
      summm = summm + (1 << ee) * oracle_responses[ee][rrr];

    sum_oracle_response_array_unique_identification[rrr] = summm;
  }

  int succ_count = 0;
  // int found_coeff = 0;

  for(i = 0; i < KYBER_K; i++)
	{
    u_poly_index = i;

		for(j = 0; j < KYBER_N; j=j+parallel_factor)
		{
      
      #if (INTERACTIVE_MODE == 1)
      printf("\n******************************************************************************\n");
      
      if(j == 0)
        printf("\nTrying to Recover Secret Coefficient %d of polynomial %d\n\n", i, j);
      else
        printf("\nTrying to Recover Secret Coefficient %d of polynomial %d\n\n", i, (256-j));

      #endif

      u_coeff_index = j;

      for(unsigned int pqp = 0; pqp < parallel_factor; pqp++)
      {
        for(int hh = 0; hh < 20; hh++)
          bit_now_array[pqp][hh] = 100;
      }

      for(int no_ct = 0; no_ct < NO_CTS; no_ct++)
      {

        u_coeff = choice_u[no_ct];
        v_coeff = choice_v[no_ct];

        #if (INTERACTIVE_MODE == 1)

          printf("\n\n###############################\n\n");
          printf("\n\nCiphertext Query: %d\n\n", no_ct);

        #endif

        crypto_kem_enc_attack(ct, ss_a, pk);
        crypto_kem_dec(ss_b, ct, sk);

        #if (INTERACTIVE_MODE == 0)

        printf("Decrypted Message: [ ");
        for(int jj = 0; jj < 32; jj++)
        {
          printf("%02x, ", global_message_oracle_value[jj]);
        }
        printf(" ]\n");

        #endif
        
        #if (INTERACTIVE_MODE == 1)

          printf("\nOracle Response: %d\n", global_message_oracle_value[0]&0x1);

        #endif

        queries = queries+1;

        int byte_pos_of_message;
        int bit_pos_of_message;
        for(unsigned int parallel_rep = 0; parallel_rep < parallel_factor; parallel_rep++)
        {
          byte_pos_of_message = (int)parallel_rep/8;
          bit_pos_of_message = (int)parallel_rep%8;
          bit_now_array[parallel_rep][no_ct] = (global_message_oracle_value[byte_pos_of_message]>>bit_pos_of_message) & 0x1;
        }

      }

      int sum_bit_now_array[parallel_factor];

      for(unsigned int yry = 0; yry < parallel_factor; yry++)
        sum_bit_now_array[yry] = 0;

      for(unsigned int parallel_rep = 0; parallel_rep < parallel_factor; parallel_rep++)
      {
        for(int cc = 0; cc < NO_CTS; cc++)
          sum_bit_now_array[parallel_rep] = sum_bit_now_array[parallel_rep] + (1 << cc) * bit_now_array[parallel_rep][cc];
      }

      for(unsigned int parallel_rep = 0; parallel_rep < parallel_factor; parallel_rep++)
      {
        for(int cc = 0; cc < (2*KYBER_ETA1+1); cc++)
        {
          if(sum_bit_now_array[parallel_rep] == sum_oracle_response_array_unique_identification[cc])
          {
            secret_now[parallel_rep] = cc - (KYBER_ETA1);
          }
        }
      }


      



      for(unsigned int parallel_rep = 0; parallel_rep < parallel_factor; parallel_rep++)
      {

        unsigned int index_now = j+parallel_rep;
        if(index_now < parallel_factor)
        {
          secret_coeff[i][index_now] = secret_now[parallel_rep];

          #if (INTERACTIVE_MODE == 1)

          int identified_correct = 0;
          int number_got_from_user;
          
          // printf("Correct Value is: %d\n", secret_key_module[i][index_now]);
          while(identified_correct == 0)
          {
            printf("Guess the Secret Coefficient: ");
            scanf("%d", &number_got_from_user);
            if(number_got_from_user == secret_key_module[i][index_now])
            {
              printf("Your guess of %d for the coefficient is correct...\n", number_got_from_user);
              identified_correct = 1;
            }
            else
            {
              printf("Your guess for the coefficient is wrong... Try again\n");
            }

          }

          #endif

        }
        else
        {
          secret_coeff[i][KYBER_N-(j)+parallel_rep] = -1*secret_now[parallel_rep];

          #if (INTERACTIVE_MODE == 1)

          int identified_correct = 0;
          int number_got_from_user;

          // printf("Correct Value is: %d\n", secret_coeff[i][KYBER_N-(j)+parallel_rep]);
          while(identified_correct == 0)
          {
            printf("Guess the Secret Coefficient: ");
            scanf("%d", &number_got_from_user);
            if(number_got_from_user == -1*secret_key_module[i][KYBER_N-(j)+parallel_rep])
            {
              printf("Your guess of %d for the coefficient is correct...\n", number_got_from_user);
              identified_correct = 1;
            }
            else
            {
              printf("Your guess for the coefficient is wrong... Try again\n");
            }

          }

          #endif

        }



      }


    }



    for(int yr1 = 0; yr1 < KYBER_N; yr1++)
    {
      if(secret_key_module[i][yr1] == secret_coeff[i][yr1])
        succ_count = succ_count+1;
    }

    printf("\n\nSecret Coeff Recovered: %d\n\n", i);
    for(int yr1 = 0; yr1 < KYBER_N; yr1++)
    {
      printf("%d, ", secret_coeff[i][yr1]);
    }
    printf("\n");

  }

  if(succ_count == KYBER_K*KYBER_N)
  {
    printf("Success...\n");
    printf("Key Recovered with Success Rate:%f\n",(((float)succ_count)/(KYBER_K*KYBER_N)));
    printf("****************************************************************************\n");
  }
  else
  {
    printf("Failure...\n");
    printf("Key Recovered with Success Rate:%f\n",(((float)succ_count)/(KYBER_K*KYBER_N)));
    printf("****************************************************************************\n");
  }

  return queries;

}



int main(void)
{

  int queries;

  double average_queries = 0;
  // For Doing Attack...

  for(int i = 0; i < NTESTS; i++)
  {

   printf("Attack Test: %d\n", i);
   queries = test_kem_cca();

   if(i == 0)
    average_queries = queries;
   else
    average_queries = average_queries + (double)(queries - average_queries)/(i+1);

    printf("Queries: %f, Average Queries: %f\n",(float)queries,average_queries);

  }

	return 0;
}


