#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <math.h>
#include "api.h"
#include "reduce.h"
#include "kem.h"

#define NTESTS 1

static void write_canary(unsigned char *d)
{
  *((uint64_t *) d)= 0x0123456789ABCDEF;
}

static int check_canary(unsigned char *d)
{
  if(*(uint64_t *) d !=  0x0123456789ABCDEF)
    return -1;
  else
    return 0;
}

int main(void)
{

  int choice_u, choice_v;
  int i;
  int choice;
  int crypto_kem_dec_success;
  int count_success = 0;
  int analysed_coeff;
  int coeffs_tried = 0;
  int16_t temp_1, temp_2;
  uint16_t bit_1, bit_2;
  int succ_coeff_array[2*KYBER_ETA1+1];
  int other_succ_coeff_array[2*KYBER_ETA1+1];
  int sum = 0;
  int flag = 0;

  int du = (1 << KYBER_DU);
  int dv = (1 << KYBER_DV);

  int choice_u_scheme, choice_v_scheme, choice_scheme;
  int sum_other_coeff_array = 0;

  uint8_t decrypt_success_array[2*KYBER_ETA1+1];

  double float_u, float_v;
  int compressed_u, compressed_v;
  int decompressed_u, decompressed_v, decompressed_v1;

  int choice_2;
  int print_once = 0;

  for(i=0;i<2*KYBER_ETA1+1;i++)
    succ_coeff_array[i] = 0;

    int ham_wt_touch = 0;
    for(int ham_wt = 1; ham_wt <= (1 << (2*KYBER_ETA1+1)); ham_wt++)
    {
      // printf("ham_wt Trial: %d\n", ham_wt);
      ham_wt_touch = 0;
      for(choice_u = 0; choice_u<KYBER_Q; choice_u++)
      {

          float_u = ((double)du/KYBER_Q)*choice_u;
          compressed_u = (int)round(float_u) % du;

          float_u = ((double)KYBER_Q/du)*compressed_u;
          decompressed_u = round(float_u);

          float_v = ((double)dv/KYBER_Q)*0; // choice_v = 0
          compressed_v = (int)round(float_v) % dv;

          float_v = ((double)KYBER_Q/dv)*compressed_v;
          decompressed_v1 = round(float_v);

          for(int ii=0;ii<2*KYBER_ETA1+1;ii++)
              other_succ_coeff_array[ii] = 0;

          for(choice_2 = -1*KYBER_ETA1;choice_2 <= KYBER_ETA1;choice_2++)
          {

              temp_2 = (decompressed_v1 - (decompressed_u*choice_2))%KYBER_Q;
              if(temp_2 < 0)
                  temp_2 = temp_2 + KYBER_Q;

              // temp_2 = csubq(temp_2);
              bit_2 = (((temp_2 << 1) + KYBER_Q/2) / KYBER_Q) & 1;

              other_succ_coeff_array[choice_2+KYBER_ETA1] = bit_2;
          }

          sum_other_coeff_array = 0;
          for(int ii = 0;ii<2*KYBER_ETA1+1;ii++)
          {
              sum_other_coeff_array+=other_succ_coeff_array[ii];
          }

          if(sum_other_coeff_array == 0)
          {
            for(choice_v = 0; choice_v<KYBER_Q; choice_v++)
            {
                for(int ii=0;ii<2*KYBER_ETA1+1;ii++)
                    decrypt_success_array[ii] = 0;

                for(choice = -1*KYBER_ETA1;choice<=KYBER_ETA1;choice++)
                {

                    float_v = ((double)dv/KYBER_Q)*choice_v;
                    compressed_v = (int)round(float_v) % dv;

                    float_v = ((double)KYBER_Q/dv)*compressed_v;
                    decompressed_v = round(float_v);

                    temp_1 = (decompressed_v - (decompressed_u*choice))%KYBER_Q;
                    if(temp_1 < 0)
                        temp_1 = temp_1 + KYBER_Q;

                    // temp_1 = csubq(temp_1);
                    bit_1 = (((temp_1 << 1) + KYBER_Q/2) / KYBER_Q) & 1;

                    decrypt_success_array[choice+KYBER_ETA1] = bit_1;

                }

                int sum_bit_low_array = 0;
                for(int ii = 0;ii<2*KYBER_ETA1+1;ii++)
                {
                    sum_bit_low_array += (decrypt_success_array[ii])*(1<<ii);
                }

                if(sum_bit_low_array == ham_wt)
                {
                    // float_v = ((double)8/KYBER_Q)*choice_v; // choice_v = 0
                    // compressed_v = (int)round(float_v) % 8;

                    int zero_centered_u = barrett_reduce(choice_u);
                    int zero_centered_v = barrett_reduce(choice_v);

                    printf("Choice_u %d, Choice_v: %d\n",zero_centered_u,zero_centered_v);
                    for(int i=0;i<2*KYBER_ETA1+1;i++)
                        printf("%d, ",decrypt_success_array[i]);
                    printf("\n");
                    ham_wt_touch = 1;
                    break;
                }
              }

          }
          if(ham_wt_touch == 1)
            break;
      }

    }

  return 0;
}
