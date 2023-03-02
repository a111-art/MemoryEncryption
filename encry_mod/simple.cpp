#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <math.h>
#include <algorithm>
#include "encry_mod/alg_src/ElasticCuckooHashing/elastic_cuckoo_table.h"
using namespace std;
void simple_example(uint32_t d, uint64_t size, char *hash_func, uint8 elastic,
                    uint8_t oneshot, float rehash_threshold, uint8_t scale,
                    uint8_t swaps, uint8_t priority) 
{
  uint64_t i = 0;
  uint64_t N = (1<<30);
  // N <<= 1;
  printf("in simple_example: N=%lld\n",N);
  uint64_t *test_values = NULL;
  outkeyTable new_elem;
  elasticCuckooTable_t elasticCuckooHT;
  cuckooTable_t cuckooHT;

  if (elastic) 
  {
    create_elastic(d, size, &elasticCuckooHT, hash_func, rehash_threshold,
                   scale, swaps, priority);
  } 
  else 
  {
    create(d, size, &cuckooHT, hash_func);
  }

  // test_values = (uint64_t *)malloc(N * sizeof(uint64_t));

  // for (i = 0; i < N; i++) 
  // {
  //   test_values[i] = 0;
  // }

  for (i = 0; i < N; i++) {
    new_elem.valid = 1;

    if (elastic) 
    {
      do 
      {
        _rdrand16_step((unsigned short *)&new_elem.VMID);
        _rdrand16_step((unsigned short *)&new_elem.PID);
      } while (find_elastic(&new_elem, &elasticCuckooHT) != NULL);

    } 
    else 
    {
      do 
      {
        _rdrand16_step((unsigned short *)&new_elem.VMID);
        _rdrand16_step((unsigned short *)&new_elem.PID);
      } while (find(&new_elem, &cuckooHT) != NULL);
    }

    // test_values[i] = new_elem.value;

    if (elastic) {
      insert_elastic(&new_elem, &elasticCuckooHT, 0, 0);
    } 
    else {
      insert(&new_elem, &cuckooHT);
    }

    if (elastic) 
    {
      evaluate_elasticity(&elasticCuckooHT, oneshot);
    }
  }

  if (elastic) {
    destroy_elastic(&elasticCuckooHT);
  } else {
    destroy(&cuckooHT);
  }
}

int main(int argc, char **argv) 
{
  uint32_t d = 4, size = 0, elastic = 0, oneshot = 0, scale = 0, swaps = 0;
  char hash_func[20];
  float threshold = 0;
  uint8_t priority = 0;

  assert(argc == 10 || argc == 5);
  d = strtol(argv[1], NULL, 10);
  if (d < 2) {
    printf("Number of ways required to be greater than 2\n");
  }
  size = strtol(argv[2], NULL, 10);
  if (strcmp(argv[3], "blake2") == 0) {
    strcpy(hash_func, "blake2");
  } else if (strcmp(argv[3], "city") == 0) {
    strcpy(hash_func, "city");
  } else {
    printf("Hash function not found\n");
    return 0;
  }

  if (strcmp(argv[4], "elastic") == 0) {
    elastic = 1;
  } else {
    elastic = 0;
  }

  if (elastic) {
    if (strcmp(argv[5], "oneshot") == 0) {
      oneshot = 1;
    } else {
      oneshot = 0;
    }
    threshold = strtof(argv[6], NULL);
    scale = strtol(argv[7], NULL, 10);
    swaps = strtol(argv[8], NULL, 10);
    priority = strtol(argv[9], NULL, 10);
  }

  simple_example(d, size, hash_func, elastic, oneshot, threshold, scale, swaps,
                 priority);

  return 0;
}

