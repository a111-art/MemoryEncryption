#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "elastic_cuckoo_table.h"
// #define DEBUG_CUCKOO 0

#define HASH_SIZE 4
#define MAX_RETRIES 64
#define EXTEND 1.25
namespace gem5
{
  namespace encry_mod
  {
    uint64_t_h Gcnt=0; //insert counter
    unsigned char uint16max[2]={0xFF,0xFF};
    unsigned char uint256max[32]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
                                  };

    uint64_t_h hash_size(uint64_t_h size);
    void blake3Hash(void *out,size_t outlen,const void* in,size_t inlen,const void *key,size_t keylen)
    {
        assert(keylen == BLAKE3_KEY_LEN);
        if(!in || !out || inlen == 0 || outlen == 0)
        {
          if(Gcnt<20)
          printf("func[blake3Hash] error: in=%p out=%p inlen=%ld outlen=%ld\n",in,out,inlen,outlen);
          return;
        }
        else
        {
          blake3_hasher hasher;
          blake3_hasher_init_keyed(&hasher, (unsigned char*)key);
          blake3_hasher_update(&hasher, in, inlen);
          blake3_hasher_finalize(&hasher,(uint8_t *)out,outlen);
        }
        return;
    }
    void outKeyEntryCopy(OutsideKeyEntry *dest,OutsideKeyEntry* src)
    {
      assert(dest && src);
      // dest->valid = src->valid;
      dest->PID  = src->PID;
      dest->VMID = src->VMID;
      memcpy(dest->externalKey,src->externalKey,16);
      memcpy(dest->internalKey,src->internalKey,16);
    }
    int outKeyEntryCmp(OutsideKeyEntry *A,OutsideKeyEntry *B)
    {
      if(A->VMID != B->VMID)
      {
        return A->VMID < B->VMID ? -1 : 1;
      }
      else if(A->PID != B->PID)
      {
        return A->PID < B->PID ? -1 : 1;
      }
      return 0;
      // else 
      // {
      //   int tmp = strcmp(A->internalKey,B->internalKey);
      //   if(!tmp)
      //   {
      //     return strcmp(A->externalKey,B->externalKey);
      //   }
      //   else return tmp;
      // }
    }
    void std_rand_get(unsigned char *container, int size, unsigned char *upperb) 
    {
        unsigned char *trds = container;
        int cnt = size / (sizeof(int));// bytes
        int lf = size - cnt * (sizeof(int));
        // srand((unsigned)time(NULL));//在enc_mod_init()中完成
        while (lf) 
        {
            *trds = (unsigned char)(rand() % (0xFF));
            trds++;
            lf--;
        }     
        while (cnt) 
        {
            *((unsigned int *)trds) = (rand() % 0xFFFFFFF);
            trds += 4;
            cnt--;
        }
        cnt = (size);// < (32) ? (size) : (32);
        while (cnt) 
        {
            if (*container == *upperb)
                continue;
            else if (*container > *upperb) 
            {
                *container = *upperb - 1;
                break;
            } 
            else  break;
            container++;
            upperb++;
            cnt--;
        }
        return;
    }
    void getrd16(uint16_t *p)
    {
        std_rand_get((unsigned char*)p,2,uint16max);
        return;
    }
    void getrd256(unsigned char *p)
    {
        std_rand_get((unsigned char*)p,32,uint256max);
        return;
    }
    void create(uint32_t_h d, uint64_t_h size, cuckooTable_t *hashtable,const char *hash_func) 
    {
      size_t i, j;

      hashtable->d = d;
      strcpy(hashtable->hash_func, hash_func);

      hashtable->keys = (unsigned char **)malloc(d * sizeof(unsigned char *));
      for(i=0;i<d;i++)
      {
        hashtable->keys[i]=(unsigned char *)malloc(BLAKE3_KEY_LEN * sizeof(unsigned char));
        getrd256(hashtable->keys[i]);
        printf("Key[%lu] = ",i);
          for(j=0;j<BLAKE3_KEY_LEN;j++)
            printf("%02x", hashtable->keys[i][j]);
        printf("\n");
        #ifdef DEBUG_CUCKOO
        printf("Key[%lu] = ",i);
          for(j=0;j<32;j++)
            printf("%02x", hashtable->keys[i][j]);
        printf("\n");
        #endif
      }
      if(strcmp(hash_func,"blake3") == 0)
      {
        // hashtable->blake3hasher = (blake3_hasher *)malloc(d * sizeof(blake3_hasher));
        // blake3_hasher hashers[d];
        // for(i=0;i<d;i++)
        // {
          // hashtable->blake3hasher[i] = hashers[i];
          // blake3_hasher_init_keyed(&(hashtable->blake3hasher[i]) , hashtable->keys[i]);
        // }
        hashtable->hash_size = hash_size(size);
      }
      else if (strcmp(hashtable->hash_func, "blake2") == 0) 
      {
        // hashtable->blake3hasher = NULL;
        hashtable->hash_size = hash_size(size);
      } 
      else if (strcmp(hashtable->hash_func, "city") == 0) 
      {
        // hashtable->blake3hasher = NULL;
        hashtable->hash_size = log2(size);
      } 
      else 
      {
        assert(1 == 0 && "Unknown hash function\n");
      }

      hashtable->size = size;
     
      hashtable->num_elems = (uint64_t_h *)malloc(d * sizeof(uint64_t_h));
      hashtable->rehashed = (uint64_t_h *)malloc(d * sizeof(uint64_t_h));
      hashtable->util = (float *)malloc(d * sizeof(float));
      hashtable->occupancy = 0.0;

    #ifdef DEBUG_CUCKOO
      printf("Creating a %lu-ary Cuckoo hashtable\n", hashtable->d);
      printf("Hash function %s\n", hashtable->hash_func);
      printf("Total number of slots %llu\n", hashtable->size * d);
      printf("Hash-size %llu\n", hashtable->hash_size);
    #endif

      for (i = 0; i < d; i++) 
      {
        hashtable->num_elems[i] = 0;
        hashtable->rehashed[i] = 0;
        hashtable->util[i] = 0.0;
      }

      hashtable->hashtable = (OutsideKeyEntry **)malloc(d * sizeof(OutsideKeyEntry *));
      for (i = 0; i < hashtable->d; i++) 
      {
        hashtable->hashtable[i] = (OutsideKeyEntry *)malloc(hashtable->size * sizeof(OutsideKeyEntry));
        for (j = 0; j < hashtable->size; j++) 
        {
          hashtable->hashtable[i][j].valid = 0;
          hashtable->hashtable[i][j].PID = hashtable->hashtable[i][j].VMID = 0;
          memset(hashtable->hashtable[i][j].externalKey,0,16*sizeof(char));
          memset(hashtable->hashtable[i][j].internalKey,0,16*sizeof(char));
        }
      }
      // printf("func[create] new_size:%lld occupancy:%.2f\n",size,hashtable->occupancy);
    }

    void create_elastic(uint32_t_h d, uint64_t_h size, elasticCuckooTable_t *hashtable,
                        const char *hash_func, float rehash_threshold, uint32_t_h scale,
                        uint32_t_h swaps, uint8_t priority) 
      {
      hashtable->current = (cuckooTable_t *)malloc(sizeof(cuckooTable_t));
      hashtable->migrate = NULL;
      hashtable->rehash_threshold = rehash_threshold;
      hashtable->rehashing = 0;
      hashtable->d = d;
      hashtable->curr_size = size;
      if (strcmp(hash_func, "blake2") == 0 || strcmp(hash_func,"blake3") == 0) {
        hashtable->scale = 256;
      } else {
        hashtable->scale = scale;
      }
      hashtable->swaps = swaps;
      hashtable->priority = priority;
      hashtable->rehash_probes = 0;
      hashtable->rehash_elems = 0;
      strcpy(hashtable->hash_func, hash_func);
      create(d, size, hashtable->current, hash_func);
    }

    uint64_t_h rehash(elasticCuckooTable_t *hashtable, uint64_t_h swaps) 
    {
      uint64_t_h i = 0, j = 0, retries = 0;
      uint32_t_h rehashed = 0;
      uint16_t nest = 0, new_nest = 0;
      cuckooTable_t *current = hashtable->current;
      OutsideKeyEntry move;

      do {
        getrd16(&nest);
        nest = nest % current->d;
      } while (current->rehashed[nest] == current->size);

      for (i = 0; i < swaps; i++) 
      {
        if (current->rehashed[nest] < current->size) 
        {
          if (current->hashtable[nest][current->rehashed[nest]].valid == 1) 
          {
            move.valid = 1;
            move.PID = current->hashtable[nest][current->rehashed[nest]].PID;
            move.VMID = current->hashtable[nest][current->rehashed[nest]].VMID;
            memcpy(move.externalKey,current->hashtable[nest][current->rehashed[nest]].externalKey,16);
            memcpy(move.internalKey,current->hashtable[nest][current->rehashed[nest]].internalKey,16);
          
            current->hashtable[nest][current->rehashed[nest]].valid = 0;
            current->rehashed[nest]++;
            current->num_elems[nest]--;
            if (hashtable->priority) 
            {
              // this will end up trying first the new hashtable
              retries += insert_elastic(&move, hashtable, 1, nest);
            } 
            else 
            {
              // perform a random walk
              retries += insert_elastic(&move, hashtable, 0, 0);
            }
            hashtable->rehash_probes += retries;
            hashtable->rehash_elems++;
          } else {
            current->rehashed[nest]++;
          }
          for (j = 0; j < current->d; j++) {
            rehashed += current->rehashed[j];
          }
          if (rehashed == current->size * current->d) {
            break;
          }
          do {
            getrd16(&new_nest);
            new_nest = new_nest % current->d;
          } while (new_nest == nest && current->rehashed[nest] == current->size);
          nest = new_nest;
        }
      }
      update_occupancy(current);
      update_occupancy(hashtable->migrate);
      return retries;
    }

    uint64_t_h evaluate_elasticity(elasticCuckooTable_t *hashtable,
                                uint8_t complete) {
      uint64_t_h retries = 0;
      if (hashtable->current->occupancy > hashtable->rehash_threshold &&!hashtable->rehashing) 
      {
        printf("func[evaluate_elasticity] old_size:%lld occupancy:%.2f scale:%ld new_size:%lld\n",hashtable->current->size,hashtable->current->occupancy,hashtable->scale,hashtable->curr_size * hashtable->scale);
        hashtable->rehashing = 1;
        hashtable->migrate = (cuckooTable_t *)malloc(sizeof(cuckooTable_t));
        create(hashtable->d, hashtable->curr_size * hashtable->scale,
              hashtable->migrate, hashtable->hash_func);
      }
      if (complete) 
      {
        if (hashtable->rehashing) {
          while (hashtable->current->occupancy != 0) {
            retries += rehash(hashtable, hashtable->swaps);
          }
          hashtable->rehashing = 0;
          destroy(hashtable->current);
          hashtable->current = hashtable->migrate;
          hashtable->migrate = NULL;
          hashtable->curr_size *= hashtable->scale;
        }

      } 
      else 
      {
        if (hashtable->rehashing) 
        {
          retries += rehash(hashtable, hashtable->swaps);
        }
        if (hashtable->current->occupancy == 0 && hashtable->rehashing) 
        {
          hashtable->rehashing = 0;
          destroy(hashtable->current);
          hashtable->current = hashtable->migrate;
          hashtable->migrate = NULL;
          hashtable->curr_size *= hashtable->scale;
        }
      }

      return retries;
    }

    void destroy(cuckooTable_t *hashtable) 
    {
      uint32_t_h i;
      free(hashtable->keys);
      printf("keys destroy!\n");
      free(hashtable->num_elems);
      printf("num_elems destroy!\n");
      free(hashtable->util);
      printf("util destroy!\n");
      // if(hashtable->blake3hasher != NULL)
      // {
      //   // for(i=0;i<hashtable->d;i++)
      //   free(hashtable->blake3hasher);
      //   printf("blake3hasher destroy!\n");
      // }
      // else 
      // {
      //   printf("undefined!\n");
      // }
      for (i = 0; i < hashtable->d; i++) 
      {
        free(hashtable->hashtable[i]);
      }
      free(hashtable->hashtable);
    }

    void destroy_elastic(elasticCuckooTable_t *hashtable) 
    {
      if(hashtable->current!=NULL)
        destroy(hashtable->current);
      if (hashtable->migrate != NULL) 
      {
        destroy(hashtable->migrate);
      }
    }

    uint32_t_h insert_recursion(OutsideKeyEntry *elem, cuckooTable_t *hashtable, uint32_t_h nest,
                              uint32_t_h tries) {
      uint16_t new_nest;
      uint64_t_h hash = 0;

      tries++;

      hash = gen_hash(elem, hashtable, nest);
      

      OutsideKeyEntry tmp;
      tmp.valid = 0;
      if (hashtable->hashtable[nest][hash].valid == 1) 
      {
        tmp.valid = hashtable->hashtable[nest][hash].valid;
        // tmp.value = hashtable->hashtable[nest][hash].value;
        tmp.PID = hashtable->hashtable[nest][hash].PID;
        tmp.VMID = hashtable->hashtable[nest][hash].VMID;
        memcpy(tmp.externalKey,hashtable->hashtable[nest][hash].externalKey,16);
        memcpy(tmp.internalKey,hashtable->hashtable[nest][hash].internalKey,16);
          

        hashtable->num_elems[nest]--;
      }

      hashtable->hashtable[nest][hash].valid = 1;
      // hashtable->hashtable[nest][hash].value = elem->value;
      hashtable->hashtable[nest][hash].PID = elem->PID;
      hashtable->hashtable[nest][hash].VMID = elem->VMID;
      memcpy(hashtable->hashtable[nest][hash].externalKey,elem->externalKey,16);
      memcpy(hashtable->hashtable[nest][hash].internalKey,elem->internalKey,16);

      hashtable->num_elems[nest]++;

      // need to allocate the replaced element
      if (tmp.valid) 
      {
        do {
          getrd16(&new_nest);
          new_nest = new_nest % hashtable->d;
        } while (new_nest == nest);
        nest = new_nest;

        if (tries > MAX_RETRIES) {
          return tries;
        }
        return insert_recursion(&tmp, hashtable, nest, tries);
      }
      update_occupancy(hashtable);
      return tries;
    }

    uint32_t_h insert(OutsideKeyEntry *elem, cuckooTable_t *hashtable) {
      uint32_t_h tries = 0;
      uint16_t nest = 0, new_nest = 0;
      uint64_t_h hash = 0;
      OutsideKeyEntry old;

      do {
        getrd16(&new_nest);
        new_nest = new_nest % hashtable->d;
      } while (new_nest == nest);
      nest = new_nest;

      // try to insert until MAX_RETRIES insertion attempts
      for (tries = 0; tries < MAX_RETRIES; tries++) {

    #ifdef DEBUG_CUCKOO
        printf("Inserting element with value (%u,%u), nest %u\n", elem->VMID,elem->PID, nest);
    #endif

        hash = gen_hash(elem, hashtable, nest);

        old.valid = 0;
        // remove previous element if it exists
        if (hashtable->hashtable[nest][hash].valid == 1) {
          old.valid = hashtable->hashtable[nest][hash].valid;
          // old.value = hashtable->hashtable[nest][hash].value;
          old.PID = hashtable->hashtable[nest][hash].PID;
          old.VMID = hashtable->hashtable[nest][hash].VMID;
          memcpy(old.externalKey,hashtable->hashtable[nest][hash].externalKey,16);
          memcpy(old.internalKey,hashtable->hashtable[nest][hash].internalKey,16);

          hashtable->num_elems[nest]--;
        }

        // insert new element
        hashtable->hashtable[nest][hash].valid = 1;
        // hashtable->hashtable[nest][hash].value = elem->value;
        old.PID = hashtable->hashtable[nest][hash].PID;
        old.VMID = hashtable->hashtable[nest][hash].VMID;
        memcpy(old.externalKey,hashtable->hashtable[nest][hash].externalKey,16);
        memcpy(old.internalKey,hashtable->hashtable[nest][hash].internalKey,16);

        hashtable->num_elems[nest]++;

        // we removed an element and we have to put it back
        if (old.valid) {
          // copy old element
          // elem->value = old.value;
          outKeyEntryCopy(elem,&old);
          elem->valid = 1;

          // pick new nest to try
          do {
            getrd16(&new_nest);
            new_nest = new_nest % hashtable->d;
          } while (new_nest == nest);
          nest = new_nest;
        }
        // we are done
        else {
          break;
        }
      }
      update_occupancy(hashtable);
      // printf("Insert Tries %lu\n",tries+1);
      return tries + 1;
    }

    uint32_t_h insert_elastic(OutsideKeyEntry *elem, elasticCuckooTable_t *hashtable,
                            uint8_t bias, uint16_t bias_nest) {
      uint32_t_h tries = 0, current_inserts = 0, migrate_inserts = 0;
      uint16_t nest = 0, new_nest = 0;
      uint64_t_h hash = 0;
      OutsideKeyEntry old;
      cuckooTable_t *selectTable;

      if (bias) {
        nest = bias_nest;
      } else {
        getrd16(&nest);
        nest = nest % hashtable->current->d;
        // if(nest != 0 && nest !=1 )printf("nest=%d\n",nest);
      }

      // try to insert until MAX_RETRIES insertion attempts
      for (tries = 0; tries < MAX_RETRIES; tries++) 
      {
        Gcnt++;
    #ifdef DEBUG_CUCKOO
        printf("Inserting element with value (%u,%u), nest %u\n", elem->VMID,elem->PID, nest);
    #endif

        hash = gen_hash(elem, hashtable->current, nest);

        if (hashtable->rehashing && hash < hashtable->current->rehashed[nest]) {
          hash = gen_hash(elem, hashtable->migrate, nest);
          selectTable = hashtable->migrate;
          migrate_inserts++;
        } else {
          selectTable = hashtable->current;
          current_inserts++;
        }

        old.valid = 0;
        // remove previous element if it exists
        if (selectTable->hashtable[nest][hash].valid == 1) 
        {
          old.valid = selectTable->hashtable[nest][hash].valid;
          // old.value = selectTable->hashtable[nest][hash].value;
          
          outKeyEntryCopy(&old,&selectTable->hashtable[nest][hash]);
          selectTable->num_elems[nest]--;
        }

        // insert new element
        selectTable->hashtable[nest][hash].valid = 1;
        // selectTable->hashtable[nest][hash].value = elem->value;
        outKeyEntryCopy(&selectTable->hashtable[nest][hash],elem);
        selectTable->num_elems[nest]++;

        // we removed an element and we have to put it back
        if (old.valid) {
          // copy old element
          outKeyEntryCopy(elem,&old);
          // elem->value = old.value;
          elem->valid = 1;

          // pick new nest to try
          do {
            getrd16(&new_nest);
            new_nest = new_nest % selectTable->d;
          } while (new_nest == nest);
          nest = new_nest;
        }
        // we are done
        else {
          break;
        }
      }
      if (migrate_inserts) {
        update_occupancy(hashtable->migrate);
      }
      if (current_inserts) {
        update_occupancy(hashtable->current);
      }
      return tries + 1;
    }

    void delete_non (OutsideKeyEntry *elem, cuckooTable_t *hashtable) 
    {
      uint32_t_h nest;
      uint64_t_h hash = 0;

      for (nest = 0; nest < hashtable->d; nest++) 
      {
        hash = gen_hash(elem, hashtable, nest);
        
        if (hashtable->hashtable[nest][hash].valid == 1 &&
            (!outKeyEntryCmp(elem,&(hashtable->hashtable[nest][hash])))) 
            {
              hashtable->hashtable[nest][hash].valid = 0;
              // hashtable->hashtable[nest][hash].value = 0;
              hashtable->num_elems[nest]--;
              update_occupancy(hashtable);
              return;
        }
      }
    }

    void delete_elastic(OutsideKeyEntry *elem, elasticCuckooTable_t *hashtable) {
      uint32_t_h nest = 0;
      uint64_t_h hash = 0;
      cuckooTable_t *selectTable;

      for (nest = 0; nest < hashtable->current->d; nest++) 
      {
          hash = gen_hash(elem, hashtable->current, nest);

          if (hashtable->rehashing && hash < hashtable->current->rehashed[nest]) {
            hash = gen_hash(elem, hashtable->migrate, nest);
            selectTable = hashtable->migrate;
          } 
          else 
          {
            selectTable = hashtable->current;
          }

          if (selectTable->hashtable[nest][hash].valid == 1 &&
              (!outKeyEntryCmp(&(selectTable->hashtable[nest][hash]),elem)))
              {
                selectTable->hashtable[nest][hash].valid = 0;
                // selectTable->hashtable[ngen_hashest][hash].value = 0;
                selectTable->num_elems[nest]--;
                update_occupancy(selectTable);
                return;
              }
      }
    }

    OutsideKeyEntry *find(OutsideKeyEntry *elem, cuckooTable_t *hashtable) {
      uint32_t_h nest = 0;
      uint64_t_h hash = 0;

      for (nest = 0; nest < hashtable->d; nest++) {
        hash = gen_hash(elem, hashtable, nest);

        if (hashtable->hashtable[nest][hash].valid == 1 &&
            (!outKeyEntryCmp(&(hashtable->hashtable[nest][hash]),elem))) {
          return &hashtable->hashtable[nest][hash];
        }
      }
      return NULL;
    }

    OutsideKeyEntry *find_elastic(OutsideKeyEntry *elem, elasticCuckooTable_t *hashtable) 
    {
      uint32_t_h nest = 0;
      uint64_t_h hash = 0;
      cuckooTable_t *selectTable;

      for (nest = 0; nest < hashtable->current->d; nest++) {
        hash = gen_hash(elem, hashtable->current, nest);

        if (hashtable->rehashing && hash < hashtable->current->rehashed[nest]) {
          hash = gen_hash(elem, hashtable->migrate, nest);
          selectTable = hashtable->migrate;
        } 
        else 
        {
          selectTable = hashtable->current;
        }

        if (selectTable->hashtable[nest][hash].valid == 1 &&
            (!outKeyEntryCmp(&(selectTable->hashtable[nest][hash]),elem))) 
            {
              return &selectTable->hashtable[nest][hash];
            }
      }
      return NULL;
    }

    uint64_t_h gen_hash(OutsideKeyEntry *elem, cuckooTable_t *hashtable, uint32_t_h nest) 
    {
      uint64_t_h hash = 0;
      uint32_t_h value = ((uint64_t_h)elem->VMID)<<16 | (uint32_t_h)(elem->PID);
    #ifdef DEBUG_CUCKOO
      uint32_t_h i;
      for (i = 0; i < hashtable->d ; i++) 
      {
        if (strcmp(hashtable->hash_func,"blake3") == 0)
        {
          // blake3_hasher_update(&(hashtable->blake3hasher[nest]), &value, HASH_SIZE);
          // blake3_hasher_finalize(&(hashtable->blake3hasher[nest]),(uint8_t *)(&hash),hashtable->hash_size / 8);

          blake3Hash(&hash , hashtable->hash_size / 8 , &value,HASH_SIZE,&hashtable->keys[nest],32);
      
        }
        else if (strcmp(hashtable->hash_func, "blake2") == 0) 
        {
          blake2b(&hash, hashtable->hash_size / 8, &value, HASH_SIZE,
                  &hashtable->keys[i], 8);
        } 
        else if (strcmp(hashtable->hash_func, "city") == 0) 
        {
          hash = CityHash64WithSeed((const char *)&value, HASH_SIZE,
                                    (uint64_t_h)(hashtable->keys[nest]));
          hash = hash & hmask((uint64_t_h)hashtable->hash_size);
        } 
        else
        {
          assert(1 == 0 && "Unknown hash function\n");
        }
        printf("Hash %llu\n", hash);
      }
    #endif

      if (strcmp(hashtable->hash_func,"blake3") == 0)
      {
        blake3Hash(&hash , hashtable->hash_size / 8 , &value,HASH_SIZE,&hashtable->keys[nest],32);
      }
      else if (strcmp(hashtable->hash_func, "blake2") == 0) 
      {
        blake2b(&hash, hashtable->hash_size / 8, &value, HASH_SIZE, &hashtable->keys[nest], 8);
      } 
      else if (strcmp(hashtable->hash_func, "city") == 0) 
      {
        hash = CityHash64WithSeed((const char *)&value, HASH_SIZE,
                                  (uint64_t_h)(hashtable->keys[nest]));
        hash = hash & hmask((uint64_t_h)hashtable->hash_size);
      } 
      else 
      {
        assert(1 == 0 && "Unknown hash function\n");
      }
      if (hash > hashtable->size) 
      {
        printf("Hash value %llu, size %llu\n", hash, hashtable->size);
        assert(1 == 0 && "Hash value is larger than index\n");
      }
      return hash;
    }

    void update_occupancy(cuckooTable_t *hashtable) {
      uint32_t_h i = 0;
      uint64_t_h total_elems = 0;
      for (i = 0; i < hashtable->d; i++) {
        hashtable->util[i] = hashtable->num_elems[i] / (float)hashtable->size;
        total_elems += hashtable->num_elems[i];
      }
      hashtable->occupancy = total_elems / (float)(hashtable->d * hashtable->size);
    #ifdef DEBUG_CUCKOO
      printf("Total elements: %llu\n", total_elems);
      printf("Occupancy: %f\n", hashtable->occupancy);
    #endif
    }

    void printTable(cuckooTable_t *hashtable) 
    {
      size_t i, j,k;
      for (i = 0; i < hashtable->d; i++) 
      {
        printf("way[%ld]:\n",i);
        for (j = 0; j < hashtable->size; j++) 
        {
          printf("([%u],[vmid=%u,asid=%u]", hashtable->hashtable[i][j].valid,
                hashtable->hashtable[i][j].VMID,hashtable->hashtable[i][j].PID);
          printf("{");
          for(k=0;k<16;k++)
            printf("%02x",*(hashtable->hashtable[i][j].internalKey+i));
          printf(",");
          for(k=0;k<16;k++)
            printf("%02x",*(hashtable->hashtable[i][j].externalKey+i));
          printf("}");
          printf(") | ");

        }
        printf("\n\n");
      }
    }

    uint64_t_h hash_size(uint64_t_h size) 
    {
      uint64_t_h hash_size = 0;

      while (log2(size) > (float)hash_size) 
      {
        hash_size += 8;
      }
    #ifdef DEBUG_CUCKOO
      printf("func[hash_size] hashtable size:%llu,requested size:%llu\n", hash_size, size);
      // printf("hashtable size = %llu, requested size = %llu\n", hash_size, size);
    #endif
      return hash_size;
    }
    /*
    bash:
    ./elastic_cuckoo 4 256 blake2 elastic oneshot 0.75 128 1 0
    */
    /*
    void simple_example(uint32_t_h d, uint64_t_h size, char *hash_func, uint8 elastic,
                        uint8_t oneshot, float rehash_threshold, uint8_t scale,
                        uint8_t swaps, uint8_t priority) 
    {
      uint64_t_h i = 0;
      uint64_t_h N = (1<<20);
      // N <<= 1;
      printf("in simple_example: N=%lld\n",N);
      // uint64_t_h *test_values = NULL;
      OutsideKeyEntry new_elem;
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
      // assert(&elasticCuckooHT != NULL);
      // test_values = (uint64_t_h *)malloc(N * sizeof(uint64_t_h));

      // for (i = 0; i < N; i++) 
      // {
      //   test_values[i] = 0;
      // }

      for (i = 0; i < N; i++) 
      {
        new_elem.valid = 1;
        if (elastic) 
        {
          do 
          {
            getrd16((unsigned short *)&new_elem.VMID);
            getrd16((unsigned short *)&new_elem.PID);
          } while (find_elastic(&new_elem, &elasticCuckooHT) != NULL);
          // printf("get one!\n");
        } 
        else 
        {
          do 
          {
            getrd16((unsigned short *)&new_elem.VMID);
            getrd16((unsigned short *)&new_elem.PID);
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

      // printTable(elasticCuckooHT.current);

      if (elastic) {
        destroy_elastic(&elasticCuckooHT);
      } else {
        destroy(&cuckooHT);
      }
      
      printf("func[simple_example] insert count:%lld\n",Gcnt);
    }

    int main(int argc, char **argv) 
    {
      uint32_t_h d = 4, size = 0, elastic = 0, oneshot = 0, scale = 0, swaps = 0;
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
    //
    */
  }
}
