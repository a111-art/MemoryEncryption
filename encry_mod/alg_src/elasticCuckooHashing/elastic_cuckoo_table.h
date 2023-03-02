#ifndef ELASTIC_CUCKOO_TABLE_H
#define ELASTIC_CUCKOO_TABLE_H

#include "encry_mod/alg_src/blake2/blake2-impl.h"
#include "encry_mod/alg_src/blake2/blake2.h"
#include "encry_mod/alg_src/blake3/blake3.h"
#include "encry_mod/alg_src/cityhash/city.h"
#include <assert.h>
#include <math.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define uint64_t_h unsigned long long
#define uint32_t_h unsigned long

#define hsize(n) ((uint64_t_h)1 << (n))
#define hmask(n) (hsize(n) - 1)
namespace gem5
{
    namespace encry_mod
    {
    typedef struct outkeyTable
    {
        uint8_t valid;
        unsigned short VMID,PID;
        unsigned char internalKey[16],externalKey[16];
    }OutsideKeyEntry;

    typedef struct cuckooTable_t 
    {
      OutsideKeyEntry **hashtable;  // hashtable structure
      uint32_t_h d;          // d-ary cuckoo hashtable
      uint64_t_h hash_size;  // number of bits required for hashing
      char hash_func[20];  // hash function to be used
      uint64_t_h size;       // size per d way
      uint64_t_h *num_elems; // current # elements per d way
      unsigned char **keys;      // key per d way
      uint64_t_h *rehashed;  // current rehashed entries
      // blake3_hasher *blake3hasher;
      float *util;         // utilization per d way
      float occupancy;     // overall hashtable occupancy
    } cuckooTable_t;

    typedef struct elasticCuckooTable_t {
      cuckooTable_t *current; // current hashtable
      cuckooTable_t *migrate; // migrate hashtable
      float rehash_threshold; // rehash treshold
      uint8_t rehashing;      // flag if rehashing
      uint32_t_h d;             // d-ary cuckoo hashtable
      uint64_t_h curr_size;     // size per d hashtable of current
      uint32_t_h scale;         // scaling factor
      uint32_t_h swaps;         // number of swaps
      uint8_t priority;       // priority of table during rehashing
      uint64_t_h rehash_probes; // number of rehash probes
      uint64_t_h rehash_elems;  // number of rehash elements
      char hash_func[20];     // hash function to be used
    } elasticCuckooTable_t;

    /*
    * create_elastic allocates an elastic cuckoo hashtable
    * @d number of ways/nests
    * @size size of each way/nest
    * @hashtable the hashtable
    * @hash_func name of the hash function
    */
    void create(uint32_t_h d, uint64_t_h size, cuckooTable_t *hashtable,const char *hash_func);
    /*
    * create_elastic allocates an elastic cuckoo hashtable
    * @d number of ways/nests
    * @size size of each way/nest
    * @hashtable the hashtable
    * @hash_func name of the hash function
    * @rehash_treshold resizing threshold as a fraction
    * @scale scaling factor during resizing
    * @swaps number of swaps during rehashing
    * @priority bias the rehashing inserts vs random
    */
    void create_elastic(uint32_t_h d, uint64_t_h size, elasticCuckooTable_t *hashtable,
                        const char *hash_func, float rehash_threshold, uint32_t_h scale,
                        uint32_t_h swaps, uint8_t priority);
    /*
    * rehash rehash elements in th elastic cuckoo hashtable
    * @hashtable the elastic cuckoo hashtable
    * @swaps the number of swaps to perform
    * @return number of tries
    */
    uint64_t_h rehash(elasticCuckooTable_t *hashtable, uint64_t_h swaps);

    /*
    * evaluate_elasticity evaluates the "elasticity" of the elastic cuckoo hashtable
    * if a threhold of occupancy is passed reszing is initiated
    * @hashtable elastic cuckoo hashtable to be evaluated
    * @complete if a resize is triggered perform a complete or gradual resize
    * @return number of retries if rehash was initiated
    */
    uint64_t_h evaluate_elasticity(elasticCuckooTable_t *hashtable, uint8_t complete);

    /*
    * destroy de-allocate the cuckoo hashtable
    * @hashtable the cuckoo hashtable to de-allocate
    */
    void destroy(cuckooTable_t *hashtable);

    /*
    * destroy_elastic de-allocate the elastic cuckoo hashtable
    * @hashtable the elastic cuckoo hashtable to de-allocate
    */
    void destroy_elastic(elasticCuckooTable_t *hashtable);

    /*
    * insert try to insert an element in the cuckoo hashtable with recursion
    * @elem element to insert
    * @hashtable cuckoo hashtable to be updated
    * @nest nest/way to insert
    * @tries number of tries before aborting
    */
    uint32_t_h insert_recursion(OutsideKeyEntry *elem, cuckooTable_t *hashtable, uint32_t_h nest,
                              uint32_t_h tries);

    /*
    * insert try to insert an element in the cuckoo hashtable
    * @elem element to insert
    * @hashtable cuckoo hashtable to be updated
    */
    uint32_t_h insert(OutsideKeyEntry *elem, cuckooTable_t *hashtable);

    /*
    * insert_elastic try to insert an element in the elastic cuckoo hashtable
    * @elem element to insert
    * @hashtable elasticCuckoo hashtable to be updated
    * @bias enable to selected the bias_nest
    * @bias_nest when bias is enabled select @bias_nest as the first try
    */
    uint32_t_h insert_elastic(OutsideKeyEntry *elem, elasticCuckooTable_t *hashtable,
                            uint8_t bias, uint16_t bias_nest);

    /*
    * find find an element in the cuckoo hashtable
    * @elem element to search for
    * @hashtable cuckoo hashtable to search in
    */
    OutsideKeyEntry *find(OutsideKeyEntry *elem, cuckooTable_t *hashtable);

    /*
    * find_elastic find an element in the elastic cuckoo hashtable
    * @elem element to search for
    * @hashtable elasticCuckoo hashtable to search in
    */
    OutsideKeyEntry *find_elastic(OutsideKeyEntry *elem, elasticCuckooTable_t *hashtable);

    /*
    * delete_non marks an element invalid from the cuckoo hashtable
    * @elem element to be marked invalid (if found)
    * @hashtable cuckoo hashtable to update
    */
    void delete_non (OutsideKeyEntry *elem, cuckooTable_t *hashtable);

    /*
    * delete_elastic marks an element invalid from the elastic cuckoo hashtable
    * @elem element to be marked invalid (if found)
    * @hashtable elasticCuckoo hashtable to update
    */
    void delete_elastic(OutsideKeyEntry *elem, elasticCuckooTable_t *hashtable);

    /*
    * update_occupancy updates the occupancy of the hashtable
    * @hashtable the cuckoo hashtable of which the occupancy will be updated
    */
    void update_occupancy(cuckooTable_t *hashtable);

    /*
    * gen_hash generates a hash index
    * @elem used to generate the hash
    * @hashtable use the hash function defined in the hashtable
    * @nest the nest/way for which a hash is generated
    */
    uint64_t_h gen_hash(OutsideKeyEntry *elem, cuckooTable_t *hashtable, uint32_t_h nest);

    /*
    * printTable prints is a helper functions that prints the hashtable
    * @hashtable is a cuckoo hashtable
    */
    void printTable(cuckooTable_t *hashtable);

    void outKeyEntryCopy(OutsideKeyEntry *dest,OutsideKeyEntry* src);
    int outKeyEntryCmp(OutsideKeyEntry *A,OutsideKeyEntry *B);
    void std_rand_get(unsigned char *container, int size, unsigned char *upperb);
  }
}
#if defined(__cplusplus)
}
#endif

#endif // ELASTIC_CUCKOO_TABLE_H
