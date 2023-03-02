#ifndef __PERFORM_ENGINE_H
#define __PERFORM_ENGINE_H
#include <unordered_map>
#include <vector>
#include <unistd.h>

#include "mem/packet.hh"
#include "debug/ShowPacket.hh"
#include "mem/page_table.hh"

#include "encry_mod/alg_src/sm2/SM2_ENC.hh"
#include "encry_mod/alg_src/sm4/SM4_ENC.hh"
#include "encry_mod/alg_src/blake3/blake3.h"
#include "encry_mod/alg_src/elasticCuckooHashing/elastic_cuckoo_table.h"

#include "../ext/miracl/include/miracl.h"
#include "../ext/miracl/include/mirdef.h"

#define CachelineSize 64
#define enc_latency 4
#define dec_latency 4
#define create_key_latency 1
#define MAX_UINT 0xFFFFFFFF
#define is_functional 0
#define no_functional 1
#define sm4_encry 2
#define sm4_decry 3
#define insideTabSize 64
#define outsideTabSize 2048
#define isElastic 1
#define d_ary 4

#define size_per_way (1<<8) //(1<<8) -> (1<<16): 4*2^16*(128*2+32+8) / 2^28 = 296 Kb
#define rehash_threshold 0.75
#define inc_scale (1<<8)
#define rehash_swaps 192// (rehash_threshold)*size_per_way
#define rehash_bias 1
#define BlakeHash "blake3"

// #define randN0Len 4

#define IDALen 8
#define dstIP4Len 16
#define dstPortLen 8
#define RDMABUFFSIZE 1024
#define SM2ENC_sk_Len (16+96)
namespace gem5
{
    namespace encry_mod
    {
        typedef gem5::Packet *PacketPtr;
        extern bool hasInit;
        extern std::unordered_map<unsigned short,std::unordered_map<uint64_t, uint64_t>> vAddrMapping;
        extern std::unordered_map<unsigned short,std::unordered_map<uint64_t, unsigned char>> cbitMapping;
        // extern char elasticCuckooHashFunc[7];
        extern unsigned char privateKeySM2[32];
        extern epoint *publicKeySM2;
        extern bool hasKey[16];
        extern unsigned char CPUSAFEKEY[16];
        extern uint64_t countForEnc;
        extern uint64_t countForDec;
        extern unsigned RDMABuff [RDMABUFFSIZE];
        typedef struct keyTable
        {
            bool dirty=false;
            unsigned char freq;
            unsigned short VMID=0,PID=0;
            unsigned char internalKey[16]={0},externalKey[16]={0};
        }keyTable;

        typedef struct keyStruct
        {
            unsigned char E_PK_sk[SM2ENC_sk_Len];
            unsigned char SM4Enc_SK_sig_PB[128]={0};
        }keyStruct;

        typedef struct SM2sign
        {
            unsigned char R[32]={0},S[32]={0};
        }SM2sign;

        typedef struct migDestStruct
        {
            unsigned int ipv4;
            // unsigned int ipv6;
            unsigned short port;
            unsigned short nvmid,npid;
            uint64_t size;
        }migDest;

        typedef struct SM2PubKeystr
        {
            unsigned char x[32]={0};
            unsigned char y[32]={0};
        }SM2PubKeystr;

        typedef struct SM2KeyPairs
        {
            unsigned char priKey[32];
            SM2PubKeystr PubKey;
        }SM2KeyPairs;

        typedef struct CAcard
        {
            SM2sign sig;
            SM2PubKeystr PubK;
            unsigned char IssuingIDA[IDALen];
        }CAcard;

        typedef struct migDestattestationStruct
        {
            unsigned short level = 1;//ROOTpub is 0
            CAcard CAlink;//for simple only one level
        }simpleCA;

        typedef struct reqStruct
        {
            unsigned char destIp[dstIP4Len]={0},destPort[dstPortLen]={0};//16 + 8

            unsigned char IDA[IDALen]={0};               //4    
            unsigned char cla = 0;                       //1 /*cal = 1 VM migrant*/

            SM2sign sig;                                 //32*2
            SM2PubKeystr pubB;                           //32*2
            unsigned short dVMID = 0,dPID = 0;           //2*2
            unsigned char timeStamp[8]={0};              //8
            // unsigned char randN0 [randN0Len] = {0};   //4
            uint64_t size = 0;                           //8
        }reqStruct;//16+8+4+1+32*2*2+8+2*2+8

        typedef struct respStruct
        {
            unsigned char IDA[IDALen];
            simpleCA CA;
            SM2sign timeSpsig;
            unsigned char H_V_P[32]={0};
            unsigned short VMID=0,PID=0;
        }respStruct;
        typedef struct dataStruct
        {
            unsigned char keyID = 0;
            uint64_t lineAddr = 0;
            unsigned char lineCont[64];
        }dataStruct;
        /* get system pointer*/
        extern uint8_t* pmemAddr;
        extern uint64_t rangeStart;
        inline uint8_t * toHostAddr(uint64_t paddr)
        {
            return pmemAddr + paddr - rangeStart; 
        }

        // extern uint64_t countForCreateKeys;
        void enc_dec_init();
        void enc_dec_free();
        extern void std_rand_get(unsigned char *container, int size, unsigned char *upperb);
        bool enc_dec_engine(PacketPtr pkt,unsigned char *functionalPtr,uint64_t addr,int model,int alg);
        void sm2Encrypt(unsigned char* Message,unsigned int Mlen,epoint *pubKey);
        void sm2Decrypt(unsigned char* Cipher,unsigned int Clen,unsigned char *priKey);
        void sm4Encrypt(unsigned char* PlainText,unsigned char *priKey,bool isCacheLine,uint64_t paddr);
        void sm4Decrypt(unsigned char* CipherText,unsigned char *priKey,bool isCacheLine,uint64_t paddr);
        unsigned short getVMID();
        unsigned short getASID();
        void setCbit(uint64_t vaddr);
        void setKeyID(uint64_t vaddr);
        bool getCbit(uint64_t vaddr);
        int getKeyID(uint64_t vaddr);
        int CreateIntKeySM4();
        int CreateExtKeySM4(uint64_t hpwd,uint64_t lpwd);
        void DeleteKeyEntrySM4(unsigned short vmid ,unsigned short asid);
        unsigned short getAddrSetIndex(unsigned short vmid,unsigned short asid);
        void DataTrans(uint64_t gvAddr,uint64_t destInfo);
        void AccDataTrans(uint64_t dstGVAddr,uint64_t guestInfo);
        void VMTrans(uint64_t gvAddr,uint64_t size,uint64_t destInfo);
        void AccVMTrans(uint64_t dstgvAddr,uint64_t size,uint64_t guestInfo);
    }//encry_mod
}//gem5
#endif
