#include "encry_mod/perform_engine.hh"
#include "encry_mod/alg_src/sm2/kdf.hh"
#include "encry_mod/alg_src/sm2/SM2_sv.hh"
#include <sys/timeb.h>
#include <stdlib.h>

namespace gem5
{   
    namespace encry_mod
    {
        bool hasInit=false;
        std::unordered_map<unsigned short,std::unordered_map<uint64_t, uint64_t>> vAddrMapping;//代替pageTable
        std::unordered_map<unsigned short,std::unordered_map<uint64_t, unsigned char>> cbitMapping;//方便删除不同进程的映射
        
        keyTable insideTab[insideTabSize];
        elasticCuckooTable_t elasticCuckooHT;
        cuckooTable_t cuckooHT;
        unsigned RDMABuff [RDMABUFFSIZE]={0};
        
        unsigned char IDAs[3][IDALen]={{0x0},{0x1},{0x2}};
        unsigned char ENTLA[2] = {0x00, 0x40};

        unsigned char CPUSAFEKEY[16];
        
        SM2PubKeystr ROOTpub;
        unsigned char ROOTpri[32];
        SM2KeyPairs sampleKeys[3]; //IDA K use k-st pairs , 0 is free
       
        unsigned char std_priKey[32] = {0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1,
                                        0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3, 0x9F, 0x95,
                                        0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A,
                                        0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8};

        unsigned char std_pubKey[64] = {0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1,
                                        0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
                                        0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07,
                                        0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
                                        0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5,
                                        0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
                                        0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A,
                                        0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13};
        unsigned char std_rand[32] = {0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A,
                                      0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D, 0xCC,
                                      0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE,
                                      0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21};
        // uint32_t HashKey[8] = {  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL,
        //                          0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL,
        //                          0x1F83D9ABUL, 0x5BE0CD19UL};

        // unsigned char MAXrandN0[32] = {0xFF,0xFF,0xFF,0xFF};
        

        uint8_t *pmemAddr = NULL;
        uint64_t rangeStart = 0;

        uint64_t countForEnc=0;
        uint64_t countForDec=0;
        uint64_t countForCreateKeys=0;
        unsigned short insideKeyCnt  = 0;
        unsigned short outsideKeyCnt = 0;
        unsigned short getASID()
        {
            return 0;
        }
        unsigned short getVMID()
        {
            return 0;
        }
        // attention the addr is va
        unsigned short getAddrSetIndex(unsigned short vmid,unsigned short asid)
        {
            return asid;
        }
        void setCbit (uint64_t vaddr)
        {
            vaddr &= 0xFFFFF000;//align
            unsigned short mapInd = getAddrSetIndex(getVMID(),getASID());
            assert(vAddrMapping.find(mapInd)!=vAddrMapping.end());//该页面映射应该已经存在，且物理地址的加密分布也存在
            auto iteratorv = vAddrMapping[mapInd].find(vaddr);
            if (iteratorv == vAddrMapping[mapInd].end())
            {
                printf("error [%lx],unapplied!\n",vaddr);
                assert(0);
                return;
            }//该地址必须已分配
            uint64_t paddr=iteratorv->second;
            auto iterator = cbitMapping[mapInd].find(paddr);
            if(iterator == cbitMapping[mapInd].end())//防止由KeyID = 1 切换到 0
                cbitMapping[mapInd].insert(std::pair<uint64_t,unsigned char>(paddr,0));
            printf("[%lx]added\n",vaddr);
            return;
        }
        // attention the addr is va
        void setKeyID (uint64_t vaddr)
        {
            vaddr &= 0xFFFFF000;
            unsigned short mapInd = getAddrSetIndex(getVMID(),getASID());
            assert(vAddrMapping.find(mapInd)!=vAddrMapping.end());//该套地址映射应该已经存在
            auto iteratorv = vAddrMapping[mapInd].find(vaddr);//find()返回一个指向2的迭代器
            assert(iteratorv != vAddrMapping[mapInd].end());//该地址必须已分配
            //assert(iterator == AddrSet.end());//不支持中途修改密钥：安全性,防止加解密不一致
            uint64_t paddr=iteratorv->second;
            auto iterator=cbitMapping[mapInd].find(paddr);
            if(iterator != cbitMapping[mapInd].end())
            {
                printf("this addr's page has used inside key!\n");
                return;
            }
            
            cbitMapping[mapInd].insert(std::pair<uint64_t,unsigned char>(paddr,1));
            // printf("[%lx]Extkey\n",vaddr);
            return;
        }
        bool getCbit(uint64_t GPAddr)
        {
            unsigned short mapInd = getAddrSetIndex(getVMID(),getASID());
            // if(vAddrMapping.find(mapInd)==vAddrMapping.end())
            // {
            //     printf("func[getCbit] paddr:%llx unmapped\n",paddr);
            // }
            // assert(vAddrMapping.find(mapInd)!=vAddrMapping.end());//该页地址映射应该已经存在
            GPAddr &= 0xFFFFF000;
            return cbitMapping[mapInd].find(GPAddr)!=cbitMapping[mapInd].end();
        }
        int getKeyID(uint64_t GPAddr)
        {
            unsigned short mapInd = getAddrSetIndex(getVMID(),getASID());
            assert(vAddrMapping.find(mapInd)!=vAddrMapping.end());//该页地址映射应该已经存在
            GPAddr &= 0xFFFFF000;
            auto iterator = cbitMapping[mapInd].find(GPAddr);
            if(iterator == cbitMapping[mapInd].end())
            {
                return -1;
            }
                return iterator->second;//return keyID
        }
        int searchInside(unsigned short vmid,unsigned short asid)
        {
            int index=-1;
            for(int i=0;i<insideTabSize;i++)
            {
                if(insideTab[i].VMID==vmid && insideTab[i].PID==asid)
                    return index=i;
            }
            return index;
        }
        // int searchOutside(unsigned short vmid,unsigned short asid)
        // {
        //     int index=-1;
        //     for(int i=0;i<outsideTabSize;i++)
        //     {
        //         if(outsideTab[i].VMID==vmid && outsideTab[i].PID==asid)
        //             return index=i;
        //     }
        //     return index;
        // }
        bool KeyCheck(unsigned char *key)
        {
            bool keyValid = false;
            for(int i=0;i<16;i++)
            {
                if(key[i])
                {
                    keyValid=true;
                    break;
                }
            }
            return keyValid;
        }
        int getLeastFreqindex()
        {
            if (insideKeyCnt==0)
            {
                return -1;
            }
            int index = 0;
            unsigned char tfreq=insideTab[0].freq;
            for(int i=1;i<insideKeyCnt;i++)
            {
                if(tfreq>insideTab[i].freq)
                {
                    tfreq =insideTab[i].freq;
                    index=i;
                }
            }
            return index;
        }
        void evctionKeyEntry(int insideIndex)
        {
            for(int i=0;i<insideKeyCnt;i++)
                insideTab[i].freq=0;//重置频次
            OutsideKeyEntry *outsidep = NULL;
            OutsideKeyEntry elem;
            elem.PID =  insideTab[insideIndex].PID;
            elem.VMID = insideTab[insideIndex].VMID;

            sm4Encrypt(insideTab[insideIndex].internalKey,CPUSAFEKEY,false,(uint64_t)insideTab[insideIndex].PID);
            sm4Encrypt(insideTab[insideIndex].externalKey,CPUSAFEKEY,false,(uint64_t)insideTab[insideIndex].PID);
            // int outsideIndex=searchOutside(insideTab[insideIndex].VMID,insideTab[insideIndex].PID);
            if(isElastic)
            {
                outsidep = find_elastic(&elem,&elasticCuckooHT);
                if(!outsidep)
                {
                    //dram中不存在
                    memcpy((char *)elem.externalKey,(const char*)insideTab[insideIndex].externalKey,16);
                    memcpy((char *)elem.internalKey,(const char*)insideTab[insideIndex].internalKey,16);
                    insert_elastic(&elem,&elasticCuckooHT,0,0);
                    outsideKeyCnt++;
                }
                else 
                {
                    memcpy((char *)(outsidep->externalKey),(const char*)insideTab[insideIndex].externalKey,16);
                    memcpy((char *)(outsidep->internalKey),(const char*)insideTab[insideIndex].internalKey,16);
                }
            }
            else 
            {
                assert(0 && "non-elastic");
            }
            
            // if (outsideIndex==-1)
            // {   
            //     outsideIndex=outsideKeyCnt;
            //     outsideKeyCnt++;
            // }
            // outsideTab[outsideIndex].PID=insideTab[insideIndex].PID;
            // outsideTab[outsideIndex].VMID=insideTab[insideIndex].VMID;
            return;
        }
        int cacheKeyInside(OutsideKeyEntry *outsidep)
        {
            assert(outsidep);

            int evctionIndex = insideKeyCnt; //最后一个位置
            if(insideKeyCnt==insideTabSize)  //如果已经满了
            {
                evctionIndex = getLeastFreqindex();
                
                if (evctionIndex!=-1&&insideTab[evctionIndex].dirty)//如果为脏
                {
                    evctionKeyEntry(evctionIndex);
                } 

                if(evctionIndex==-1)evctionIndex=0;
            }
            insideTab[evctionIndex].freq=0;
            insideTab[evctionIndex].dirty=0;
            insideTab[evctionIndex].PID =  outsidep->PID;
            insideTab[evctionIndex].VMID = outsidep->VMID;
            memcpy(insideTab[evctionIndex].externalKey,outsidep->externalKey,16);
            memcpy(insideTab[evctionIndex].internalKey,outsidep->internalKey,16);
            
            sm4Decrypt(insideTab[evctionIndex].internalKey,CPUSAFEKEY,false,insideTab[evctionIndex].PID);
            sm4Decrypt(insideTab[evctionIndex].externalKey,CPUSAFEKEY,false,insideTab[evctionIndex].PID);

            insideKeyCnt++;
            insideKeyCnt=insideKeyCnt>insideTabSize?insideTabSize:insideKeyCnt;
            return evctionIndex;
        }
       
        void enc_dec_init()
        {
            sm2::SM2_Init();//sm2
            srand((unsigned)time(NULL));
            
            hasInit=true;
            std_rand_get(CPUSAFEKEY,16,sm4::SM4_n);
            elasticCuckooTable_t elasticCuckooHT;
            cuckooTable_t cuckooHT;
            
            // for test all keys are same
            memcpy(ROOTpub.x,std_pubKey,32);
            memcpy(ROOTpub.y,std_pubKey+32,32);
            memcpy(ROOTpri,std_priKey,32);

            for(int i = 1;i <= 2;i++)
            {
                memcpy(sampleKeys[i].priKey,std_priKey,32);
                memcpy(sampleKeys[i].PubKey.x,std_pubKey,32);
                memcpy(sampleKeys[i].PubKey.y,std_pubKey+32,32);
            }

            if(isElastic)
            {
                // d, size, &elasticCuckooHT, hash_func, rehash_threshold,scale, swaps, priority
                create_elastic(d_ary,size_per_way,&elasticCuckooHT,BlakeHash,rehash_threshold,inc_scale,rehash_swaps,rehash_bias);
            }
            else
            {
                //non-elastic
                assert(0 && "now is not supported by non-elastic!");
            } 
        }
        void enc_dec_free()
        {
            destroy_elastic(&elasticCuckooHT);
            return;
        }

        int CreateIntKeySM4()
        {
            if(!hasInit)
            {
                printf("undone init\n");
            }

            //GENERATE SM4 keys
            unsigned short vmid=getVMID();
            unsigned short asid=getASID();
            unsigned char *insideKeyPtr;
            countForCreateKeys++;
            int index=insideKeyCnt;
            if(insideKeyCnt==insideTabSize)//内部已满
            {
                int index=getLeastFreqindex();
                assert(index!=-1);
                if(insideTab[index].dirty)
                {
                    evctionKeyEntry(index);
                }
            }
            else insideKeyCnt++;
            insideKeyPtr=insideTab[index].internalKey;
            insideTab[index].dirty=true;
            insideTab[index].freq=0;
            insideTab[index].PID=asid;insideTab[index].VMID=vmid;
            std_rand_get(insideKeyPtr,16,sm4::SM4_n);
            //for test
            {
                printf("in func CreateIntKeySM4: \n");
                for(int i=0;i<16;i++)
                {
                    printf("%02x",insideKeyPtr[i]);
                }
                printf("\n");
            }
            memset(insideTab[index].externalKey,0,sizeof(char)*16);
            return index;
        } 
        int CreateExtKeySM4(uint64_t hpwd,uint64_t lpwd)
        {
            unsigned short vmid = getVMID();
            unsigned short asid = getASID();
            int index=searchInside(vmid,asid);

            // printf("ext key:%lx%lx\n",hpwd,lpwd);
            
            if(index==-1)
            {
                OutsideKeyEntry elem;
                elem.VMID = vmid;
                elem.PID =  asid;

                OutsideKeyEntry *outsidep = find_elastic(&elem,&elasticCuckooHT);
                if(!outsidep)
                {
                    //新创建
                    assert(0 && "genky fisrt");
                    // index=CreateIntKeySM4();
                    // assert(index!=-1);
                }
                else 
                {
                    index=cacheKeyInside(outsidep);
                    insideTab[index].dirty=true;
                }
            }
            else 
            {
                insideTab[index].dirty=true;
            }
            if(KeyCheck(insideTab[index].externalKey))//没有重复创建
            {
                printf("Repeated creation of external key!\n");
                assert(0);
            }
            memcpy(insideTab[index].externalKey,&hpwd,8);
            memcpy(insideTab[index].externalKey+8,&lpwd,8);
            return index;
        }
        void DeleteKeyEntrySM4(unsigned short vmid ,unsigned short asid)
        {
            int index = searchInside(vmid,asid);
            OutsideKeyEntry elem;
            elem.VMID = vmid;
            elem.PID = asid;
            delete_elastic(&elem,&elasticCuckooHT);
            if(index != -1)
            {
                insideTab[index].PID = insideTab[insideKeyCnt].PID;
                insideTab[index].VMID = insideTab[insideKeyCnt].VMID;
                memcpy(insideTab[index].internalKey,insideTab[insideKeyCnt].internalKey,16);
                memcpy(insideTab[index].externalKey,insideTab[insideKeyCnt].externalKey,16);
                insideKeyCnt--;
            }
        }
        //请保证Message可容纳Mlen+96 bytes
        void sm2Encrypt(unsigned char* Message,unsigned int Mlen,epoint *pubKey)
        {
            countForEnc++;
            unsigned char MessageB[Mlen+96]={0};
            memcpy(MessageB,Message,Mlen);
            unsigned char randK[32]={0};
            std_rand_get(randK,32,(unsigned char*)(sm2::SM2_n));
            int tmp = sm2::SM2_Encrypt(randK, pubKey, MessageB, Mlen, Message);
            if (tmp != 0)
            {
                printf("encrypt error!\n");
                assert(!tmp);
            }	
            return;
        }
        void sm2Decrypt(unsigned char* Cipher,unsigned int Clen,unsigned char *priKey)
        {     
            countForDec++;
            big ks;
            ks = mirvar(0);
            bytes_to_big(32, reinterpret_cast<const char*>(priKey), ks);
            
            unsigned char CipherB[Clen]={0};
            memcpy(CipherB,Cipher,Clen);
            int tmp = sm2::SM2_Decrypt(ks, CipherB, Clen, Cipher);

            //for test
            printf("sm2 decrypt code:%d\n",tmp);

            if (tmp != 0)
            {
                printf("decrypt error!\n");
                assert(!tmp);
            }        
            return;
        }
        void sm4Encrypt(unsigned char* PlainText,unsigned char *priKey,bool isCacheLine,uint64_t paddr)
        {
            // return;
            // countForEnc++;
            unsigned char tPlainText[CachelineSize];
            memcpy(tPlainText,PlainText,isCacheLine?CachelineSize:16);
            unsigned char tmp;
            // 统一进程下 不同地址处相同数据 加密结果不一样
            *((uint64_t *) priKey) ^= paddr;
            *((uint64_t *)(priKey + 8)) ^= paddr;
            if(isCacheLine)
            {
                for(int i=0;i<4;i++)
                {
                    tmp=*priKey;
                    *priKey=(*priKey+i)%0xFF;//相同cacheLine下 不同分组的相同数据加密结果不一样
                    sm4::SM4_Encrypt(priKey,tPlainText+i*16,PlainText+i*16);
                    *priKey=tmp;
                }
                // for(int i=0;i<(isCacheLine?CachelineSize:16);i++)
                // {
                //     *(PlainText+i)+=1;
                // }
            }
            else 
            {
                sm4::SM4_Encrypt(priKey,tPlainText,PlainText);

                // for(int i=0;i<(isCacheLine?CachelineSize:16);i++)
                // {
                //     *(PlainText+i)+=1;
                // }
            }
            //复原密钥
            *((uint64_t *) priKey) ^= paddr; 
            *((uint64_t *)(priKey + 8)) ^= paddr;
            return;
        }
        void sm4Decrypt(unsigned char* CipherText,unsigned char *priKey,bool isCacheLine,uint64_t paddr)
        {
            // return;
            // countForDec++;
            unsigned char tCipherText[CachelineSize];
            memcpy(tCipherText,CipherText,isCacheLine?CachelineSize:16);
            unsigned char tmp;
            // 统一进程下 不同地址处相同数据 加密结果不一样
            *((uint64_t *) priKey) ^= paddr;
            *((uint64_t *)(priKey + 8)) ^= paddr;
            if(isCacheLine)
            {
                for(int i=0;i<4;i++)
                {
                    tmp=*priKey;
                    *priKey=(*priKey+i)%0xFF;//相同cacheLine下 不同分组的相同数据加密结果不一样
                    sm4::SM4_Decrypt(priKey,tCipherText+i*16,CipherText+i*16);
                    *priKey=tmp;
                }
                // for(int i=0;i<(isCacheLine?CachelineSize:16);i++)
                // {
                //     *(CipherText+i)-=1;
                // }
            }
            else 
            {
                sm4::SM4_Decrypt(priKey,tCipherText,CipherText);

                // for(int i=0;i<(isCacheLine?CachelineSize:16);i++)
                // {
                //     *(CipherText+i)-=1;
                // }
            }
             //复原密钥
            *((uint64_t *) priKey) ^= paddr;
            *((uint64_t *)(priKey + 8)) ^= paddr;
            return;
        }
        bool enc_dec_engine(PacketPtr pkt,unsigned char *functionalPtr,uint64_t addr,int model,int alg)
        { 

            unsigned char *dataPtr;
            uint64_t pktAddr;
            bool ifdo=false;
           
            //get addr,dataPtr
            switch (model)
            {
                case no_functional:// cache
                    dataPtr=pkt->getPtr<uint8_t>();
                    pktAddr=pkt->getAddr();
                    break;
                case is_functional: //bypass cache
                    dataPtr=functionalPtr;
                    pktAddr=addr;
                    break;
                default:
                    printf("wrong function\n");
                    assert(0);
                    break;
            }
            
            unsigned short asid = getASID();
            unsigned short vmid = getVMID();
            bool Cbit  = getCbit (pktAddr);

            if(!Cbit)
            {
                {
                    // if (pktAddr>=0x14000 && pktAddr<=0x15000)
                    // printf("get[%lx]\n",pktAddr);
                }//test
                return false;
            }
            else
            {
                // if (pktAddr>=0x14000 && pktAddr<=0x15000)
                //     printf("engine:%s[%lx]\n",(alg==sm4_encry)?"enc\0":"dec\0",pktAddr);
            }
            int keyID = getKeyID(pktAddr);
            assert(keyID!=-1);
            unsigned char *pk=NULL;
            
            int index = searchInside(vmid,asid);
            if(index==-1)//片上索引不存在
            {
                OutsideKeyEntry elem;
                elem.VMID = vmid;
                elem.PID =  asid;

                OutsideKeyEntry *outsidep = find_elastic(&elem,&elasticCuckooHT);
                if(!outsidep)//内存中索引不存在
                {
                    printf("key is not exsit!\n");
                    assert(0);
                }
                else//索引在外部
                {
                    index=cacheKeyInside(outsidep);//将索引缓存到片上
                    pk = keyID?insideTab[index].externalKey:insideTab[index].internalKey;
                    assert(KeyCheck(pk));//如果keyid=1 需要判断是否存在
                }
            }
            else//片上索引存在
            {
                pk = keyID?insideTab[index].externalKey:insideTab[index].internalKey;
                assert(KeyCheck(pk));//需要判断是否存在
            }
            if(alg==sm4_encry)//enc
            {   
                sm4Encrypt(dataPtr,pk,true,pktAddr);
                insideTab[index].freq++;
                ifdo=true;
                // AddrSet.insert(pktAddr);这是解决该地址未加密就解密
            }
            else if(alg==sm4_decry)//dec
            {
                // std::set<uint64_t>::iterator it=AddrSet.end();
                //if(AddrSet.find(pktAddr)!=AddrSet.end())//这是解决该地址未加密就解密
                // {
                sm4Decrypt(dataPtr,pk,true,pktAddr);
                insideTab[index].freq++;
                ifdo=true;
                // }
            }
            else 
            {
                printf("wrong model!\n");
                assert(0);
            }
            if (insideTab[index].freq==0xFF)//防止溢出
            {
                int least=getLeastFreqindex();
                // printf("[%d]max\n",index);
                assert(least!=-1);//至少有密钥
                insideTab[least].freq=0;
                for(int i=0;i<insideKeyCnt;i++)
                {
                    if(i != least)insideTab[i].freq=1;
                }
            }        
            // FILE *file=fopen("/home/li/trans-test/encTimes.txt","a+");
            // fprintf(file,"enc times:%ld  dectimes:%ld\n",countForEnc,countForDec);
            // fclose(file);
            return ifdo;
        }

        const char netWorkSimFile[] = "/home/li/trans-test/simNetWork/simlog.txt";
        const char AttestationSimFile[] = "/home/li/trans-test/simNetWork/simAttestation.txt";  
        const char memTransDataSimFile[] = "/home/li/trans-test/simNetWork/memTransData.txt";
        
        bool logFileWriter(unsigned char* svAddr,uint64_t size,int modl)
        {
            /*
                send through RDMA
            */
            FILE *file = fopen(netWorkSimFile,"a+");
            assert(file && "write netWorkSimFile");
            if (!file)
            {
                assert(0 && "in func logFileWriter: file open failed!\n");// for test
                return false;
            }
            if(!modl)
            {
                for (uint64_t i = 0;i<size;i++)
                {
                    if(*(svAddr+i))
                        fprintf(file,"%c",*(svAddr+i));
                    printf("%c",*(svAddr+i));
                }
            }
            else
            {
                for (uint64_t i = size;i;i--)
                {
                    fprintf(file,"%02x",*(svAddr+i-1));
                    printf("0x%02x",*(svAddr+i-1));
                    if(i>1)printf(", ");
                }
            }

            fclose(file);
            return true;
        }
        bool RDMARecv(unsigned char *srcBuff,unsigned char* dstSVAddr,uint64_t size)
        {
            /*
                recv through RDMA to dstSVAddr
            */
            assert(srcBuff && dstSVAddr && "in function RDMARecv");
            memcpy(dstSVAddr,srcBuff,size);
            return true;
        }
        bool RDMASend(unsigned char* svAddrSrc,uint64_t size)
        {
            /*
                send through RDMA from dstSVAddr
            */
            return true;
        }
        int itoa(unsigned char d,unsigned char *buff,unsigned int size)
        {
            // unsigned char *tbuff = (unsigned char *)malloc(sizeof(size));
            unsigned int i = size;
            while (d && size)
            {
                /* code */
                *(buff+size-1) = d%10 +'0';
                d/=10;
                size--;
            }
            return 3-size;
        }
        void getIPbymigDest(migDest *dest,unsigned char* ip,int mod)
        {
            // printf("in func getIP: %x\n",dest->ipv4);
            assert((mod == 4|| mod == 6) && ("ipv4 or ipv6"));
            assert(dest);
            unsigned char ipList[4];
            ipList [0] = dest->ipv4 >>24;
            ipList [1] = dest->ipv4 >>16;
            ipList [2] = dest->ipv4 >>8;
            ipList [3] = dest->ipv4;
            // itoa
            unsigned char tbuff[3]={0};
            unsigned char *t = ip;
            int ts;
            for (int i = 0; i < 4; i++)
            {
                /* code */
                // printf("plist[%d]=%x\n",i,ipList[i]);
                ts = itoa(*(ipList+i),tbuff,3);
                for(int j=0;j<ts;j++)
                {
                    *t = *(tbuff+3-ts+j);
                    t++;
                }
                if(i!=3)*t = '.';
                t++;
                memset(tbuff,0,3);
            }
            // printf("in func getIP: s:%s\n",ip);
            return;
        }
        bool getTimeStamp(unsigned char *timeSp)
        {
            if(!timeSp)return false;
            uint64_t timesp = time(NULL);
            printf("in func getTimeStamp:%ld\n",timesp);
            memcpy(timeSp,(uint8_t *)(&timesp),8);
            return true;
        }
        bool getIDA(unsigned char *IDA,int which)
        {
            memcpy(IDA,IDAs[which],8);
            return true;
        }
        void getZA(unsigned char *ZA,unsigned char *IDA,unsigned char *Pubx,unsigned char *Puby)
        {
            unsigned char Msg[202]; //2+8+32*6 = 202
            memcpy(Msg, ENTLA, 2);                          
            memcpy(Msg + 2, IDA, IDALen);                   
            memcpy(Msg + 2 + IDALen, sm2::SM2_a, SM2_NUMWORD);  
            memcpy(Msg + 2 + IDALen + SM2_NUMWORD, sm2::SM2_b, SM2_NUMWORD);
            memcpy(Msg + 2 + IDALen + SM2_NUMWORD * 2, sm2::SM2_Gx, SM2_NUMWORD);
            memcpy(Msg + 2 + IDALen + SM2_NUMWORD * 3, sm2::SM2_Gy, SM2_NUMWORD);
            memcpy(Msg + 2 + IDALen + SM2_NUMWORD * 4, Pubx, SM2_NUMWORD);
            memcpy(Msg + 2 + IDALen + SM2_NUMWORD * 5, Puby, SM2_NUMWORD);
            sm2::SM3_256(Msg, 202, ZA);
            return;
        }
        uint8_t *gvPtosvP(uint64_t msgGVAddr,unsigned short vmid,unsigned short asid,
                        unsigned short *mapInd,uint64_t *GPAddr)
        {
            uint8_t *svp = NULL;
            if(mapInd)
                *mapInd = getAddrSetIndex(vmid,asid);
            assert(vAddrMapping.find(*mapInd) != vAddrMapping.end());
            auto iteratorv = vAddrMapping[*mapInd].find(msgGVAddr & 0xFFFFF000);
            // assert(iteratorv != vAddrMapping[*mapInd].end() && (msgGVAddr & 0xFFFFF000));
            if(iteratorv == vAddrMapping[*mapInd].end())
            {
                printf("[%lx]unmapped\n",msgGVAddr & 0xFFFFF000);
            }
            *GPAddr = iteratorv->second;
            *GPAddr |= (msgGVAddr & 0x00000FFF);
            svp = toHostAddr(*GPAddr);
            return svp;
        }
        SM2PubKeystr *VerifyCA(respStruct *pkt)
        {
            assert(pkt);
            uint8_t level = pkt->CA.level;
            assert(level == 1);

            
            int npass;
            CAcard *iter;
            SM2PubKeystr *pubK = &ROOTpub;
            unsigned char ZA[SM3_len/8]={0},toBeCon[32*2];
            for(uint8_t i=0 ; i<level ; i++)
            {
                iter = &(pkt->CA.CAlink);
                getZA(ZA,iter->IssuingIDA,pubK->x,pubK->y);
                
                printf("in func VerifyCA: ZA\n");
                printf("in func VerifyCA: IDA   = %ld\n",*((uint64_t *)(iter->IssuingIDA)));

                for(int i=0;i<SM3_len/8;i++)
                {
                    printf("%02x",ZA[i]);
                }
                printf("\n");
                printf("IDA : %ld\n",*((uint64_t *)(iter->IssuingIDA)));
                memcpy(toBeCon,iter->PubK.x,32);
                memcpy(toBeCon+32,iter->PubK.y,32);
                
                npass = sm2::SM2_Verify(toBeCon,64,ZA,pubK->x,pubK->y,iter->sig.R,iter->sig.S);
                if(npass)
                {
                    printf("%d level verify failed!\n",i);
                    return NULL;
                }
                pubK = &(iter->PubK);
            }
            // printf("in func VerifyCA :%p\n",&(pkt->CA.CAlink[0].PubK));
            return pubK;
        }
        
        bool buildReq(reqStruct *reqPkt,migDest *destInfoSVAddr,uint8_t cla,uint8_t *dB,SM2PubKeystr *PB,unsigned char *timeSp,uint64_t size)
        {
            assert(reqPkt && destInfoSVAddr || cla <=1 || dB || timeSp && PB);
            if(!size)return false;    
            // if(!reqPkt || !destInfoSVAddr || cla >1 || !dB || !timeSp || !size || PB)
            // {
            //     if(!reqPkt)
            //     {
            //         printf("not reqPkt\n");
            //         return false;
            //     }
            //     if(!destInfoSVAddr)
            //     {
            //         printf("!destInfoSVAddr\n");
            //         return false;
            //     }
            //     if(cla>1)
            //     {
            //         printf("cla:%d\n",cla);
            //         return false;
            //     }
            //     if(!dB)
            //     {
            //         printf("!dB\n");
            //         return false;
            //     }
            //     if(!timeSp)
            //     {
            //         printf("!timeSp\n");
            //         return false;
            //     }
            //     if(!size)
            //     {
            //         printf("!size\n");
            //         return false;
            //     }
            //     if(!PB)
            //     {
            //         printf("!PB\n");
            //         return false;
            //     }
            //     else
            //     {
            //         if ((!(PB->x)))
            //         {
            //             printf("!PB->x\n");
            //             return false;
            //         }
            //         if ((!(PB->y)))
            //         {
            //             printf("!PB->y\n");
            //             return false;
            //         }
            //     }
            // }
            // return true;
            //dest ip   to string
            getIPbymigDest((migDest *)destInfoSVAddr,reqPkt->destIp,4);
            //dest port to string
            sprintf((char *)reqPkt->destPort,"%d",((migDest *)destInfoSVAddr)->port);
            
            //get IDA  应该有一个指令
            getIDA(reqPkt->IDA,1);//此处which = 0 为了测试
            reqPkt->cla = cla;//操作号 内存数据迁移
            // return true;
            //get PB
            memcpy(reqPkt->pubB.x,PB->x,32);
            memcpy(reqPkt->pubB.y,PB->y,32);

            //get timeStamp
            getTimeStamp(timeSp);
              
            memcpy(reqPkt->timeStamp,timeSp,8);

            //get sig_PB(tiamSp)
            unsigned char ZA[SM3_len/8]={0};
            unsigned char exLocIDA[8];
            unsigned char randForSign[32];
            getIDA(exLocIDA,1);
            std_rand_get(randForSign,32,(unsigned char *)(sm2::SM2_n));
            getZA(ZA,exLocIDA,PB->x,PB->y);
            sm2::SM2_Sign(reqPkt->timeStamp, 8, ZA, randForSign, dB, reqPkt->sig.R, reqPkt->sig.S);

            // print for test
            // for (int i=0;i<1;i++)
            // {
            //     printf("in func buildReq: sign rand:\n");
            //     for(int i=0;i<32;i++)
            //         printf("0x%02x,",*(randForSign+i));
            //     printf("\n");
            //     printf("in func buildReq: sign  IDA:\n");
            //     for(int i=0;i<8;i++)
            //         printf("0x%02x,",*(exLocIDA+i));
            //     printf("\n");
            //     printf("in func buildReq: sign pubK:\n");
                
            //     for(int i=0;i<32;i++)
            //         printf("0x%02x,",PB->x[i]);
            //     printf("\n");
            //     for(int i=0;i<32;i++)
            //         printf("0x%02x,",PB->y[i]);
            //     printf("\n");
            //     // break;
            //     printf("in func buildReq: sign ZA:\n");
            //     for(int i=0;i<32;i++)
            //         printf("0x%02x,",*(ZA+i));
            //     printf("\n");
            //     printf("in func buildReq: sign dB:\n");
            //     for(int i=0;i<32;i++)
            //         printf("0x%02x,",*(dB+i));
            //     printf("\n");
            // }
            
            /* get msg */
            //get timeSample has done before
            //get dst VMID-PID
            reqPkt->dVMID = ((migDest *)destInfoSVAddr)->nvmid;
            reqPkt->dPID = ((migDest *)destInfoSVAddr)->npid;
            //get size of trans mem
            reqPkt->size = size;
            return true;
        }
        bool verifyResp(respStruct *recv,uint8_t *timeSp,SM2PubKeystr **recvPubK)
        {
            assert(recv && timeSp);
            *recvPubK = VerifyCA(recv);
            if(!(*recvPubK))
            {
                // 校验未通过
                return false;
            }
            else
            {
                printf("CA pass\n");
            }
        
            unsigned char ZA[SM3_len/8]={0};
            getZA(ZA,recv->IDA,(*recvPubK)->x,(*recvPubK)->y);
            printf("in func verifyResp: IDA :");
            printf("%ld",*((uint64_t *)(recv->IDA)));
            printf("\n");
            for(int i=0;i<8;i++)
            {
                printf("%02x",ZA[i]);
            }
            printf("\n");
            if(sm2::SM2_Verify(timeSp,8,ZA,(*recvPubK)->x,(*recvPubK)->y,recv->timeSpsig.R,recv->timeSpsig.S))
            {
                printf("timeStamp verify failed\n");
                return false;
            }
            return true;
        }
        bool buildKeyEntry(keyStruct *keyPkt,unsigned short mapInd,uint64_t msgGPAddr,unsigned short vmid,
                            unsigned short asid,migDest *destInfoSVAddr,SM2PubKeystr *recvPubK)
        {
            if(!keyPkt || !destInfoSVAddr || !recvPubK)
                return false;
            // auto iterator = cbitMapping[mapInd].find(msgGPAddr);
            unsigned char sk[16]={0},H_M[32]={0},tmp[36]={0};
            if (!getCbit(msgGPAddr))
            {
                // printf("in func buildKeyEntry : unencrypted!\n");
                memset(keyPkt->E_PK_sk,0,SM2ENC_sk_Len);
                memset(keyPkt->SM4Enc_SK_sig_PB,0,(64));
                return true;
            }
            else 
            {
                int ind = searchInside(vmid,asid);
                if(ind == -1)
                {
                    /*
                        find outSide table
                    */
                    OutsideKeyEntry elem;
                    elem.VMID = vmid;
                    elem.PID =  asid;

                    OutsideKeyEntry *outsidep = find_elastic(&elem,&elasticCuckooHT);

                    assert(outsidep && !(outsidep->valid));

                    ind = cacheKeyInside(outsidep);
                }
                std_rand_get(sk,16,sm4::SM4_n);
                //for test
                {
                    printf("in func buildKeyEntry: sk:\n");
                    for(int i=0;i<16;i++)
                    {
                        printf("%02x",sk[i]);
                    }
                    printf("\n");
                }
                epoint *kG = epoint_init();
                big x,y;
                x=mirvar(0);
                y=mirvar(0);
                bytes_to_big(SM2_NUMWORD,(const char *)(recvPubK->x),x);
                bytes_to_big(SM2_NUMWORD,(const char *)(recvPubK->y),y);
                epoint_set(x,y,SM2_NUMWORD,kG);
                memcpy(keyPkt->E_PK_sk,sk,16);
                sm2Encrypt(keyPkt->E_PK_sk,16,kG);//SM2(sk)
                memcpy(tmp,((unsigned char*)&(((migDest *)destInfoSVAddr)->nvmid)),2);
                memcpy(tmp+2,((unsigned char*)&(((migDest *)destInfoSVAddr)->npid)),2);
                memcpy(tmp+4,insideTab[ind].internalKey,16);
                memcpy(tmp+20,insideTab[ind].externalKey,16);
            }
            //get H(M)
            sm2::SM3_256(tmp,36,H_M);
            memcpy(keyPkt->SM4Enc_SK_sig_PB,H_M,32);

            unsigned char ZA[SM3_len/8]={0};
            unsigned char exLocIDA[8];
            unsigned char randForSign[32];

            getIDA(exLocIDA,1);
            getZA(ZA,exLocIDA,sampleKeys[1].PubKey.x,sampleKeys[1].PubKey.y); //for test local machine is IDAs[1] ,remote is IDAs[2]
            std_rand_get(randForSign,32,(unsigned char *)sm2::SM2_n);
            unsigned char tmpHash[32];

            sm2::SM2_Sign(H_M, 32, ZA, randForSign, sampleKeys[1].priKey, 
                          keyPkt->SM4Enc_SK_sig_PB, keyPkt->SM4Enc_SK_sig_PB+32);

            //
            memcpy(keyPkt->SM4Enc_SK_sig_PB+64,tmp,36);
            
            sm4Encrypt(keyPkt->SM4Enc_SK_sig_PB,sk,true,0);
            sm4Encrypt(keyPkt->SM4Enc_SK_sig_PB+64,sk,true,0);
            return true;
        }
        void showData(unsigned char *p)
        {
            for(int i=0;i<4;i++)
            {
                for(int j=0;j<16;j++)
                {
                    if(j==8)printf(" ");
                    printf("%02x ",*(p+i*16+j));
                }
                for(int j=0;j<16;j++)
                {
                    if(j==0)printf("|| ");
                    if(j==8)printf(" ");
                    if(isprint(*(p+i*16+j)))
                        printf("%c ",*(p+i*16+j)); 
                    else printf("  ");
                }
                printf("\n");
            }
            printf("\n");
            return;
        }
        void DataTrans(uint64_t msgGVAddr,uint64_t destInfoGVAddr)
        {
            // printf("msg=[%lx],info=[%lx]\n",msgGVAddr,destInfoGVAddr);
            unsigned short vmid = getVMID() , asid = getASID();
            unsigned short mapInd = 0;
            uint64_t msgGPAddr = 0,dstInfoGPAddr = 0;
            uint8_t *msgSVAddr = gvPtosvP(msgGVAddr,vmid,asid,&mapInd,&msgGPAddr);      //内存起始地址
            assert(msgSVAddr != NULL);
            // printf("msgGP=%p,msgSV=%p\n",msgGPAddr,msgSVAddr);
            // for(int i=0;i<5;i++)
            // {
            //     printf("%c",*(msgSVAddr+i));
            // }
            // printf("\n");
            // return;
            uint8_t *destInfoSVAddr = gvPtosvP(destInfoGVAddr,vmid,asid,&mapInd,&dstInfoGPAddr);//连接目标信息起始指针
            assert(destInfoSVAddr != NULL);
            
            uint64_t size = ((migDest *)destInfoSVAddr)->size;
            assert(!(size%64) && "transfer unit must align with 64B");

            // printf("in func [dataTrans]: size=%ld\n",size);
            // [dest info]||IDA||cla||PB||sigB(tS0)||(tS0||dest_VMID-PID||size)
            unsigned char timeSp[8]={0};
            reqStruct reqPkt;

            if(!buildReq(&reqPkt,(migDest *)destInfoSVAddr,0,sampleKeys[1].priKey,&(sampleKeys[1].PubKey),timeSp,size))
            {
                printf("build req failed!\n");
                return;
            } 
            FILE *file=NULL;
            {
                logFileWriter((unsigned char *)"**********Request**********\n",29,0);
                logFileWriter((unsigned char *)"dest ip: ",10,0);
                logFileWriter(reqPkt.destIp,16,0);
                // file =fopen(netWorkSimFile,"a+");
                // assert(file && "write dest ip");
                // fprintf(file,"%s",reqPkt.destIp);
                // fprintf(file,"\n");
                // fclose(file);

                logFileWriter((unsigned char *)" dest port: ",13,0);
                logFileWriter(reqPkt.destPort,dstPortLen,0);

                logFileWriter((unsigned char *)"\nIDA: ",7,0);
                logFileWriter(reqPkt.IDA,8,1);

                logFileWriter((unsigned char *)"\ncla: ",7,0);
                logFileWriter(&(reqPkt.cla),1,1);

                logFileWriter((unsigned char *)"\nPB:",5,0);
                logFileWriter((unsigned char *)"\n  x: ",7,0);
                logFileWriter(reqPkt.pubB.x,32,1);
                logFileWriter((unsigned char *)"\n  y: ",7,0);
                logFileWriter(reqPkt.pubB.y,32,1);

                logFileWriter((unsigned char *)"\nsig:",6,0);     
                logFileWriter((unsigned char *)"\n  r: ",7,0);
                logFileWriter(reqPkt.sig.R,32,1);
                logFileWriter((unsigned char *)"\n  s: ",7,0);
                logFileWriter(reqPkt.sig.S,32,1);
                
                logFileWriter((unsigned char *)"\ntimeStamp: ",13,0);
                //手动打印格式时间戳
                printf("%ld",*((uint64_t *)reqPkt.timeStamp));
                file =fopen(netWorkSimFile,"a+");
                // assert(file && "write timeStamp");
                fprintf(file,"%ld",*((uint64_t *)reqPkt.timeStamp));
                fclose(file);
                
                logFileWriter((unsigned char *)"\ndest VMID: ",13,0);
                logFileWriter((unsigned char *)(&(reqPkt.dVMID)),2,1);
                // return;
                logFileWriter((unsigned char *)" dest PID: ",12,0);
                
                logFileWriter((unsigned char *)(&(reqPkt.dPID)),2,1);

                logFileWriter((unsigned char *)"\nsize: ",8,0);
                file =fopen(netWorkSimFile,"a+");
                assert(file && "write size");
                fprintf(file,"%ld",reqPkt.size);
                fclose(file);
                printf("%ld",reqPkt.size);
                logFileWriter((unsigned char *)"\n***************************\n\n",31,0);
            }
            /*
                if you have a dma just
                
                rDMAsend(...)
            */
            //else sim by file r/w
            file =fopen(AttestationSimFile,"w");
            assert(file && "write AttestationSimFile");
            fwrite(&reqPkt,sizeof(reqStruct),1,file);
            fclose(file);

            // return;
            
            //sleep a few seconds to sim RDMA
            //sleep(3)
            printf("sending request...\n");
            // {
            //     for(int i=0;i<8;i++)printf("%02x",*(reqPkt.timeStamp+i));
            //     printf("\n");
            //     for(int i=0;i<32;i++)
            //         printf("0x%02x,",*(reqPkt.sig.R+i));
            //     printf("\n");
            //     for(int i=0;i<32;i++)
            //         printf("0x%02x,",*(reqPkt.sig.S+i));
            //     printf("\n");
            // }
            // getchar();
            sleep(7);

            respStruct recv;
            file =fopen(AttestationSimFile,"r");
            assert(file && "read AttestationSimFile");
            // fread(RDMABuff,sizeof(respStruct),1,file);
            fread(&recv,sizeof(respStruct),1,file);
            fclose(file);
            // respStruct *recv = (respStruct *)RDMABuff;

            SM2PubKeystr *recvPubK = NULL;
            printf("get identity...\n");

            //verify 
            if (!verifyResp(&recv,timeSp,&recvPubK))
            {
                logFileWriter((unsigned char *)"Remote Server fail to verify\n\n",31,0);
                return;
            }
            else 
            {
                logFileWriter((unsigned char *)"******attestation pass******\n\n",31,0);
            }
            //build key entry
            keyStruct keyPkt;
            if(!buildKeyEntry(&keyPkt,mapInd,msgGPAddr,vmid,asid,(migDest *)destInfoSVAddr,recvPubK))
            {
                logFileWriter((unsigned char *)"*failed to build key entry**\n\n",31,0);
                return;
            }
            else
            {
                logFileWriter((unsigned char *)"****build key entry over****\n\n",31,0);
            }

            // send key entry
            // RDMASend...
            file = fopen(memTransDataSimFile,"w");
            assert(file && "write memTransDataSimFile");
            fwrite(&keyPkt,sizeof(keyStruct),1,file);
            fclose(file);
            printf("sending key entry...\n");
            // getchar();
            sleep(4.5);

            /* ignore get ack sign */

            // send Mem ...
            file = fopen(memTransDataSimFile,"w");
            assert(file && "write memTransDataSimFile");
            dataStruct line;
            
            printf("sending data...\n\n");
            for(int i=0;i<size/64;i++)
            {
                line.keyID = getKeyID(msgGPAddr+i*64);
                line.lineAddr = msgGPAddr + i*64;
                memcpy(&line.lineCont,msgSVAddr+i*64,64);
                fwrite(&line,sizeof(dataStruct),1,file);
                showData(line.lineCont);
            }
            fclose(file);
            printf("sending over...\n");
            sleep(3);

            printf("over!\n");
            return;
        }   
        bool searchAccIDATable(unsigned char *IDA)
        {
            return true;
        }
        bool addAccIDA(unsigned char *IDA)
        {
            return true;
        }
        bool proIsExist(unsigned short vmid, unsigned short pid)
        {
            return true;
        }
        bool verifyReq(reqStruct *recvPkt,uint8_t *cla,unsigned short *vmid,
                        unsigned short *pid,uint64_t *size,SM2PubKeystr *PB,unsigned char *timeSp)
        {
            if(!recvPkt)
            {
                printf("!recvPkt");
            }
       
            assert(recvPkt && PB && timeSp && size && cla);
            if(!searchAccIDATable(recvPkt->IDA))
                return false;
            
            // recvPkt->cla; // handle
            *vmid = recvPkt->dVMID;
            *pid = recvPkt->dPID;
            assert((recvPkt->cla == 0 && proIsExist(recvPkt->dVMID,recvPkt->dPID))||
                    (recvPkt->cla == 1 && !proIsExist(recvPkt->dVMID,recvPkt->dPID)));

            unsigned char ZA[SM3_len/8]={0};
            getZA(ZA,recvPkt->IDA,recvPkt->pubB.x,recvPkt->pubB.y);
            
            for(int i=0;i<32;i++)
                printf("0x%02x,",*((recvPkt->sig.R)+i));
            printf("\n");
            for(int i=0;i<32;i++)
                printf("0x%02x,",*((recvPkt->sig.S)+i));
            printf("\n");

            assert(!(sm2::SM2_Verify(recvPkt->timeStamp,8,ZA,recvPkt->pubB.x,recvPkt->pubB.y,
                                     recvPkt->sig.R,recvPkt->sig.S)) && "recv req's verify failed");
            memcpy(PB->x,recvPkt->pubB.x,32);
            memcpy(PB->y,recvPkt->pubB.y,32);
            memcpy(timeSp,recvPkt->timeStamp,8);

            

            assert((recvPkt->size <= (uint64_t)RDMABuff));
            *size = recvPkt->size;
            return true;
        }
        void getCACertificate(simpleCA *container,SM2PubKeystr *msgPub)
        {
            assert( container && msgPub);
            container->level=1;//for test auto get

            // container->CAlink = (CAcard *)malloc((container->level)*sizeof(CAcard));

            unsigned char ZA[SM3_len/8]={0};
            getZA(ZA,IDAs[0],ROOTpub.x,ROOTpub.y);
            printf("in func getCACer: ZA\n");
            for(int i=0;i<SM3_len/8;i++)
            {
                printf("%02x",ZA[i]);
            }
            printf("\n");
            unsigned char msg[64];
            memcpy(msg,msgPub->x,32);
            memcpy(msg+32,msgPub->y,32);

            unsigned char randForSign[32];
            std_rand_get(randForSign,32,(unsigned char *)sm2::SM2_n);
            assert(!(sm2::SM2_Sign(msg,64,ZA,randForSign,ROOTpri,container->CAlink.sig.R,container->CAlink.sig.S)));
            
            memcpy(container->CAlink.PubK.x , msgPub->x,32);
            memcpy(container->CAlink.PubK.y , msgPub->y,32);
            memcpy(container->CAlink.IssuingIDA,IDAs[0],8);
            return;
        }
        bool getFreeVM(unsigned short *vmid,unsigned short *asid)
        {
            *vmid = 0;
            *asid = 0;
            return true;
        }
        bool buildResp(respStruct *resp,SM2KeyPairs *keyPair,unsigned char *timeSp,unsigned char cla)
        {
            getIDA(resp->IDA,2);
            getCACertificate(&(resp->CA),&(sampleKeys[2].PubKey));
            unsigned char randForSign[32],ZA[SM3_len/8];

            std_rand_get(randForSign,32,(unsigned char *)sm2::SM2_n);
            getZA(ZA,resp->IDA,keyPair->PubKey.x,keyPair->PubKey.y);
            printf("signIDA = %ld\n",*((uint64_t *)(resp->CA.CAlink.IssuingIDA)));
            printf("req.IDA = %ld\n",*((uint64_t *)(resp->IDA)));
            printf("in func buildResp: ZA\n");
            for(int i=0;i<32;i++)
            {
                printf("%02x",ZA[i]);
            }
            printf("\n");
            printf("timeSp: %ld\n",*((uint64_t *)timeSp));
            sm2::SM2_Sign(timeSp,8,ZA,randForSign,keyPair->priKey,resp->timeSpsig.R,resp->timeSpsig.S);

            if(cla == 1)
            {
                assert(getFreeVM(&(resp->VMID),&(resp->PID)) && "no free VM");
                unsigned char buff[32];
                sprintf((char *)buff,"%x",resp->VMID);
                sprintf((char *)(buff+16),"%x",resp->PID);
                sm2::SM3_256(buff,32,resp->H_V_P);
            }
            else 
            {
                resp->VMID = resp->PID = 0;
                memset(resp->H_V_P,0,32);
            }
            return true;
        }    
        bool getKeyEntry(keyStruct *keyEntry,unsigned char *priK,SM2PubKeystr *PB,uint8_t cla,
                        unsigned char *internalK,unsigned char *externalK,unsigned short dvmid,unsigned short dpid)
        {    
            bool isEnc = false;
            for(int i=0;i<SM2ENC_sk_Len;i++)
            {
                if (*(keyEntry->E_PK_sk+i))
                {
                    isEnc = true;
                    break;
                }
            }
            if(!isEnc)
            {
                printf("non-encrypted page\n");
                return false;//未加密
            }
             
            sm2Decrypt(keyEntry->E_PK_sk,SM2ENC_sk_Len,priK);
            unsigned char sk[16];
            memcpy(sk,keyEntry->E_PK_sk,16);
            //for test
            {
                printf("in func getKeyEntry: get sk:\n");
                for(int i=0;i<16;i++)
                {
                    printf("%02x",sk[i]);
                }
                printf("\n");
            }

            sm4Decrypt(keyEntry->SM4Enc_SK_sig_PB,sk,true,0);
            sm4Decrypt(keyEntry->SM4Enc_SK_sig_PB+64,sk,true,0);
            /* ignore check sigB(H(M)) */
            unsigned short vmid,pid;
            vmid = *((unsigned short *)((unsigned char *)(keyEntry->SM4Enc_SK_sig_PB+64)));
            pid = *((unsigned short *)((unsigned char *)(keyEntry->SM4Enc_SK_sig_PB+64+2)));
            printf("vmid=%d,dvmid=%d   pid=%d,dpid=%d\n",vmid,dvmid,pid,dpid);
            assert(vmid == dvmid && pid == dpid);
            memcpy(internalK,keyEntry->SM4Enc_SK_sig_PB+64+4,16);
            memcpy(externalK,keyEntry->SM4Enc_SK_sig_PB+64+4+16,16);
            return true;
        }
        
        void AccDataTrans(uint64_t dstGVAddr,uint64_t guestInfo)
        {
            unsigned short vmid = getVMID() , asid = getASID();
            unsigned short mapInd = 0;
            uint64_t dstGPAddr = 0,gstInfoGPAddr;
            uint8_t *dstSVAddr = gvPtosvP(dstGVAddr,vmid,asid,&mapInd,&dstGPAddr);          //目标内存起始地址
            assert(dstSVAddr != NULL);

            uint8_t *guestInfoSVAddr = gvPtosvP(guestInfo,vmid,asid,&mapInd,&gstInfoGPAddr);//连接目标信息起始指针
            assert(guestInfoSVAddr != NULL);

            addAccIDA(guestInfoSVAddr);//加入列表
            printf("adding guest's IDA\n");

            reqStruct recvPkt;
            unsigned short dstVMID,dstPID;
            unsigned char cla;
            SM2PubKeystr PB; 
            uint64_t size;
            unsigned char timeSp[8]={0},internalK[16]={0},externalK[16]={0};

            printf("sniffing request...\n");
            sleep(3);
            //recv
            printf("getting request\n");
            FILE *file = fopen(AttestationSimFile,"r");
            assert(file && "read AttestationSimFile");
            fread(&recvPkt,sizeof(reqStruct),1,file);
            fclose(file);
            
            if (verifyReq(&recvPkt,&cla,&dstVMID,&dstPID,&size,&PB,timeSp));
            printf("accept request from[%lx]...\n",*((uint64_t *)(recvPkt.IDA)));
            // printf("in func AccDataTrans timesp %ld\n",*((uint64_t *)timeSp));
            sleep(1.5);

            respStruct resp;
            buildResp(&resp,&(sampleKeys[2]),timeSp,cla);

            file = fopen(AttestationSimFile,"w");
            assert(file && "write AttestationSimFile");
            fwrite(&resp,sizeof(respStruct),1,file);
            fclose(file);
            printf("sending identity...\nwaiting for key entry...\n\n");
            sleep(4.5);

            //get key entry
            keyStruct keyEntry;
            file = fopen(memTransDataSimFile,"r");
            assert(file && "read memTransDataSimFile");
            fread(&keyEntry,sizeof(keyStruct),1,file);
            fclose(file);

            getKeyEntry(&keyEntry,sampleKeys[2].priKey,&PB,cla,internalK,externalK,dstVMID,dstPID);
            printf("get key entry\ninternal key:\n");
            for(int i=0;i<16;i++)
            {
                printf("%02x",internalK[i]);
            }
            printf("\n");
            printf("waiting data:\n");
            sleep(4);

            dataStruct line;
            file = fopen(memTransDataSimFile,"r");
            printf("get data: \n");
            uint64_t cnt = 0;
            for(int i=0;i<size/64;i++)//for 0 -> size/64
            {
                fread(&line,sizeof(dataStruct),1,file);
                printf("in func AccDataTrans: KeyId %d vaddr %lx\n",line.keyID,line.lineAddr);
                if(line.keyID == 0)
                {
                    sm4Decrypt(line.lineCont,internalK,true,line.lineAddr);
                }
                else if (line.keyID == 1)
                {
                    sm4Decrypt(line.lineCont,externalK,true,line.lineAddr);
                }
                showData(line.lineCont);
                //reEncry and copy
                {
                    enc_dec_engine(NULL,line.lineCont,dstGVAddr,is_functional,sm4_encry);
                    RDMARecv(line.lineCont,dstSVAddr+cnt*64,CachelineSize);
                    cnt++;
                }
            }
            sleep(2);
            printf("over!\n");
            return;
        }
        
        void VMTrans(uint64_t msgGVAddr,uint64_t size,uint64_t destInfoGVAddr)
        {
            return;
        }
        void AccVMTrans(uint64_t dstgvAddr,uint64_t size,uint64_t guestInfo)
        {
            return;
        }
    }//encry_mod
}//gem5
