#ifndef COMMON_H
#define COMMON_H

#include "printhex.h"
#include "api.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <omnetpp.h>
#include "DataMsg_m.h"

#ifdef _WIN32


#define SERVER_PK_PATH "d:/server.pk"
#define SERVER_SK_PATH "d:/server.sk"

#define CLIENT_PK_PATH "d:/client.pk"
#define CLIENT_SK_PATH "d:/client.sk"

#else
#include <unistd.h>
#include <errno.h>

#define SERVER_PK_PATH "/home/veins/.key/server.pk"
#define SERVER_SK_PATH "/home/veins/.key/server.sk"

#define CLIENT_PK_PATH "/home/veins/.key/client.pk"
#define CLIENT_SK_PATH "/home/veins/.key/client.sk"
#endif

#define ERRORMSG strerror(errno)

#define EVN EV << "\n"
#define EVN1(s1) EV << (s1) << "\n"
#define EVN2(s1, s2) EV << (s1) << (s2) << "\n"
#define EVN3(s1, s2, s3) EV << (s1) << (s2) << (s3) << "\n"
#define EVN4(s1, s2, s3, s4) EV << (s1) << (s2) << (s3) << (s4) << "\n"
#define EVN5(s1, s2, s3, s4, s5) EV << (s1) << (s2) << (s3) << (s4) << (s5) << "\n"
#define EVN6(s1, s2, s3, s4, s5, s6) EV << (s1) << (s2) << (s3) << (s4) << (s5) << (s6) << "\n"
#define EVN7(s1, s2, s3, s4, s5, s6, s7) EV << (s1) << (s2) << (s3) << (s4) << (s5) << (s6) << (s7) << "\n"

//char *stringhex(unsigned char *data, size_t len);
#define EVHEX(data, len) {char *__str = stringhex((unsigned char *)(data), (len)); EVN1(__str); free(__str);}

#define VFIN(errmsg) throw cRuntimeError((errmsg))
#define VERR(mainmsg) EVN3(mainmsg, " ", ERRORMSG); VFIN((mainmsg))

unsigned char *get_msg_data(DataMsg *msg);

unsigned char *get_msg_data2(DataMsg *msg);

void set_msg_data(DataMsg *msg, unsigned char *data);

void set_msg_data2(DataMsg *msg, unsigned char *data);


void aes_128_encrypt(const char *aes_key, char *aes_iv, char *data, size_t data_len, char *out);


void aes_128_decrypt(const char *aes_key, char *aes_iv, char *data, size_t data_len, char *out);

void random_len_data_encrypt_aes128_without_lenprefix
                                   (int *random_data_len, //true random data len
                                    int *random_data_len_to16, // 16-256 , 16 multi
                                    const char *aes_key,
                                    char *aes_iv,
                                    char **data_plain,
                                    char **data_encrypted);

void sha256(const unsigned char *k, const unsigned char *k1, const unsigned char *k2, unsigned char *out);


class MyCommon: public omnetpp::cSimpleModule
{
  public:
    unsigned char       pk[pqcrystals_kyber512_PUBLICKEYBYTES];
    unsigned char       sk[pqcrystals_kyber512_SECRETKEYBYTES];

    unsigned char       pk1[pqcrystals_kyber512_PUBLICKEYBYTES];
    unsigned char       sk1[pqcrystals_kyber512_SECRETKEYBYTES];

    unsigned char       pk2[pqcrystals_kyber512_PUBLICKEYBYTES];
    unsigned char       sk2[pqcrystals_kyber512_SECRETKEYBYTES];

    unsigned char       k[pqcrystals_kyber512_ref_BYTES];
    unsigned char       c[pqcrystals_kyber512_CIPHERTEXTBYTES];

    unsigned char       k1[pqcrystals_kyber512_ref_BYTES];
    unsigned char       c1[pqcrystals_kyber512_CIPHERTEXTBYTES];

    unsigned char       k2[pqcrystals_kyber512_ref_BYTES];
    unsigned char       c2[pqcrystals_kyber512_CIPHERTEXTBYTES];

    unsigned char       aes_key[16], aes_iv_encrypt[16], aes_iv_decrypt[16];
    char *aes_key_str;

    int                 ret_val;
    bool                is_handshake_finish = false;
  private:
    char *aes_iv_encrypt_str = NULL;
    char *aes_iv_decrypt_str = NULL;
  protected:
     // The following redefined virtual function holds the algorithm.
     virtual void initialize() override{}
     virtual void handleMessage(omnetpp::cMessage *msg) override{}
  public:
     char *get_aes_iv_encrypt_str() {
         if (aes_iv_encrypt_str) {
             free(aes_iv_encrypt_str);
         }

         aes_iv_encrypt_str = stringhex(aes_iv_encrypt, 16);

         return aes_iv_encrypt_str;
     }

     char *get_aes_iv_decrypt_str() {
         if (aes_iv_decrypt_str) {
              free(aes_iv_decrypt_str);
          }

          aes_iv_decrypt_str = stringhex(aes_iv_decrypt, 16);

          return aes_iv_decrypt_str;
     }

     void printhex(unsigned char *hex, size_t len)
     {
         size_t index = 0;

         while (1)
         {
             if (len - index >= 32) {
                 EVHEX(hex +  index, 32);
                 index += 32;
             }
             else {
                 EVHEX(hex +  index, len - index);
                 break;
             }
         }
     }

     void sendRandomData(DataMsg* datamsg) {
         int random_data_len; //true random data len
         int random_data_len_to16; // 16-256 , 16 multi

         char *random_data_plain;
         char *random_data_encryped;

         random_len_data_encrypt_aes128_without_lenprefix
                                         (&random_data_len, &random_data_len_to16, (const char*)aes_key, (char*)aes_iv_encrypt,
                                          &random_data_plain, &random_data_encryped);

         datamsg->setSerial(datamsg->getSerial() + 1);

         EVN7("Sent serial ", datamsg->getSerial() ," Random data bytes(", random_data_len, " to ", random_data_len_to16, ")");
         EVN1("plain text:");
         printhex((unsigned char*)random_data_plain, random_data_len);

         EVN1("Plain text with padding 0:");
         printhex((unsigned char*)random_data_plain, random_data_len_to16);

         EVN5("ciphertext encrypt by key:(", aes_key_str, ") iv:(", get_aes_iv_encrypt_str(), ")");
         printhex((unsigned char*)random_data_encryped, random_data_len_to16);

         EVN;
         EVN;

         char randomdatamsg[1024] = {0};
         char *randomdatastring = stringhex((unsigned char*)random_data_plain, random_data_len > 16 ? 16 : random_data_len);

         if (random_data_len>16) {
             sprintf(randomdatamsg, "\niv:%s\nRandom Message (%d bytes)\n %s%s\n", get_aes_iv_encrypt_str(), random_data_len, randomdatastring, "..........");
         }
         else
         {
             sprintf(randomdatamsg, "\niv:%s\nRandom Message (%d bytes)\n %s\n", get_aes_iv_encrypt_str(), random_data_len, randomdatastring);
         }

         free(randomdatastring);

         datamsg->setName(randomdatamsg);
         set_msg_data(datamsg, (unsigned char*)random_data_encryped);

         datamsg->setTruelen(random_data_len);
         datamsg->setDatalen(random_data_len_to16);

         send(datamsg, "out");

         free(random_data_plain);
     }

     void receiveRandomData(DataMsg* datamsg) {
         char *out = new char[datamsg->getDatalen()];

         aes_128_decrypt((const char*)aes_key, (char*)aes_iv_decrypt, ((char*)get_msg_data(datamsg)), datamsg->getDatalen(), out);

         EVN7("Received serial ", datamsg->getSerial() ," random data bytes(", datamsg->getTruelen(), " to ", datamsg->getDatalen(), ")");
         EVN1("Received ciphertext:");
         printhex(get_msg_data(datamsg), datamsg->getDatalen());
         EVN5("\nDecrept by key:(", aes_key_str, ") iv:(", get_aes_iv_decrypt_str(), ")");
         printhex((unsigned char*)out, datamsg->getDatalen());
         EVN1("\nRemove the trailing padding 0, get true plain data:");
         printhex((unsigned char*)out, datamsg->getTruelen());
         EVN;
         EVN;

         delete[] out;
         free((unsigned char*)(get_msg_data(datamsg)));
     }

     ~MyCommon(){
        free(aes_key_str);
        free(aes_iv_encrypt_str);
        free(aes_iv_decrypt_str);
     };
};

#endif //COMMON_H
