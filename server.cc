#include <string.h>
#include <omnetpp.h>
#include <stdio.h>
#include <error.h>

#include "api.h"

#include "printhex.h"
#include "common.h"
#include "randombytes.h"

#include "DataMsg_m.h"

using namespace omnetpp;

class Server : public MyCommon
{
  protected:
    // The following redefined virtual function holds the algorithm.
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
};

// The module class needs to be registered with OMNeT++
Define_Module(Server);

void Server::initialize()
{
    FILE *fp = fopen(SERVER_SK_PATH, "rb");
    fread(sk2, pqcrystals_kyber512_ref_SECRETKEYBYTES, 1, fp);
    fclose(fp);

    EVN3("Read server secret key from ", SERVER_SK_PATH," as sk2 successfully!");
    printhex(sk2, pqcrystals_kyber512_ref_SECRETKEYBYTES);

    fp = fopen(CLIENT_PK_PATH, "rb");
    fread(pk1, pqcrystals_kyber512_ref_PUBLICKEYBYTES, 1, fp);
    fclose(fp);

    EVN3("Read client public key from ", CLIENT_PK_PATH," as pk1 successfully!");
    printhex(pk1,pqcrystals_kyber512_ref_PUBLICKEYBYTES);
}

void Server::handleMessage(cMessage *msg)
{
    DataMsg* datamsg = check_and_cast<DataMsg*>(msg);

    if (!is_handshake_finish){
        memcpy(pk, get_msg_data(datamsg), pqcrystals_kyber512_PUBLICKEYBYTES);
        memcpy(c2, get_msg_data2(datamsg), pqcrystals_kyber512_CIPHERTEXTBYTES);

        EVN1("Received pk, c2 from client");

        if ( (ret_val = pqcrystals_kyber512_ref_dec(k2, c2, sk2)) != 0) {
            EVN2("Error key c2: ret value is ", ret_val);
            VFIN("Error key c2");
        }

        EVN1("Decaps k2 from sk2 c2:");
        EVN1("k2 is:");
        EVHEX(k2, 32);
        EVN1("\n");

        if ( (ret_val = pqcrystals_kyber512_ref_enc(c, k, pk)) != 0) {
            EVN2("crypto_kem_enc failed ", ret_val);
            VFIN("crypto_kem_enc failed");
        }

        EVN1("Encaps pk ---> c k successully!");
        EVN1("K is:");
        EVHEX(k, pqcrystals_kyber512_ref_BYTES);
        EVN1("\n");

        if ( (ret_val = pqcrystals_kyber512_ref_enc(c1, k1, pk1)) != 0) {
            EVN2("crypto_kem_enc failed ", ret_val);
            VFIN("crypto_kem_enc failed");
        }

        EVN1("Encaps pk1 ---> c1 k1 successully!");
        EVN1("K1 is:");
        EVHEX(k1, pqcrystals_kyber512_ref_BYTES);
        EVN1("\n");

        datamsg->setName("c c1");
        set_msg_data(datamsg, c);
        set_msg_data2(datamsg, c1);

        EVN1("Send c c1 to client successfully!");

        unsigned char aeskeyiv[32];

        sha256(k, k1, k2, aeskeyiv);

        memcpy(aes_key, aeskeyiv, 16);
        memcpy(aes_iv_encrypt, aeskeyiv + 16, 16);
        memcpy(aes_iv_decrypt, aeskeyiv + 16, 16);

        EVN1("Hash k k1 k2 by sha3-256, get aes key and iv:");
        EVN1("AES KEY:");
        EVHEX(aes_key, 16);
        EVN;
        EVN1("AES IV:");
        EVHEX(aeskeyiv + 16, 16);
        EVN1("\n");

        send(datamsg, "out");

        aes_key_str = stringhex(aes_key, 16);

        is_handshake_finish = true;
    } else {
        receiveRandomData(datamsg);
        sendRandomData(datamsg);
    }
}

