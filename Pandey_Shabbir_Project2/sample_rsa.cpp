//
//  main.cpp
//  crypto_test
//
//  Created by Ahmed Shabbir on 11/28/14.
//  Copyright (c) 2014 NYU. All rights reserved.
//


#include <iostream>
using namespace std;

#include "cryptlib.h"
#include "rsa.h"
#include "osrng.h"
#include "files.h"
#include "aes.h"
#include "modes.h"
#include "base32.h"

using namespace CryptoPP;


void test_rnd(){
    AutoSeededRandomPool rng;
    
    int countZero = 0;
    int countOne = 0;
    
    for (int i = 0; i < 100 ; i++) {
        int num =  rng.GenerateBit() ;
        if (num == 0){
            countZero ++;
        } else {
            countOne ++;
        }
        cout << num;
    }
    cout<< endl;
    
    float distOne = (countOne * 1.0) / 100;
    float distZero = (countZero * 1.0) / 100;
    
    cout << "DZ " << distZero << endl;
    cout << "DO " << distOne << endl;
}


void create_key() {
    ///////////////////////////////////////
    // Pseudo Random Number Generator
    AutoSeededRandomPool rng;
 
    
    
    ///////////////////////////////////////
    // Generate Parameters
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 256);
    
    
    ///////////////////////////////////////
    // Create Keys
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);
    
    Base32Encoder pubkeysink(new FileSink("/Users/amd/Documents/Pandey_Shabbir_Project2/pubkey.txt"));
    Base32Encoder privatekeysink(new FileSink("/Users/amd/Documents/Pandey_Shabbir_Project2/privatekey.txt"));

    // Base32Encoder privatekeysink(new FileSink("/Users/amd/Dropbox/Projects/Cryptography/Proj2/Crypt_project2/Pandey_Shabbir_Project2/privatekey.txt"));
    // Base32Encoder pubkeysink(new FileSink("/Users/amd/Dropbox/Projects/Cryptography/Proj2/Crypt_project2/Pandey_Shabbir_Project2/pubkey.txt"));
    publicKey.DEREncode(pubkeysink);
    privateKey.DEREncode(privatekeysink);
    pubkeysink.MessageEnd();
    cout << "file saved" << endl;
}








/********
 If i have a key and iv i can encrypt using aes
 ********/

void encrypt_aes(char plainText[] , SecByteBlock key, byte *iv ) {
    int messageLen = (int)strlen(plainText) + 1;
    //////////////////////////////////////////////////////////////////////////
    // Encrypt
    CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
    cfbEncryption.ProcessData((byte*)plainText, (byte*)plainText, messageLen);
}



void decrypt_aes(char plainText[] , SecByteBlock key, byte *iv ) {
    int messageLen = (int)strlen(plainText) + 1;
    //////////////////////////////////////////////////////////////////////////
    // Decrypt
    
    CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
    cfbDecryption.ProcessData((byte*)plainText, (byte*)plainText, messageLen);

}


void generate_aes_key(){
    AutoSeededRandomPool rnd;
    
    // Generate a random key
    SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
    rnd.GenerateBlock( key, key.size() );
    
    // Generate a random IV
    byte iv[AES::BLOCKSIZE];
    rnd.GenerateBlock(iv, AES::BLOCKSIZE);
    
    char plainText[] = "Hello! How are you.";
    cout << "m: " << plainText << endl;
    
    //enc
    encrypt_aes(plainText , key, iv);
    cout << "c: " << plainText << endl;
    
    //dec
    decrypt_aes(plainText , key , iv);
    cout << "d: " << plainText << endl;
    
}





int main() {
    
    create_key();
    generate_aes_key();
    return 0;
}
