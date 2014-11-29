//
//  main.cpp
//  crypto_test
//
//  Created by Ahmed Shabbir on 11/28/14.
//  Copyright (c) 2014 NYU. All rights reserved.
//



#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "aes.h"
using CryptoPP::AES;

#include "gcm.h"
using CryptoPP::GCM;

#include "secblock.h"
using CryptoPP::SecByteBlock;



#include "rsa.h"
#include "files.h"
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





/***************
 **************/
//int book_example(int argc, char* argv[])
int book_example()
{
    AutoSeededRandomPool prng;
    string plain = "GCM Mode Test";
    string cipher, encoded, recovered;
    
    //generate key
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    
    // Pretty print key
    encoded.clear();
    StringSource(key, key.size(), true,
                 new HexEncoder(
                                new StringSink(encoded)
                                ) // HexEncoder
                 ); // StringSource
    cout << "key: " << encoded << endl;
    
    
    //generate iv
    SecByteBlock iv(AES::BLOCKSIZE);
    prng.GenerateBlock(iv, iv.size());
    
    // Pretty print iv
    encoded.clear();
    StringSource(iv, iv.size(), true,
                 new HexEncoder(
                                new StringSink(encoded)
                                ) // HexEncoder
                 ); // StringSource
    cout << "iv: " << encoded << endl;
    
    
    
    /*********************************\
     \*********************************/
    
    
    
    try
    {
        cout << "plain text: " << plain << endl;
        
        GCM< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv, iv.size());
        
        // The StreamTransformationFilter adds padding
        //  as required. GCM and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new AuthenticatedEncryptionFilter(e,
                                                       new StringSink(cipher)
                                                       ) // StreamTransformationFilter
                     ); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    
    /*********************************\
     \*********************************/
    
    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                                new StringSink(encoded)
                                ) // HexEncoder
                 ); // StringSource
    cout << "cipher text: " << encoded << endl;
    
    /*********************************\
     \*********************************/
    
    try
    {
        GCM< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv, iv.size());
        
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true, 
                       new AuthenticatedDecryptionFilter(d,
                                                         new StringSink(recovered)
                                                         ) // StreamTransformationFilter
                       ); // StringSource
        
        cout << "recovered text: " << recovered << endl;
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    
    /*********************************\
     \*********************************/
    
    return 0;
}




int main() {
    
    cout << "BEGINING Creating PUBLIC AND PRIVATE KEY" << endl;
    create_key();
    
    
    cout << "BEGINING Simple AES Encyption " << endl;
    generate_aes_key();
    
    
    cout << "BEGINING FINAL EXAMPLE" << endl;
    
    book_example();
    
    return 0;
}
