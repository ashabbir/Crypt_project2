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

using namespace CryptoPP;

void sample_key() {
    ///////////////////////////////////////
    // Pseudo Random Number Generator
    AutoSeededRandomPool rng;
    
    ///////////////////////////////////////
    // Generate Parameters
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 3072);
    
    ///////////////////////////////////////
    // Generated Parameters
    const Integer& n = params.GetModulus();
    const Integer& p = params.GetPrime1();
    const Integer& q = params.GetPrime2();
    const Integer& d = params.GetPrivateExponent();
    const Integer& e = params.GetPublicExponent();
    
    ///////////////////////////////////////
    // Dump
    cout << "RSA Parameters:" << endl;
    cout << " n: " << n << endl;
    cout << " p: " << p << endl;
    cout << " q: " << q << endl;
    cout << " d: " << d << endl;
    cout << " e: " << e << endl;
    cout << endl;
    
    ///////////////////////////////////////
    // Create Keys
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);
}

int main() {
    
    sample_key();
    return 0;
}