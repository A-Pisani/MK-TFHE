#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <sys/time.h>
#include "tfhe.h"
#include "polynomials.h"
#include "lwesamples.h"
#include "lwekey.h"
#include "lweparams.h"
#include "tlwe.h"
#include "tgsw.h"



#include "mkTFHEparams.h"
#include "mkTFHEkeys.h"
#include "mkTFHEkeygen.h"
#include "mkTFHEsamples.h"
#include "mkTFHEfunctions.h"



 

using namespace std;



// **********************************************************************************
// ********************************* MAIN *******************************************
// **********************************************************************************


void dieDramatically(string message) {
    cerr << message << endl;
    abort();
} 


int32_t main(int32_t argc, char **argv) {

    /////////////////////////////////////////////////////////////
    ////    [K1D, K1A, K2D, K2A, K3D, K3A, D, A, R1, R2]     ////
    /////////////////////////////////////////////////////////////

    // generate params 
    static const int32_t k = 1;
    static const double ks_stdev = 3.05e-5;// 2.44e-5; //standard deviation
    static const double bk_stdev = 3.72e-9; // 3.29e-10; //standard deviation
    static const double max_stdev = 0.012467; //max standard deviation for a 1/4 msg space
    static const int32_t n = 560; //500;            // LWE modulus
    static const int32_t n_extract = 1024;    // LWE extract modulus (used in bootstrapping)
    static const int32_t hLWE = 0;         // HW secret key LWE --> not used
    static const double stdevLWE = 0.012467;      // LWE ciphertexts standard deviation
    static const int32_t Bksbit = 2;       // Base bit key switching
    static const int32_t dks = 8;          // dimension key switching
    static const double stdevKS = ks_stdev; // 2.44e-5;       // KS key standard deviation
    static const int32_t N = 1024;            // RLWE,RGSW modulus
    static const int32_t hRLWE = 0;        // HW secret key RLWE,RGSW --> not used
    static const double stdevRLWEkey = bk_stdev; // 3.29e-10; // 0; // 0.012467;  // RLWE key standard deviation
    static const double stdevRLWE = bk_stdev; // 3.29e-10; // 0; // 0.012467;     // RLWE ciphertexts standard deviation
    static const double stdevRGSW = bk_stdev; // 3.29e-10;     // RGSW ciphertexts standard deviation 
    static const int32_t Bgbit = 6;        // Base bit gadget
    static const int32_t dg = 5;           // dimension gadget
    static const double stdevBK = bk_stdev; // 3.29e-10;       // BK standard deviation
    static const int32_t parties = 10;      // number of parties    

    // 8 parties, B=2^6, d=5 -> works 

    // params
    LweParams *extractedLWEparams = new_LweParams(n_extract, ks_stdev, max_stdev);
    LweParams *LWEparams = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *RLWEparams = new_TLweParams(N, k, bk_stdev, max_stdev);
    MKTFHEParams *MKparams = new_MKTFHEParams(n, n_extract, hLWE, stdevLWE, Bksbit, dks, stdevKS, N, 
                            hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit, dg, stdevBK, parties);


    cout << "Params: DONE!" << endl;

   
    // Key generation 
    cout << "Starting KEY GENERATION" << endl;
    clock_t begin_KG = clock();

    // LWE key        
    MKLweKey* MKlwekey = new_MKLweKey(LWEparams, MKparams);
    MKLweKeyGen(MKlwekey);
    cout << "KeyGen MKlwekey: DONE!" << endl;

    // RLWE key 
    MKRLweKey* MKrlwekey = new_MKRLweKey(RLWEparams, MKparams);
    MKRLweKeyGen(MKrlwekey);
    cout << "KeyGen MKrlwekey: DONE!" << endl;

    // LWE key extracted 
    MKLweKey* MKextractedlwekey = new_MKLweKey(extractedLWEparams, MKparams);
    MKtLweExtractKey(MKextractedlwekey, MKrlwekey);
    cout << "KeyGen MKextractedlwekey: DONE!" << endl;

    // bootstrapping + key switching keys
    MKLweBootstrappingKey_v2* MKlweBK = new_MKLweBootstrappingKey_v2(LWEparams, RLWEparams, MKparams);
    MKlweCreateBootstrappingKey_v2(MKlweBK, MKlwekey, MKrlwekey, MKextractedlwekey, 
                                extractedLWEparams, LWEparams, RLWEparams, MKparams);
    cout << "KeyGen MKlweBK: DONE!" << endl;

    // bootstrapping FFT + key switching keys
    MKLweBootstrappingKeyFFT_v2* MKlweBK_FFT = new_MKLweBootstrappingKeyFFT_v2(MKlweBK, LWEparams, RLWEparams, MKparams);
    cout << "KeyGen MKlweBK_FFT: DONE!" << endl;   

    clock_t end_KG = clock();
    double time_KG = ((double) end_KG - begin_KG)/CLOCKS_PER_SEC;
    cout << "Finished KEY GENERATION" << endl;


    
    /*============================================================================*/

    /* 
    ///////////////////////////////////////////////////////////
    //////              [R1, 0, Dec, Agg]               //////
    ///////////////////////////////////////////////////////////

    // generate params 
    static const int32_t Bgbit2 = 8;        // Base bit gadget
    static const int32_t dg2 = 4;           // dimension gadget
    static const int32_t parties2 = 4;      // number of parties    

    // new parameters 
    // 4 parties, B=2^8, d=4 -> works

    // params
    LweParams *extractedLWEparams2 = new_LweParams(n_extract, ks_stdev, max_stdev);
    LweParams *LWEparams2 = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *RLWEparams2 = new_TLweParams(N, k, bk_stdev, max_stdev);
    MKTFHEParams *MKparams2 = new_MKTFHEParams(n, n_extract, hLWE, stdevLWE, Bksbit, dks, stdevKS, N, 
                            hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit2, dg2, stdevBK, parties2);


    cout << "Params: DONE!" << endl;

   
    // Key generation 
    cout << "Starting KEY GENERATION" << endl;
    clock_t begin_KG2 = clock();

    // LWE key        
    MKLweKey* MKlwekey2 = new_MKLweKey(LWEparams2, MKparams2);
    MKLweKeyGen(MKlwekey2);
    cout << "KeyGen MKlwekey: DONE!" << endl;

    // RLWE key 
    MKRLweKey* MKrlwekey2 = new_MKRLweKey(RLWEparams2, MKparams2);
    MKRLweKeyGen(MKrlwekey2);
    cout << "KeyGen MKrlwekey: DONE!" << endl;

    // LWE key extracted 
    MKLweKey* MKextractedlwekey2 = new_MKLweKey(extractedLWEparams2, MKparams2);
    MKtLweExtractKey(MKextractedlwekey2, MKrlwekey2);
    cout << "KeyGen MKextractedlwekey: DONE!" << endl;

    // bootstrapping + key switching keys
    MKLweBootstrappingKey_v2* MKlweBK2 = new_MKLweBootstrappingKey_v2(LWEparams2, RLWEparams2, MKparams2);
    MKlweCreateBootstrappingKey_v2(MKlweBK2, MKlwekey2, MKrlwekey2, MKextractedlwekey2, 
                                extractedLWEparams2, LWEparams2, RLWEparams2, MKparams2);
    cout << "KeyGen MKlweBK: DONE!" << endl;

    // bootstrapping FFT + key switching keys
    MKLweBootstrappingKeyFFT_v2* MKlweBK_FFT2 = new_MKLweBootstrappingKeyFFT_v2(MKlweBK2, LWEparams2, RLWEparams2, MKparams2);
    MKlweBK_FFT2 = MKlweBK_FFT2;
    cout << "KeyGen MKlweBK_FFT: DONE!" << endl;   

    clock_t end_KG2 = clock();
    double time_KG2 = ((double) end_KG2 - begin_KG2)/CLOCKS_PER_SEC;
    time_KG2 = time_KG2;
    cout << "Finished KEY GENERATION" << endl;
 */
    /*============================================================================*/

    /*============================================================================*/

/*
    ///////////////////////////////////////////////////////////
    //////              [0, R2, Dec, Agg]               //////
    ///////////////////////////////////////////////////////////

    // generate params 
    static const int32_t Bgbit3 = 8;        // Base bit gadget
    static const int32_t dg3 = 4;           // dimension gadget
    static const int32_t parties3 = 4;      // number of parties    

    // new parameters 
    // 4 parties, B=2^8, d=4 -> works

    // params
    LweParams *extractedLWEparams3 = new_LweParams(n_extract, ks_stdev, max_stdev);
    LweParams *LWEparams3 = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *RLWEparams3 = new_TLweParams(N, k, bk_stdev, max_stdev);
    MKTFHEParams *MKparams3 = new_MKTFHEParams(n, n_extract, hLWE, stdevLWE, Bksbit, dks, stdevKS, N, 
                            hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit3, dg3, stdevBK, parties3);


    cout << "Params: DONE!" << endl;

   
    // Key generation 
    cout << "Starting KEY GENERATION" << endl;
    clock_t begin_KG3 = clock();

    // LWE key        
    MKLweKey* MKlwekey3 = new_MKLweKey(LWEparams3, MKparams3);
    MKLweKeyGen(MKlwekey3);
    cout << "KeyGen MKlwekey: DONE!" << endl;

    // RLWE key 
    MKRLweKey* MKrlwekey3 = new_MKRLweKey(RLWEparams3, MKparams3);
    MKRLweKeyGen(MKrlwekey3);
    cout << "KeyGen MKrlwekey: DONE!" << endl;

    // LWE key extracted 
    MKLweKey* MKextractedlwekey3 = new_MKLweKey(extractedLWEparams3, MKparams3);
    MKtLweExtractKey(MKextractedlwekey3, MKrlwekey3);
    cout << "KeyGen MKextractedlwekey: DONE!" << endl;

    // bootstrapping + key switching keys
    MKLweBootstrappingKey_v2* MKlweBK3 = new_MKLweBootstrappingKey_v2(LWEparams3, RLWEparams3, MKparams3);
    MKlweCreateBootstrappingKey_v2(MKlweBK3, MKlwekey3, MKrlwekey3, MKextractedlwekey3, 
                                extractedLWEparams3, LWEparams3, RLWEparams3, MKparams3);
    cout << "KeyGen MKlweBK: DONE!" << endl;

    // bootstrapping FFT + key switching keys
    MKLweBootstrappingKeyFFT_v2* MKlweBK_FFT3 = new_MKLweBootstrappingKeyFFT_v2(MKlweBK3, LWEparams3, RLWEparams3, MKparams3);
    MKlweBK_FFT3 = MKlweBK_FFT3 ;
    cout << "KeyGen MKlweBK_FFT: DONE!" << endl;   

    clock_t end_KG3 = clock();
    double time_KG3 = ((double) end_KG3 - begin_KG3)/CLOCKS_PER_SEC;
    time_KG3 = time_KG3;
    cout << "Finished KEY GENERATION" << endl;

    */

    /*============================================================================*/

    int numberofReceivers =  2;
    std::cout << numberofReceivers << " Receivers" << endl;

    int numberofDataOwners = 3;
    std::cout << numberofDataOwners << " Data Owners" << endl;


    std::cout << "Data Preparation for the Beaver triplets Started" << endl;

    int16_t nb_bits = 16;
    // choice vector
    int choice_vector[numberofDataOwners][numberofReceivers]; 
    int choice_vector1[numberofDataOwners][numberofReceivers]; 
    int choice_vector2[numberofDataOwners][numberofReceivers]; 
    
    // sensitive data
    int data[numberofDataOwners][numberofReceivers]; 
    int data1[numberofDataOwners][numberofReceivers]; 
    int data2[numberofDataOwners][numberofReceivers];  

    // sensitive data ciphertext
    MKLweSample *dataEnc1[numberofDataOwners][numberofReceivers];
    MKLweSample *dataEnc2[numberofDataOwners][numberofReceivers];

    // random data for Beaver's triplets
    int alpha[numberofDataOwners][numberofReceivers]; 
    int alpha1[numberofDataOwners][numberofReceivers]; 
    int alpha2[numberofDataOwners][numberofReceivers];

    // alpha ciphertext
    MKLweSample *alphaEnc1[numberofDataOwners][numberofReceivers];
    MKLweSample *alphaEnc2[numberofDataOwners][numberofReceivers];

    int beta[numberofDataOwners][numberofReceivers]; 
    int beta1[numberofDataOwners][numberofReceivers]; 
    int beta2[numberofDataOwners][numberofReceivers];

    int gamma[numberofDataOwners][numberofReceivers]; 
    int gamma1[numberofDataOwners][numberofReceivers]; 
    int gamma2[numberofDataOwners][numberofReceivers];

    // gamma ciphertext
    MKLweSample *gammaEnc1[numberofDataOwners][numberofReceivers];
    MKLweSample *gammaEnc2[numberofDataOwners][numberofReceivers];

    MKLweSample *epsilon[numberofDataOwners][numberofReceivers]; 
    MKLweSample *epsilon1[numberofDataOwners][numberofReceivers]; 
    MKLweSample *epsilon2[numberofDataOwners][numberofReceivers]; 

    int delta[numberofDataOwners][numberofReceivers]; 
    int delta1[numberofDataOwners][numberofReceivers]; 
    int delta2[numberofDataOwners][numberofReceivers]; 

    MKLweSample *epsilonMulchoice_vector1[numberofDataOwners][numberofReceivers]; 
    MKLweSample *epsilonMulchoice_vector2[numberofDataOwners][numberofReceivers];
    MKLweSample *deltaMuldata1[numberofDataOwners][numberofReceivers]; 
    MKLweSample *deltaMuldata2[numberofDataOwners][numberofReceivers];

    MKLweSample *epsMulcvPlusDeltaMulData1[numberofDataOwners][numberofReceivers];
    MKLweSample *epsMulcvPlusDeltaMulData2[numberofDataOwners][numberofReceivers];
    MKLweSample *epsMulDelta[numberofDataOwners][numberofReceivers];

    MKLweSample *partialAdd[numberofDataOwners][numberofReceivers]; 
    MKLweSample *partialAdd1[numberofDataOwners][numberofReceivers]; 
    MKLweSample *partialAdd2[numberofDataOwners][numberofReceivers]; 

    MKLweSample *result[numberofDataOwners][numberofReceivers]; 


    int Modulus = 32771; //32771>2^15 // Modulus should be a prime number

    // for random numbers
    std::random_device rd;
    std::uniform_int_distribution<> dist;

    clock_t start_Data_Owners = clock();

    for(int i=0; i<numberofDataOwners; i++){
        for(int j=0; j<numberofReceivers; j++){
            // choosing Receivers for each DO
            choice_vector[i][j] = dist(rd) % 2;
            std::cout << "random number for choice: " << choice_vector[i][j] << endl;

            if(choice_vector[i][j]!= 0)
                choice_vector1[i][j] = dist(rd) % choice_vector[i][j];
            else
                choice_vector1[i][j] = 0;
            std::cout << "random share 1 for choice: " << choice_vector1[i][j] << endl;

            choice_vector2[i][j] = choice_vector[i][j] - choice_vector1[i][j];
            std::cout << "random share 2 for choice: " << choice_vector2[i][j] << endl;

            // data of each DO          -------> TO BE ENCRYPTED
            if(choice_vector[i][j] == 1)
                data[i][j] = 36; 
            else
                data[i][j] = dist(rd) % Modulus;
            
            std::cout << "data: " << i << j << "\t" << data[i][j] << endl;

            if(data[i][j]!= 0)
                data1[i][j] = dist(rd) % data[i][j];
            else
                data1[i][j] = 0;
            std::cout << "random share 1 of data: " << data1[i][j] << endl;

            data2[i][j] = data[i][j] - data1[i][j];
            std::cout << "random share 2 of data: " << data2[i][j] << endl;
            // data of each DO          -------> ENCRYPTED --> layers: DO-Dec, DO-Agg, R
            dataEnc1[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams);
            dataEnc2[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams);
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&dataEnc1[i][j][k], i, (data1[i][j]>>k)&1, &MKlwekey->key[i]);
                MKlweNthPartyEncrypt(&dataEnc2[i][j][k], i, (data2[i][j]>>k)&1, &MKlwekey->key[i]);
            }

            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&dataEnc1[i][j][k], i+1, (data1[i][j]>>k)&1, &MKlwekey->key[i+1]);
                MKlweNthPartyEncrypt(&dataEnc2[i][j][k], i+1, (data2[i][j]>>k)&1, &MKlwekey->key[i+1]);
            }

            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&dataEnc1[i][j][k], 8+j, (data1[i][j]>>k)&1, &MKlwekey->key[8 + j]);
                MKlweNthPartyEncrypt(&dataEnc2[i][j][k], 8+j, (data2[i][j]>>k)&1, &MKlwekey->key[8 + j]);
            }


            // generating alpha
            alpha[i][j] = dist(rd) % Modulus;
            std::cout << "alpha: " << alpha[i][j] << endl;
            if(alpha[i][j] != 0){
                alpha1[i][j] = dist(rd) % alpha[i][j];
            }else{
                alpha1[i][j] = 1;
            }
            std::cout << "random share 1 of alpha: " << alpha1[i][j] << endl;
            alpha2[i][j] = alpha[i][j] - alpha1[i][j];
            std::cout << "random share 2 of alpha: " << alpha2[i][j] << endl;

            // alpha          -------> ENCRYPTED
            alphaEnc1[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams);
            alphaEnc2[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams);
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&alphaEnc1[i][j][k], i, (alpha1[i][j]>>k)&1, &MKlwekey->key[i]);
                MKlweNthPartyEncrypt(&alphaEnc2[i][j][k], i, (alpha2[i][j]>>k)&1, &MKlwekey->key[i]);
            }
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&alphaEnc1[i][j][k], i+1, (alpha1[i][j]>>k)&1, &MKlwekey->key[i+1]);
                MKlweNthPartyEncrypt(&alphaEnc2[i][j][k], i+1, (alpha2[i][j]>>k)&1, &MKlwekey->key[i+1]);
            }
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&alphaEnc1[i][j][k], 8 + j, (alpha1[i][j]>>k)&1, &MKlwekey->key[8 + j]);
                MKlweNthPartyEncrypt(&alphaEnc2[i][j][k], 8 + j, (alpha2[i][j]>>k)&1, &MKlwekey->key[8 + j]);
            }

            // generating beta
            beta[i][j] = dist(rd) % Modulus;
            std::cout << "beta: " << beta[i][j] << endl;
            if(beta[i][j] != 0){
                beta1[i][j] = dist(rd) % beta[i][j];
            }else{
                beta1[i][j] = 0;
            }
            std::cout << "random share 1 of beta: " << beta1[i][j] << endl;
            beta2[i][j] = beta[i][j] - beta1[i][j];
            std::cout << "random share 2 of beta: " << beta2[i][j] << endl;


            //constracting gamma and its shares
            gamma[i][j] = (alpha[i][j]) * (beta[i][j]);
            std::cout << "gamma: " << gamma[i][j] << endl;
            if(gamma[i][j] != 0){
                gamma1[i][j] = dist(rd) % gamma[i][j];
            }else{
                gamma1[i][j] = 0;
            }
            std::cout << "random share 1 of gamma: " << gamma1[i][j] << endl;
            gamma2[i][j] = gamma[i][j] - gamma1[i][j];
            std::cout << "random share 2 of gamma: " << gamma2[i][j] << endl; 
            // gamma          -------> ENCRYPTED
            gammaEnc1[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams);
            gammaEnc2[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams);
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&gammaEnc1[i][j][k], i, (gamma1[i][j]>>i)&1, &MKlwekey->key[i]);
                MKlweNthPartyEncrypt(&gammaEnc2[i][j][k], i, (gamma2[i][j]>>i)&1, &MKlwekey->key[i]);
            }
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&gammaEnc1[i][j][k], i+1, (gamma1[i][j]>>i)&1, &MKlwekey->key[i+1]);
                MKlweNthPartyEncrypt(&gammaEnc2[i][j][k], i+1, (gamma2[i][j]>>i)&1, &MKlwekey->key[i+1]);
            }
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&gammaEnc1[i][j][k], 8 + j, (gamma1[i][j]>>k)&1, &MKlwekey->key[8 + j]);
                MKlweNthPartyEncrypt(&gammaEnc2[i][j][k], 8 + j, (gamma2[i][j]>>k)&1, &MKlwekey->key[8 + j]);
            }
        }
    }

    clock_t end_Data_Owners = clock();
    double time_Data_Owners = ((double) end_Data_Owners - start_Data_Owners)/CLOCKS_PER_SEC;
    cout << "Time per DOs specific (seconds)... " << time_Data_Owners << endl;


    std::cout << "Data Preparation for the Beaver triplets Done" << endl;

    std::cout << "Masking/Unmaskin Preparation starting" << endl;

    clock_t start_Agg_Dec = clock();


    for(int i=0; i<numberofDataOwners; i++){
        for(int j=0; j<numberofReceivers; j++){
            ////////////////
	        //by Dec: removal of keys
	        //////////////// 
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyUnmask(&dataEnc1[i][j][k], i, (data1[i][j]>>k)&1, &MKlwekey->key[i]);
                MKlweNthPartyUnmask(&dataEnc2[i][j][k], i, (data2[i][j]>>k)&1, &MKlwekey->key[i]);

                MKlweNthPartyUnmask(&alphaEnc1[i][j][k], i, (alpha1[i][j]>>k)&1, &MKlwekey->key[i]);
                MKlweNthPartyUnmask(&alphaEnc2[i][j][k], i, (alpha2[i][j]>>k)&1, &MKlwekey->key[i]);

                MKlweNthPartyUnmask(&gammaEnc1[i][j][k], i, (gamma1[i][j]>>i)&1, &MKlwekey->key[i]);
                MKlweNthPartyUnmask(&gammaEnc2[i][j][k], i, (gamma2[i][j]>>i)&1, &MKlwekey->key[i]);
            }
            ////////////////
	        //by Agg: removal of keys
	        ////////////////  
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyUnmask(&dataEnc1[i][j][k], i+1, (data1[i][j]>>k)&1, &MKlwekey->key[i+1]);
                MKlweNthPartyUnmask(&dataEnc2[i][j][k], i+1, (data2[i][j]>>k)&1, &MKlwekey->key[i+1]);

                MKlweNthPartyUnmask(&alphaEnc1[i][j][k], i+1, (alpha1[i][j]>>k)&1, &MKlwekey->key[i+1]);
                MKlweNthPartyUnmask(&alphaEnc2[i][j][k], i+1, (alpha2[i][j]>>k)&1, &MKlwekey->key[i+1]);

                MKlweNthPartyUnmask(&gammaEnc1[i][j][k], i+1, (gamma1[i][j]>>i)&1, &MKlwekey->key[i+1]);
                MKlweNthPartyUnmask(&gammaEnc2[i][j][k], i+1, (gamma2[i][j]>>i)&1, &MKlwekey->key[i+1]);
            }
            ////////////////
	        //by Dec: masking of keys
	        //////////////// 
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&dataEnc1[i][j][k], 6, (data1[i][j]>>k)&1, &MKlwekey->key[6]);
                MKlweNthPartyEncrypt(&dataEnc2[i][j][k], 6, (data2[i][j]>>k)&1, &MKlwekey->key[6]);

                MKlweNthPartyEncrypt(&alphaEnc1[i][j][k], 6, (alpha1[i][j]>>k)&1, &MKlwekey->key[6]);
                MKlweNthPartyEncrypt(&alphaEnc2[i][j][k], 6, (alpha2[i][j]>>k)&1, &MKlwekey->key[6]);

                MKlweNthPartyEncrypt(&gammaEnc1[i][j][k], 6, (gamma1[i][j]>>i)&1, &MKlwekey->key[6]);
                MKlweNthPartyEncrypt(&gammaEnc2[i][j][k], 6, (gamma2[i][j]>>i)&1, &MKlwekey->key[6]);
            } 
            ////////////////
	        //by Agg: masking of keys
	        //////////////// 
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&dataEnc1[i][j][k], 7, (data1[i][j]>>k)&1, &MKlwekey->key[7]);
                MKlweNthPartyEncrypt(&dataEnc2[i][j][k], 7, (data2[i][j]>>k)&1, &MKlwekey->key[7]);

                MKlweNthPartyEncrypt(&alphaEnc1[i][j][k], 7, (alpha1[i][j]>>k)&1, &MKlwekey->key[7]);
                MKlweNthPartyEncrypt(&alphaEnc2[i][j][k], 7, (alpha2[i][j]>>k)&1, &MKlwekey->key[7]);

                MKlweNthPartyEncrypt(&gammaEnc1[i][j][k], 7, (gamma1[i][j]>>i)&1, &MKlwekey->key[7]);
                MKlweNthPartyEncrypt(&gammaEnc2[i][j][k], 7, (gamma2[i][j]>>i)&1, &MKlwekey->key[7]);
            } 

        }
    }    


    std::cout << "Masking/Unmaskin Preparation Done" << endl;

    std::cout << "Learning authorised Receivers Started" << endl;

    int authorisedRj[numberofReceivers];
    int authorisedRj1[numberofReceivers];
    int authorisedRj2[numberofReceivers];


    //  Agg - the addition of shared choice vector1

    for (int j = 0; j < numberofReceivers; ++j){
        for (int i = 0; i < numberofDataOwners; ++i){
            authorisedRj1[j] += choice_vector1[i][j];
        } 
    }


    // Dec - the addition of shared choice vector2  
    
    for (int j = 0; j < numberofReceivers; ++j){
        for (int i = 0; i < numberofDataOwners; ++i){
            authorisedRj2[j] += choice_vector2[i][j];
        } 
    }

    std::cout << "Learning authorised Receivers by Agg and Dec Started" << endl;  


    // Agg and Dec compute the number of DOs for Rj
    for (int j = 0; j < numberofReceivers; ++j){
        authorisedRj[j] = authorisedRj1[j] + authorisedRj2[j];
        authorisedRj[j] = authorisedRj[j] ;
    }

    int t = 2;
    std::cout << "threshold t:"<< "\t" << t << endl;

    int dataAggforAuthorisedRj[numberofReceivers];

    for (int i = 0; i < numberofReceivers; ++i){
        if (authorisedRj[i] >= t){
            dataAggforAuthorisedRj[i] = 1;
            //std:: cout << " Authorised R[" << i <<"] has " << authorisedRj[i] << " votes" << endl;
        }
    }

    
    std::cout << "Learning authorised Receivers Done" << endl;

    std::cout << "Aggregation Started" << endl; 


	for (int i = 0; i < numberofDataOwners; ++i){
	    for (int j = 0; j < numberofReceivers; ++j){

            epsilon[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
            epsilon1[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
            epsilon2[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);

            if (dataAggforAuthorisedRj[j]==1){
                ////////////////
                //by Agg
                //////////////// 
                //epsilon1[i][j]= data1[i][j] + alpha1[i][j]; 
                full_adder(epsilon1[i][j], dataEnc1[i][j], alphaEnc1[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                delta1[i][j] = choice_vector1[i][j] + beta1[i][j];

                ////////////////
                // by Dec
                ////////////////
                //epsilon2[i][j]= data2[i][j] + alpha2[i][j];
                full_adder(epsilon2[i][j], dataEnc2[i][j], alphaEnc2[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                delta2[i][j] = choice_vector2[i][j] + beta2[i][j];

                ////////////////
                // both
                ////////////////
                //epsilon[i][j] = epsilon1[i][j] + epsilon2[i][j];
                full_adder(epsilon[i][j], epsilon1[i][j], epsilon2[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                //ENCRYPT EPSILON
                delta[i][j] = delta1[i][j] + delta2[i][j]; 
                delta[i][j] = delta[i][j];


                epsilonMulchoice_vector1[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
                epsilonMulchoice_vector2[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
                deltaMuldata1[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
                deltaMuldata2[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
                epsMulcvPlusDeltaMulData1[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
                epsMulcvPlusDeltaMulData2[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
                epsMulDelta[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
                partialAdd[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
                partialAdd1[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
                partialAdd2[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
                result[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);


                // ////////////////
                // //by Agg
                // //////////////// 
                // partialAdd1[i][j] = gamma1[i][j] + epsilon[i][j]*choice_vector1[i][j]+delta[i][j]*data1[i][j];
                epsilonMulchoice_vector1[i][j] = mulTimesPlain(epsilon[i][j], choice_vector1[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                deltaMuldata1[i][j] = mulTimesPlain(dataEnc1[i][j], delta[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                full_adder(epsMulcvPlusDeltaMulData1[i][j], epsilonMulchoice_vector1[i][j], deltaMuldata1[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                full_adder(partialAdd1[i][j], epsMulcvPlusDeltaMulData1[i][j], gammaEnc1[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);


                // ////////////////
                // // by Dec
                // ////////////////
                // partialAdd2[i][j] = gamma2[i][j] + epsilon[i][j]*choice_vector2[i][j]+delta[i][j]*data2[i][j];
                epsilonMulchoice_vector2[i][j] = mulTimesPlain(epsilon[i][j], choice_vector2[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                deltaMuldata2[i][j] = mulTimesPlain(dataEnc2[i][j], delta[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                full_adder(epsMulcvPlusDeltaMulData2[i][j], epsilonMulchoice_vector2[i][j], deltaMuldata2[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                full_adder(partialAdd2[i][j], epsMulcvPlusDeltaMulData2[i][j], gammaEnc2[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);


                clock_t start_Dec_only = clock();

                // ////////////////
                // // by Dec
                // ////////////////
                // partialAdd[i][j] = partialAdd1[i][j] + partialAdd2[i][j];
                full_adder(partialAdd[i][j], partialAdd1[i][j], partialAdd2[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                // result[i][j] = partialAdd[i][j] - epsilon[i][j]*delta[i][j];
                full_subtracter(result[i][j], partialAdd[i][j], epsMulDelta[i][j], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                
                clock_t end_Dec_only = clock();
                double time_Dec_only = ((double) end_Dec_only - start_Dec_only)/CLOCKS_PER_SEC;
                cout << "Time per Dec specific (seconds)... " << time_Dec_only << endl;

		    }
		}
	}

    clock_t end_Agg_Dec = clock();
    double time_Agg_Dec = ((double) end_Agg_Dec - start_Agg_Dec)/CLOCKS_PER_SEC;

    cout << "Time per Agg/Dec total (seconds)... " << time_Agg_Dec << endl;

    MKLweSample *AggforRj[numberofReceivers];
    MKLweSample *temp[numberofReceivers];

    clock_t start_Dec_only = clock();

    for (int i = 0; i < numberofReceivers; ++i){

        AggforRj[i] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);
        for(int k = 0; k < nb_bits + 1; k ++){
            MKbootsCONSTANT_FFT_v2m2(&AggforRj[i][k], 0, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
        }
        temp[i] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams);


        if (dataAggforAuthorisedRj[i]==1){
            for (int j = 0; j < numberofDataOwners; ++j){
                //////// AggforRj[i] += result[j][i];
                full_adder(temp[i], AggforRj[i], result[j][i], nb_bits, MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                for(int k = 0; k < nb_bits; k ++){
                    MKbootsCOPY_FFT_v2m2(&AggforRj[i][k], &temp[i][k], MKlweBK_FFT, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                }
                
            }
        }
    }

    clock_t end_Dec_only = clock();
    double time_Dec_only = ((double) end_Dec_only - start_Dec_only)/CLOCKS_PER_SEC;

    cout << "Time per Dec Final Aggregation (seconds)... " << time_Dec_only << endl;


    int AggforRjDec[numberofReceivers];

    clock_t start_Agg_Dec2 = clock();

	for (int i = 0; i < numberofReceivers; ++i){

        ////////////////
        //by Dec: removal of keys
        //////////////// 
        for(int k=0; k< nb_bits; k++){
            MKlweNthPartyUnmask(&AggforRj[i][k], 6, 0, &MKlwekey->key[6]);
        }
        ////////////////
        //by Agg: removal of keys
        ////////////////  
        for(int k=0; k< nb_bits; k++){            
            MKlweNthPartyUnmask(&AggforRj[i][k], 7, 0, &MKlwekey->key[7]);
        }

        clock_t start_Rec = clock();

		if (dataAggforAuthorisedRj[i]==1){
            for(int k=0; k< nb_bits; k++){            
                AggforRjDec[i] = MKlweLastPartyDecrypt(&AggforRj[i][k], 8+i, &MKlwekey->key[8+i], nb_bits);
            }
			std::cout << "Authorised R["<< i <<"] has " << authorisedRj[i] << " votes. Resulting Data Aggregation is:" << "\t" << AggforRjDec[i] % Modulus << endl;
		}
        clock_t end_Rec = clock();
        double time_Rec = ((double) end_Rec - start_Rec)/CLOCKS_PER_SEC;

        cout << "Time per Rec Final Unmasking (seconds)... " << time_Rec << endl;

	}

    clock_t end_Agg_Dec2 = clock();
    double time_Agg_Dec2 = ((double) end_Agg_Dec2 - start_Agg_Dec2)/CLOCKS_PER_SEC;

    cout << "Time per Agg/Dec Final Unmasking (seconds)... " << time_Agg_Dec2 << endl;



    std::cout << "Aggregation Done" << endl; 

   

    // delete keys
    delete_MKLweBootstrappingKeyFFT_v2(MKlweBK_FFT);
    delete_MKLweBootstrappingKey_v2(MKlweBK);
    delete_MKLweKey(MKextractedlwekey);
    delete_MKRLweKey(MKrlwekey);
    delete_MKLweKey(MKlwekey);
    // delete params
    delete_MKTFHEParams(MKparams);
    delete_TLweParams(RLWEparams);
    delete_LweParams(LWEparams);
    delete_LweParams(extractedLWEparams);


    return 0;
}
