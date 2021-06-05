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

    int numberofReceivers =  2;
    std::cout << numberofReceivers << " Receivers" << endl;

    int numberofDataOwners = 3;
    std::cout << numberofDataOwners << " Data Owners" << endl;

    /////////////////////////////////////////////////////////////
    ////    [K1D, K1A, R1, R2]     ////
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
    static const int32_t Bgbit = 8;        // Base bit gadget
    static const int32_t dg = 4;           // dimension gadget
    static const double stdevBK = bk_stdev; // 3.29e-10;       // BK standard deviation
    static const int32_t parties = 2;      // number of parties    

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
    MKLweKey* MKlwekey[numberofDataOwners];
    for(int i=0; i < numberofDataOwners; i ++){
        MKlwekey[i] = new_MKLweKey(LWEparams, MKparams);
        MKLweKeyGen(MKlwekey[i]);
    }      
    
    //cout << "KeyGen MKlwekey: DONE!" << endl;

    // RLWE key 
    MKRLweKey* MKrlwekey = new_MKRLweKey(RLWEparams, MKparams);
    MKRLweKeyGen(MKrlwekey);
    //cout << "KeyGen MKrlwekey: DONE!" << endl;

    // LWE key extracted 
    MKLweKey* MKextractedlwekey = new_MKLweKey(extractedLWEparams, MKparams);
    MKtLweExtractKey(MKextractedlwekey, MKrlwekey);
    //cout << "KeyGen MKextractedlwekey: DONE!" << endl;

    // bootstrapping + key switching keys
    MKLweBootstrappingKey_v2* MKlweBK[numberofDataOwners];
    // bootstrapping FFT + key switching keys
    for(int i=0; i< numberofDataOwners; i++){
        MKlweBK[i] = new_MKLweBootstrappingKey_v2(LWEparams, RLWEparams, MKparams);
        MKlweCreateBootstrappingKey_v2(MKlweBK[i], MKlwekey[i], MKrlwekey, MKextractedlwekey, 
                                    extractedLWEparams, LWEparams, RLWEparams, MKparams);
    }
    //cout << "KeyGen MKlweBK: DONE!" << endl;
    //cout << "KeyGen MKlweBK_FFT: DONE!" << endl;   

    clock_t end_KG = clock();
    double time_KG = ((double) end_KG - begin_KG)/CLOCKS_PER_SEC;
    cout << "Finished KEY GENERATION" << endl;
    cout << "Time per DOs (seconds)... " << time_KG << endl;

    /*============================================================================*/


    ///////////////////////////////////////////////////////////
    //////                  [D, A, R1, R2]               //////
    ///////////////////////////////////////////////////////////

    // generate params 
    static const int32_t Bgbit4 = 8;        // Base bit gadget
    static const int32_t dg4 = 4;           // dimension gadget
    static const int32_t parties4 = 4;      // number of parties    

    // new parameters 
    // 4 parties, B=2^8, d=4 -> works

    // params
    MKTFHEParams *MKparams4 = new_MKTFHEParams(n, n_extract, hLWE, stdevLWE, Bksbit, dks, stdevKS, N, 
                            hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit4, dg4, stdevBK, parties4);


    cout << "Params: DONE!" << endl;

   
    // Key generation 
    cout << "Starting KEY GENERATION" << endl;
    clock_t begin_KG4 = clock();

    // LWE key        
    MKLweKey* MKlwekey4 = new_MKLweKey(LWEparams, MKparams4);
    MKLweKeyGen(MKlwekey4);
    cout << "KeyGen MKlwekey: DONE!" << endl;

    // RLWE key 
    MKRLweKey* MKrlwekey4 = new_MKRLweKey(RLWEparams, MKparams4);
    MKRLweKeyGen(MKrlwekey4);
    cout << "KeyGen MKrlwekey: DONE!" << endl;

    // LWE key extracted 
    MKLweKey* MKextractedlwekey4 = new_MKLweKey(extractedLWEparams, MKparams4);
    MKtLweExtractKey(MKextractedlwekey4, MKrlwekey4);
    cout << "KeyGen MKextractedlwekey: DONE!" << endl;

    // bootstrapping + key switching keys
    MKLweBootstrappingKey_v2* MKlweBK4 = new_MKLweBootstrappingKey_v2(LWEparams, RLWEparams, MKparams4);
    MKlweCreateBootstrappingKey_v2(MKlweBK4, MKlwekey4, MKrlwekey4, MKextractedlwekey4, 
                                extractedLWEparams, LWEparams, RLWEparams, MKparams4);
    cout << "KeyGen MKlweBK: DONE!" << endl;

    // bootstrapping FFT + key switching keys
    MKLweBootstrappingKeyFFT_v2* MKlweBK_FFT4 = new_MKLweBootstrappingKeyFFT_v2(MKlweBK4, LWEparams, RLWEparams, MKparams4);
    MKlweBK_FFT4 = MKlweBK_FFT4 ;
    cout << "KeyGen MKlweBK_FFT: DONE!" << endl;   

    clock_t end_KG4 = clock();
    double time_KG4 = ((double) end_KG4 - begin_KG4)/CLOCKS_PER_SEC;
    time_KG4 = time_KG4;
    cout << "Finished KEY GENERATION" << endl;
    cout << "Time per Agg-Dec-Rec Key (seconds)... " << time_KG4 << endl;


    /*============================================================================*/

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


    int Modulus = 41; //32771>2^15 // Modulus should be a prime number

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
            dataEnc1[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams4);
            dataEnc2[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams4);
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&dataEnc1[i][j][k], 0, (data1[i][j]>>k)&1, &MKlwekey[i]->key[0]);
                MKlweNthPartyEncrypt(&dataEnc2[i][j][k], 0, (data2[i][j]>>k)&1, &MKlwekey[i]->key[0]);
            }

            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&dataEnc1[i][j][k], 1, (data1[i][j]>>k)&1, &MKlwekey[i]->key[1]);
                MKlweNthPartyEncrypt(&dataEnc2[i][j][k], 1, (data2[i][j]>>k)&1, &MKlwekey[i]->key[1]);
            }

            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&dataEnc1[i][j][k], 2 + j, (data1[i][j]>>k)&1, &MKlwekey4->key[2 + j]);
                MKlweNthPartyEncrypt(&dataEnc2[i][j][k], 2 + j, (data2[i][j]>>k)&1, &MKlwekey4->key[2 + j]);
            }


            // generating alpha
            alpha[i][j] = dist(rd) % Modulus;
            std::cout << "alpha: " << alpha[i][j] << endl;
            if(alpha[i][j] != 0){
                alpha1[i][j] = dist(rd) % alpha[i][j];
            }else{
                alpha1[i][j] = 0;
            }
            std::cout << "random share 1 of alpha: " << alpha1[i][j] << endl;
            alpha2[i][j] = alpha[i][j] - alpha1[i][j];
            std::cout << "random share 2 of alpha: " << alpha2[i][j] << endl;

            // alpha          -------> ENCRYPTED
            alphaEnc1[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams4);
            alphaEnc2[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams4);
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&alphaEnc1[i][j][k], 0, (alpha1[i][j]>>k)&1, &MKlwekey[i]->key[0]);
                MKlweNthPartyEncrypt(&alphaEnc2[i][j][k], 0, (alpha2[i][j]>>k)&1, &MKlwekey[i]->key[0]);
            }
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&alphaEnc1[i][j][k], 1, (alpha1[i][j]>>k)&1, &MKlwekey[i]->key[1]);
                MKlweNthPartyEncrypt(&alphaEnc2[i][j][k], 1, (alpha2[i][j]>>k)&1, &MKlwekey[i]->key[1]);
            }
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&alphaEnc1[i][j][k], 2 + j, (alpha1[i][j]>>k)&1, &MKlwekey4->key[2 + j]);
                MKlweNthPartyEncrypt(&alphaEnc2[i][j][k], 2 + j, (alpha2[i][j]>>k)&1, &MKlwekey4->key[2 + j]);
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
            gammaEnc1[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams4);
            gammaEnc2[i][j] = new_MKLweSample_array(nb_bits, LWEparams, MKparams4);
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&gammaEnc1[i][j][k], 0, (gamma1[i][j]>>i)&1, &MKlwekey[i]->key[0]);
                MKlweNthPartyEncrypt(&gammaEnc2[i][j][k], 0, (gamma2[i][j]>>i)&1, &MKlwekey[i]->key[0]);
            }
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&gammaEnc1[i][j][k], 1, (gamma1[i][j]>>i)&1, &MKlwekey[i]->key[1]);
                MKlweNthPartyEncrypt(&gammaEnc2[i][j][k], 1, (gamma2[i][j]>>i)&1, &MKlwekey[i]->key[1]);
            }
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&gammaEnc1[i][j][k], 2 + j, (gamma1[i][j]>>k)&1, &MKlwekey4->key[2 + j]);
                MKlweNthPartyEncrypt(&gammaEnc2[i][j][k], 2 + j, (gamma2[i][j]>>k)&1, &MKlwekey4->key[2 + j]);
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
                MKlweNthPartyUnmask(&dataEnc1[i][j][k], 0, (data1[i][j]>>k)&1, &MKlwekey[i]->key[0]);
                MKlweNthPartyUnmask(&dataEnc2[i][j][k], 0, (data2[i][j]>>k)&1, &MKlwekey[i]->key[0]);

                MKlweNthPartyUnmask(&alphaEnc1[i][j][k], 0, (alpha1[i][j]>>k)&1, &MKlwekey[i]->key[0]);
                MKlweNthPartyUnmask(&alphaEnc2[i][j][k], 0, (alpha2[i][j]>>k)&1, &MKlwekey[i]->key[0]);

                MKlweNthPartyUnmask(&gammaEnc1[i][j][k], 0, (gamma1[i][j]>>i)&1, &MKlwekey[i]->key[0]);
                MKlweNthPartyUnmask(&gammaEnc2[i][j][k], 0, (gamma2[i][j]>>i)&1, &MKlwekey[i]->key[0]);
            }
            ////////////////
	        //by Agg: removal of keys
	        ////////////////  
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyUnmask(&dataEnc1[i][j][k], 1, (data1[i][j]>>k)&1, &MKlwekey[i]->key[1]);
                MKlweNthPartyUnmask(&dataEnc2[i][j][k], 1, (data2[i][j]>>k)&1, &MKlwekey[i]->key[1]);

                MKlweNthPartyUnmask(&alphaEnc1[i][j][k], 1, (alpha1[i][j]>>k)&1, &MKlwekey[i]->key[1]);
                MKlweNthPartyUnmask(&alphaEnc2[i][j][k], 1, (alpha2[i][j]>>k)&1, &MKlwekey[i]->key[1]);

                MKlweNthPartyUnmask(&gammaEnc1[i][j][k], 1, (gamma1[i][j]>>i)&1, &MKlwekey[i]->key[1]);
                MKlweNthPartyUnmask(&gammaEnc2[i][j][k], 1, (gamma2[i][j]>>i)&1, &MKlwekey[i]->key[1]);
            }
            ////////////////
	        //by Dec: masking of keys
	        //////////////// 
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&dataEnc1[i][j][k], 0, (data1[i][j]>>k)&1, &MKlwekey4->key[0]);
                MKlweNthPartyEncrypt(&dataEnc2[i][j][k], 0, (data2[i][j]>>k)&1, &MKlwekey4->key[0]);

                MKlweNthPartyEncrypt(&alphaEnc1[i][j][k], 0, (alpha1[i][j]>>k)&1, &MKlwekey4->key[0]);
                MKlweNthPartyEncrypt(&alphaEnc2[i][j][k], 0, (alpha2[i][j]>>k)&1, &MKlwekey4->key[0]);

                MKlweNthPartyEncrypt(&gammaEnc1[i][j][k], 0, (gamma1[i][j]>>i)&1, &MKlwekey4->key[0]);
                MKlweNthPartyEncrypt(&gammaEnc2[i][j][k], 0, (gamma2[i][j]>>i)&1, &MKlwekey4->key[0]);
            } 
            ////////////////
	        //by Agg: masking of keys
	        //////////////// 
            for(int k=0; k< nb_bits; k++){
                MKlweNthPartyEncrypt(&dataEnc1[i][j][k], 1, (data1[i][j]>>k)&1, &MKlwekey4->key[1]);
                MKlweNthPartyEncrypt(&dataEnc2[i][j][k], 1, (data2[i][j]>>k)&1, &MKlwekey4->key[1]);

                MKlweNthPartyEncrypt(&alphaEnc1[i][j][k], 1, (alpha1[i][j]>>k)&1, &MKlwekey4->key[1]);
                MKlweNthPartyEncrypt(&alphaEnc2[i][j][k], 1, (alpha2[i][j]>>k)&1, &MKlwekey4->key[1]);

                MKlweNthPartyEncrypt(&gammaEnc1[i][j][k], 1, (gamma1[i][j]>>i)&1, &MKlwekey4->key[1]);
                MKlweNthPartyEncrypt(&gammaEnc2[i][j][k], 1, (gamma2[i][j]>>i)&1, &MKlwekey4->key[1]);
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

            epsilon[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
            epsilon1[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
            epsilon2[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);

            if (dataAggforAuthorisedRj[j]==1){
                ////////////////
                //by Agg
                //////////////// 
                //epsilon1[i][j]= data1[i][j] + alpha1[i][j]; 
                full_adder(epsilon1[i][j], dataEnc1[i][j], alphaEnc1[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                delta1[i][j] = choice_vector1[i][j] + beta1[i][j];

                ////////////////
                // by Dec
                ////////////////
                //epsilon2[i][j]= data2[i][j] + alpha2[i][j];
                full_adder(epsilon2[i][j], dataEnc2[i][j], alphaEnc2[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                delta2[i][j] = choice_vector2[i][j] + beta2[i][j];

                ////////////////
                // both
                ////////////////
                //epsilon[i][j] = epsilon1[i][j] + epsilon2[i][j];
                full_adder(epsilon[i][j], epsilon1[i][j], epsilon2[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                //ENCRYPT EPSILON
                delta[i][j] = delta1[i][j] + delta2[i][j]; 
                delta[i][j] = delta[i][j];


                epsilonMulchoice_vector1[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
                epsilonMulchoice_vector2[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
                deltaMuldata1[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
                deltaMuldata2[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
                epsMulcvPlusDeltaMulData1[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
                epsMulcvPlusDeltaMulData2[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
                epsMulDelta[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
                partialAdd[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
                partialAdd1[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
                partialAdd2[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
                result[i][j] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);


                // ////////////////
                // //by Agg
                // //////////////// 
                // partialAdd1[i][j] = gamma1[i][j] + epsilon[i][j]*choice_vector1[i][j]+delta[i][j]*data1[i][j];
                epsilonMulchoice_vector1[i][j] = mulTimesPlain_v2(epsilon[i][j], choice_vector1[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                deltaMuldata1[i][j] = mulTimesPlain_v2(dataEnc1[i][j], delta[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                full_adder(epsMulcvPlusDeltaMulData1[i][j], epsilonMulchoice_vector1[i][j], deltaMuldata1[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                full_adder(partialAdd1[i][j], epsMulcvPlusDeltaMulData1[i][j], gammaEnc1[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);


                // ////////////////
                // // by Dec
                // ////////////////
                // partialAdd2[i][j] = gamma2[i][j] + epsilon[i][j]*choice_vector2[i][j]+delta[i][j]*data2[i][j];
                epsilonMulchoice_vector2[i][j] = mulTimesPlain_v2(epsilon[i][j], choice_vector2[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                deltaMuldata2[i][j] = mulTimesPlain_v2(dataEnc2[i][j], delta[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                full_adder(epsMulcvPlusDeltaMulData2[i][j], epsilonMulchoice_vector2[i][j], deltaMuldata2[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                full_adder(partialAdd2[i][j], epsMulcvPlusDeltaMulData2[i][j], gammaEnc2[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);


                clock_t start_Dec_only = clock();

                // ////////////////
                // // by Dec
                // ////////////////
                // partialAdd[i][j] = partialAdd1[i][j] + partialAdd2[i][j];
                full_adder(partialAdd[i][j], partialAdd1[i][j], partialAdd2[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                // result[i][j] = partialAdd[i][j] - epsilon[i][j]*delta[i][j];
                full_subtracter(result[i][j], partialAdd[i][j], epsMulDelta[i][j], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                
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

        AggforRj[i] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);
        for(int k = 0; k < nb_bits + 1; k ++){
            MKbootsCONSTANT_FFT_v2m2(&AggforRj[i][k], 0, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
        }
        temp[i] = new_MKLweSample_array(nb_bits + 1, LWEparams, MKparams4);


        if (dataAggforAuthorisedRj[i]==1){
            for (int j = 0; j < numberofDataOwners; ++j){
                //////// AggforRj[i] += result[j][i];
                full_adder(temp[i], AggforRj[i], result[j][i], nb_bits, MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
                for(int k = 0; k < nb_bits; k ++){
                    MKbootsCOPY_FFT_v2m2(&AggforRj[i][k], &temp[i][k], MKlweBK_FFT4, LWEparams, extractedLWEparams, RLWEparams, MKparams, MKrlwekey);
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
            MKlweNthPartyUnmask(&AggforRj[i][k], 0, 0, &MKlwekey4->key[0]);
        }
        ////////////////
        //by Agg: removal of keys
        ////////////////  
        for(int k=0; k< nb_bits; k++){            
            MKlweNthPartyUnmask(&AggforRj[i][k], 1, 0, &MKlwekey4->key[1]);
        }

        clock_t start_Rec = clock();

		if (dataAggforAuthorisedRj[i]==1){
            for(int k=0; k< nb_bits; k++){            
                AggforRjDec[i] = MKlweLastPartyDecrypt(&AggforRj[i][k], 2+i, &MKlwekey4->key[2+i], nb_bits);
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

   

   /*  // delete keys
    delete_MKLweKey(MKextractedlwekey);
    delete_MKRLweKey(MKrlwekey);

    // delete params
    delete_MKTFHEParams(MKparams);
    delete_TLweParams(RLWEparams);
    delete_LweParams(LWEparams);
    delete_LweParams(extractedLWEparams); */


    return 0;
}
