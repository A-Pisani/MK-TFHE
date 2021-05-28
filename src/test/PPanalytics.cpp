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

    // Test trials
    //const int32_t nb_trials = 10;


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
    static const int32_t parties = 8;      // number of parties

    // new parameters 
    // 2 parties, B=2^9, d=3 -> works
    // 4 parties, B=2^8, d=4 -> works
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

    ///////////////////////////////////////////////////////////
    //////       [K1D, K1A, K2D, K2A, K3D, K3A, R1]      //////
    ///////////////////////////////////////////////////////////

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

    // int32_t error_count_EncDec = 0;
    // int32_t error_count_v2m2 = 0;
    // double argv_time_NAND_v2m2 = 0.0;

    int numberofReceivers =  2;
    std::cout << numberofReceivers << " Receivers" << endl;

    int numberofDataOwners = 3;
    std::cout << numberofDataOwners << " Data Owners" << endl;


    std::cout << "Data Preparation for the Beaver triplets Started" << endl;


    // choice vector
    int choice_vector[numberofDataOwners][numberofReceivers]; 
    int choice_vector1[numberofDataOwners][numberofReceivers]; 
    int choice_vector2[numberofDataOwners][numberofReceivers]; 
    
    // sensitive data
    int data[numberofDataOwners][numberofReceivers]; 
    int data1[numberofDataOwners][numberofReceivers]; 
    int data2[numberofDataOwners][numberofReceivers];  

    // random data for Beaver's triplets
    int alpha[numberofDataOwners][numberofReceivers]; 
    int alpha1[numberofDataOwners][numberofReceivers]; 
    int alpha2[numberofDataOwners][numberofReceivers];

    int beta[numberofDataOwners][numberofReceivers]; 
    int beta1[numberofDataOwners][numberofReceivers]; 
    int beta2[numberofDataOwners][numberofReceivers];

    int gamma[numberofDataOwners][numberofReceivers]; 
    int gamma1[numberofDataOwners][numberofReceivers]; 
    int gamma2[numberofDataOwners][numberofReceivers];

    // int epsilon[numberofDataOwners][numberofReceivers]; 
    // int epsilon1[numberofDataOwners][numberofReceivers]; 
    // int epsilon2[numberofDataOwners][numberofReceivers]; 

    // int delta[numberofDataOwners][numberofReceivers]; 
    // int delta1[numberofDataOwners][numberofReceivers]; 
    // int delta2[numberofDataOwners][numberofReceivers]; 

    // int partialAdd[numberofDataOwners][numberofReceivers]; 
    // int partialAdd1[numberofDataOwners][numberofReceivers]; 
    // int partialAdd2[numberofDataOwners][numberofReceivers]; 

    // int result[numberofDataOwners][numberofReceivers]; 


    int Modulus = 41; //41>2^5 // Modulus should be a prime number

    // for random numbers
    std::random_device rd;
    std::uniform_int_distribution<> dist;

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
        data1[i][j] = dist(rd) % data[i][j];
        std::cout << "random share 1 of data: " << data1[i][j] << endl;

        data2[i][j] = data[i][j] - data1[i][j];
        std::cout << "random share 1 of data: " << data2[i][j] << endl;
        // TODO : ENCRYPT

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
        std::cout << "random share 1 of alpha: " << alpha2[i][j] << endl;

        // TODO : ENCRYPT

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
        std::cout << "random share 1 of beta: " << beta2[i][j] << endl;


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
        std::cout << "random share 1 of gamma: " << gamma2[i][j] << endl; 
        }
        // TODO : ENCRYPT
    }

    std::cout << "Data Preparation for the Beaver triplets Done" << endl;

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
    }


    int t = 2;
    std::cout << "threshold t:"<< "\t" << t << endl;

    // int dataAggforAuthorisedRj[numberofReceivers];

    // for (int i = 0; i < numberofReceivers; ++i){
    //     if (authorisedRj[i] >= t){
    //         dataAggforAuthorisedRj[i] = 1;
    //         //std:: cout << " Authorised R[" << i <<"] has " << authorisedRj[i] << " votes" << endl;
    //     }
    // }

    std::cout << "Learning authorised Receivers Done" << endl;

    std::cout << "Aggregation Started" << endl; 


	/* for (int i = 0; i < numberofDataOwners; ++i){
	    for (int j = 0; j < numberofReceivers; ++j){
	      if (dataAggforAuthorisedRj[j]==1){
	        ////////////////
	        //by Agg
	        //////////////// 
	      	epsilon1[i][j]= data1[i][j] + alpha1[i][j];
	      	delta1[i][j] = choice_vector1[i][j] + beta1[i][j];

	        ////////////////
	        // by Dec
	        ////////////////
	        epsilon2[i][j]= data2[i][j] + alpha2[i][j];
	      	delta2[i][j] = choice_vector2[i][j] + beta2[i][j];

	        ////////////////
	        // both
	        ////////////////
	        epsilon[i][j] = epsilon1[i][j] + epsilon2[i][j];
	        delta[i][j] = delta1[i][j] + delta2[i][j]; 

	        ////////////////
	        //by Agg
	        //////////////// 
	        partialAdd1[i][j] = gamma1[i][j] + epsilon[i][j]*choice_vector1[i][j]+delta[i][j]*data1[i][j];

	        ////////////////
	        // by Dec
	        ////////////////
	       	partialAdd2[i][j] = gamma2[i][j] + epsilon[i][j]*choice_vector2[i][j]+delta[i][j]*data2[i][j];

	        ////////////////
	        // by Dec
	        ////////////////
	        partialAdd[i][j] = partialAdd1[i][j] + partialAdd2[i][j];
	        result[i][j] = partialAdd[i][j] - epsilon[i][j]*delta[i][j];

		    }
		}
	} */






     cout << endl;
     cout << "Time per KEY GENERATION (seconds)... " << time_KG << endl;
    
    // cout << "ERRORS v2m2: " << error_count_v2m2 << " over " << nb_trials << " tests!" << endl;
    // cout << "Average time per bootNAND_FFT_v2m2: " << argv_time_NAND_v2m2/nb_trials << " seconds" << endl;

    // cout << endl << "ERRORS Encrypt/Decrypt: " << error_count_EncDec << " over " << nb_trials << " tests!" << endl;
    

   

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
