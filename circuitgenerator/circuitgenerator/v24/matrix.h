#ifndef MATRIX_H
#define MATRIX_H

#include <vector>
#include <bitset>
#include <iostream>

using namespace std;

#define MULTI_THREAD_FLAG 1
#define THREAD_NUM 4

//#define STRATEGY 2   // 1 for strategy3-1, 2 for strategy3-2
#define CHOICE 24




#if CHOICE == 17
    #define SIZE 32
    #define FILENAME "v17.txt"

#elif CHOICE == 18  
    #define SIZE 32
    #define FILENAME "v18.txt"

#elif CHOICE == 19  
    #define SIZE 32
    #define FILENAME "v19.txt"

#elif CHOICE == 20  
    #define SIZE 32
    #define FILENAME "v20.txt"

#elif CHOICE == 21  
    #define SIZE 32
    #define FILENAME "v21.txt"

#elif CHOICE == 22  
    #define SIZE 32
    #define FILENAME "v22.txt"

#elif CHOICE == 23  
    #define SIZE 32
    #define FILENAME "v23.txt"

#elif CHOICE == 24  
    #define SIZE 32
    #define FILENAME "v24.txt"

#elif CHOICE == 25  
    #define SIZE 32
    #define FILENAME "v25.txt"

#elif CHOICE == 26  
    #define SIZE 32
    #define FILENAME "v26.txt"

#elif CHOICE == 27  
    #define SIZE 32
    #define FILENAME "v27.txt"

#elif CHOICE == 28  
    #define SIZE 32
    #define FILENAME "v28.txt"

#else
    #define SIZE 16
#endif

typedef bitset<SIZE> ROW;

typedef struct{
    int src;
    int dst;
    bool flag;
}xpair;

typedef struct
{
    vector<xpair> seq;
    int gap;
    int start;
    int len;
}thread_data;

vector<ROW> get_matrix();


#endif
