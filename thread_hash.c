//Daniel Huynh, Novemberr 23th, 2024
//CS333 Jesse Chaney Lab 5. This program reads and writes archive files using getopt and read() write() functions
//
#include <stdbool.h>
#include <crypt.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "thread_hash.h"
#include <pthread.h>
//Define Macros
#define BUF_SIZE 1024
//store files into char array and iterate to crack hashes and for each password, pthread_lock and unlock 

// global file and thread variables
static int num_threads=1;
static char **  dictArr = NULL;
static char ** passArr = NULL;

// global count variable to clear arary 
int dictcount=0;
int passcount=0;

//Functionas
int find_hashtype(char hash[]);
double elapse_time(struct timeval * t0, struct timeval * t1); // Function From mm2.c
char * getsalt(char hash[]);
void hashfunct(char * hashfile, char * dictfile);
void crackhash(void);
void freelists(void);


//Main
int main(int argc, char *argv[]) {
	//Define Variables
	bool verbose;
	int opt = 0;            
	//Our Files From Opt Arg
	char *  filename = NULL;
//	char *  outputfile = NULL;
	char * dictionaryfile = NULL;
	
	//File Reading

//	int fd = STDOUT_FILENO;
//	pthread_t * threads = NULL;
//	long tid = 0;


	//Handle Commands
	while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
		switch (opt) {
			case 'i': //Input File **Required**
				if(optarg) filename = optarg;
				printf("%s", filename);
				break;
			case 'o': //Output File
//				outputfile = optarg;
//				if(optarg) fd = open(optarg, O_WRONLY);
				break;
			case 'd': // Dictionary File **Required**
				dictionaryfile = optarg;
				printf("%s", dictionaryfile);
				break;
			case 't': // Set Threads
				num_threads = atoi(optarg);
//				threads= malloc(num_threads * sizeof(pthread_t));
				break;
			case 'n': // Nice Function
				 //pass 10 to the nice function
				nice(10);
				break;
			case 'v': // Verbose Option
				verbose = !verbose;
				break;
			case 'h': // Help Menu
				break;
			default:
				printf("Error processing an option\n");

		}
	}
	if(!filename){
		printf("\nYou must include an input file using the -i option\n");
		exit(EXIT_FAILURE);
	}


	//global variable for dictionary 
	hashfunct(filename, dictionaryfile);
	crackhash();
	freelists();
}

void crackhash(void){
	struct crypt_data data;
	char * ourhash = NULL;
	//Loop our char * array of hashes
	for(int i =0; i < passcount; i++){
		// Initialize the struct
		memset(&data, 0, sizeof(struct crypt_data));
		for(int j =0; j < dictcount; j++){
			ourhash = crypt_rn(dictArr[j], passArr[i], &data, sizeof(data));

			if (strcmp(ourhash, passArr[i]) == 0) {
				printf("\n\ncracked: %s -> %s\n", passArr[i], dictArr[j]);
				break; // Exit inner loop if match is found
			}
			if (j == dictcount - 1) {
				printf("\n***failed to crack  %s\n", passArr[i]);
			}
		}


	}	

}

void freelists(void){
	for(int i=0; i< dictcount; i++){
		free(dictArr[i]);
	}
	free(dictArr);         // Free the dictArr itself if it was dynamically allocated
	dictArr = NULL;
	for(int i =0; i < passcount; i++){
		free(passArr[i]);

	}
	free(passArr);
	passArr = NULL;
}


void hashfunct(char * passfile, char * dictfile ){
	FILE* dictfd =0;
	FILE* passfd =0;
	size_t len = 0;	
	int arrcount =0;
	//size_t len2 =0;
	char * pass = NULL;
	char * dict = NULL;
	dictfd = fopen(dictfile, "r");
	passfd = fopen(passfile, "r");
	if(passfd){
		//Allocate the correct amount of indexes for our char **
		while(getline(&pass, &len, passfd) != -1){
			size_t linelen = strlen(pass);
			if (linelen > 0 && pass[linelen - 1] == '\n') {
				pass[linelen - 1] = '\0';
			}
			passcount++;
		}
		rewind(passfd);
		passArr = malloc(sizeof(char*) * passcount);
		if (!passArr) {
			printf("Failed password file malloc\n");
			exit(EXIT_FAILURE);
		}

		while(getline(&pass, &len, passfd) != -1){
			size_t linelen = strlen(pass);
			if (linelen > 0 && pass[linelen - 1] == '\n') {
				pass[linelen - 1] = '\0';
			}
			passArr[arrcount] = strdup(pass);
			arrcount++;
		}
		//Reset count variable for reuse
		arrcount =0;

	}else{
		printf("\nError opening password file\n");
		exit(EXIT_FAILURE);
	}
	if(dictfd){
		//Allocate the correct amount of indexes for our char **
                while(getline(&dict, &len, dictfd) != -1){
                        size_t linelen = strlen(dict);
                        if (linelen > 0 && dict[linelen - 1] == '\n') {
                                dict[linelen - 1] = '\0';
                        }
			//Index count
                        dictcount++;
                }
                rewind(dictfd);
                dictArr = malloc(sizeof(char*) * dictcount);
                if (!dictArr) {
                        printf("Failed password file malloc\n");
                        exit(EXIT_FAILURE);
                }

                while(getline(&dict, &len, dictfd) != -1){
                        size_t linelen = strlen(dict);
                        if (linelen > 0 && dict[linelen - 1] == '\n') {
                                dict[linelen - 1] = '\0';
                        }
                        dictArr[arrcount] = strdup(dict);
			//Read into index
                        arrcount++;
                }
		//Reset count variables for reuse
		arrcount =0;

        }else{
                printf("\nError opening dictionary file\n");
                exit(EXIT_FAILURE);
        }

	free(pass);  // Free the memory allocated by getline
	fclose(passfd);
	free(dict);
	fclose(dictfd);
}



int find_hashtype(char hash[]){ //Find Hash Type
	if(!hash){
		printf("Hash NULL");
		exit(EXIT_FAILURE);
	}
	if(hash[0] == '$'){
		switch(hash[1]){
			case '3': // NT algorithm
				return 1;
				break;
			case '1': // MD5 algorithm
				return 2;
				break;
			case '5': // SHA-256
				return 3;
				break;
			case '6': // SHA-512
				return 4;
				break;
			case 'y': // yescrypt algorithm
				return 5;
				break;
			case 'g': // gost-yescript 
				if(hash[2] == 'y'){
					return 6;
				}
				break;
			case '2': // bcrypt
				if(hash[2] =='b'){
					return 7;
				}
				break;
			default: //None
				return -1;
				break;

		}
	}
	//DES Algorithm
	printf("DES");
	return 0;


}
char *getsalt(char hash[]) {
	int length = strlen(hash);
	int signs = 0;

	// Allocate memory dynamically for the resulting string
	char *arr = malloc(length + 1); // +1 for the null terminator
	if (arr == NULL) {
        perror("Memory allocation failed");
        return NULL;
    }

    for (int i = 0; i < length; i++) {
        arr[i] = hash[i]; // Copy character
        if (hash[i] == '$') {
            ++signs;
        }
        if (signs == 4) { // Stop copying after the fourth '$'
            arr[i + 1] = '\0'; // Null-terminate the string
            return arr;
        }
    }

    // If the loop completes without finding 4 '$' signs
    arr[length] = '\0'; // Null-terminate the string
    return arr;
}

/*
char * getsalt(char hash[]){
	char arr[100];
	int length = strlen(hash);
	int signs =0;
	for(int i =0; i < length; i++){
		if(hash[i] =='$'){
			++signs;
		}
		arr[i] = hash[i];
		if(signs == 4){
			return arr;
		}
	}
	printf("\nfunction done:%s ", arr); 
	// expenthesis:$5$rounds=1338$21Xm5h/zMhAcEx20$JhNslGqXno.9l2PEnR9AucFlcKaoBFOQb7Afjds0Oo4
	return arr;
}
*/

double elapse_time(struct timeval * t0, struct timeval * t1){ //mm2.c function
	double et = (((double) (t1->tv_usec - t0->tv_usec)) / MICROSECONDS_PER_SECOND) + ((double) (t1->tv_sec - t0->tv_sec));
	return et;
}

