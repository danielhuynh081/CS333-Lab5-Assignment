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

//Define Macros
#define BUF_SIZE 1024

int find_hashtype(char hash[]);
double elapse_time(struct timeval * t0, struct timeval * t1); // Function From mm2.c
char * getsalt(char hash[]);


//Main
int main(int argc, char *argv[]) {
	//Define Variables
	char *  filename = NULL;
	char *  outputfile = NULL;
	char * dictionaryfile = NULL;
	char * ourhash = NULL;
	char *newsalt= NULL;
	char *line = NULL;
	char * line2= NULL;
	size_t len = 0;
	size_t len2 =0;
	FILE * inputfd = NULL;
	FILE * dictfd = NULL;
	int opt = 0;            
	int fd = STDOUT_FILENO;
	int threads =1;
	bool verbose;
	struct crypt_data data;

	//Handle Commands
	while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
		switch (opt) {
			case 'i': //Input File **Required**
				if(optarg) filename = optarg;
				printf("%s", filename);
				break;
			case 'o': //Output File
				outputfile = optarg;
				if(optarg) fd = open(optarg, O_WRONLY);
				printf("%d", fd);
				printf("%d", threads);
				printf("%s", outputfile);
				break;
			case 'd': // Dictionary File **Required**
				dictionaryfile = optarg;
				printf("%s", dictionaryfile);
				break;
			case 't': // Set Threads
				threads= atoi(optarg);
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


	dictfd = fopen(dictionaryfile, "r");
	inputfd = fopen(filename, "r");
	if(inputfd){
	//input a hash
	 while (getline(&line, &len, inputfd) != -1) {
		 // initialize the struct
		 memset(&data, 0, sizeof(struct crypt_data));

		 printf("\noriginal:%s\n", line);
		 newsalt = getsalt(line);
		 //with each hash go through the list of words and see if theres a match, if theres a match print
		 while(getline(&line2, &len2, dictfd) != -1){
			 ourhash = crypt_rn(line2 ,newsalt, &data, sizeof(data));

			 printf("trying word%s", line2);
			 if(strcmp(ourhash, line) ==0){
				 printf("Match found%s", line2);
			 }

		 }

		 /*
		 printf("\noriginal:$5$rounds=1334$XTdSb0KNJsT4j4QH$HJfcfDXd1eu/OV8xrKU20b1wfWGGBX7SY2OA5e7C5YA\n");

		 printf("\nnewnew%s\n", newsalt);

		 ourhash = crypt_rn("Reformed",newsalt, &data, sizeof(data));
		 printf("our hash =%s\n", ourhash);

		 find_hashtype(line);
		 */

		 exit(EXIT_SUCCESS);


	 }
	}
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
				  // expenthesis:$5$rounds=1338$21Xm5h/zMhAcEx20$JhNslGqXno.9l2PEnR9AucFlcKaoBFOQb7Afjds0Oo4
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

