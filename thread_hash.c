// Daniel Huynh, November 23th, 2024
// CS333 Jesse Chaney Lab 5. This program reads and writes archive files using getopt and read() write() functions
//
#include <stdbool.h>
#include <crypt.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "thread_hash.h"
#include <sys/time.h>
// Define Macros
#define BUF_SIZE 1024
#define MICROSECONDS_PER_SECOND 1000000.0

// Global file and thread variables
static int num_threads = 1;
FILE * outputfile = NULL;
static char** dictArr = NULL;
static char** passArr = NULL;

// Global count variables
int dictcount = 0;
int passcount = 0;

// Mutex for thread-safe operations
pthread_mutex_t lock;

// Function declarations
double elapse_time(struct timeval* t0, struct timeval* t1);
char* getsalt(char hash[]);
void hashfunct(char* hashfile, char* dictfile);
void crackhash(void);
void freelists(void);
void* threaded_crackhash(void* arg);

// Struct for thread arguments


// Main function
int main(int argc, char* argv[]) {
	    double total_time, hash_time, crack_time, free_time;
	double op_time;
    bool verbose = false;
    int opt = 0;
    char* filename = NULL;
    char* dictionaryfile = NULL;
    struct timeval t0, t1, t2, t3, t4, t5;
    outputfile =stdout;

    // Handle commands
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
            case 'i': // Input file **Required**
                if (optarg) filename = optarg;
                break;
            case 'd': // Dictionary file **Required**
                dictionaryfile = optarg;
                break;	
	    case 'o':
		if (optarg) {
			outputfile = fopen(optarg, "w");
			if (!outputfile) {
				perror("fopen");
				return 1;
			}
		}
		break;
            case 't': // Set threads
                num_threads = atoi(optarg);
                break;
            case 'n': // Nice function
                nice(10);
                break;
            case 'v': // Verbose option
                verbose = !verbose;
                break;
            case 'h': // Help menu
                printf("Usage: %s -i <input_file> -d <dictionary_file> [-t <num_threads>] [-n] [-v]\n", argv[0]);
                exit(EXIT_SUCCESS);
            default:
                printf("Error processing an option\n");
        }
    }

    if (!filename || !dictionaryfile) {
        printf("\nYou must include an input file (-i) and a dictionary file (-d)\n");
        exit(EXIT_FAILURE);
    }

    // Initialize mutex
    pthread_mutex_init(&lock, NULL);
     // Start measuring total time
    gettimeofday(&t0, NULL);

    // Measure time to process files (hashing)
    gettimeofday(&t1, NULL);
    hashfunct(filename, dictionaryfile);
    gettimeofday(&t2, NULL);

    // Measure time to crack hashes
    gettimeofday(&t3, NULL);  // Start time for cracking hashes
    crackhash();
    gettimeofday(&t4, NULL);  // End time after cracking hashes

    // Free resources
    freelists();
    gettimeofday(&t5, NULL);  // Time after freeing resources
	{
    op_time = elapse_time(&t3, &t4);

    printf("  O/P   time: %8.2lf\n", op_time);
	}

    pthread_mutex_destroy(&lock);

    return 0;
}

// Threaded hash cracking function

void* threaded_crackhash(void* arg) {
    long thread_id = (long)arg;  // Retrieve thread ID
    struct crypt_data data;
    char* ourhash = NULL;

    int chunk_size = passcount / num_threads;
    int start_idx = thread_id * chunk_size;
    int end_idx = (thread_id == num_threads - 1) ? passcount : start_idx + chunk_size;

    for (int i = start_idx; i < end_idx; ++i) {
        memset(&data, 0, sizeof(struct crypt_data));  // Initialize crypt data

        for (int j = 0; j < dictcount; ++j) {
            ourhash = crypt_rn(dictArr[j], passArr[i], &data, sizeof(data));

            if (strcmp(ourhash, passArr[i]) == 0) {
                pthread_mutex_lock(&lock);  // Protect output
                fprintf(outputfile, "\ncracked: %s -> %s\n", passArr[i], dictArr[j]);
                pthread_mutex_unlock(&lock);
                break;
            }

            if (j == dictcount - 1) {
                pthread_mutex_lock(&lock);  // Protect output
                fprintf(outputfile, "\n***failed to crack  %s\n", passArr[i]);
                pthread_mutex_unlock(&lock);
            }
        }
    }

    pthread_exit(NULL);
}


// Crack hashes using threads

void crackhash(void) {
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));

    for (long i = 0; i < num_threads; ++i) {
        if (pthread_create(&threads[i], NULL, threaded_crackhash, (void*)i) != 0) {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }
    }

    // Wait for all threads to complete
    for (long i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
}

// Free dynamically allocated lists
void freelists(void) {
    for (int i = 0; i < dictcount; i++) {
        free(dictArr[i]);
    }
    free(dictArr);
    dictArr = NULL;

    for (int i = 0; i < passcount; i++) {
        free(passArr[i]);
    }
    free(passArr);
    passArr = NULL;
}

// Parse hash and dictionary files
void hashfunct(char* passfile, char* dictfile) {
    FILE* dictfd = NULL;
    FILE* passfd = NULL;
    size_t len = 0;
    int arrcount = 0;
    char* pass = NULL;
    char* dict = NULL;

    dictfd = fopen(dictfile, "r");
    passfd = fopen(passfile, "r");

    if (passfd) {
        while (getline(&pass, &len, passfd) != -1) {
            size_t linelen = strlen(pass);
            if (linelen > 0 && pass[linelen - 1] == '\n') {
                pass[linelen - 1] = '\0';
            }
            passcount++;
        }
        rewind(passfd);
        passArr = malloc(sizeof(char*) * passcount);

        while (getline(&pass, &len, passfd) != -1) {
            size_t linelen = strlen(pass);
            if (linelen > 0 && pass[linelen - 1] == '\n') {
                pass[linelen - 1] = '\0';
            }
            passArr[arrcount] = strdup(pass);
            arrcount++;
        }
        arrcount = 0;
    } else {
        printf("\nError opening password file\n");
        exit(EXIT_FAILURE);
    }

    if (dictfd) {
        while (getline(&dict, &len, dictfd) != -1) {
            size_t linelen = strlen(dict);
            if (linelen > 0 && dict[linelen - 1] == '\n') {
                dict[linelen - 1] = '\0';
            }
            dictcount++;
        }
        rewind(dictfd);
        dictArr = malloc(sizeof(char*) * dictcount);

        while (getline(&dict, &len, dictfd) != -1) {
            size_t linelen = strlen(dict);
            if (linelen > 0 && dict[linelen - 1] == '\n') {
                dict[linelen - 1] = '\0';
            }
            dictArr[arrcount] = strdup(dict);
            arrcount++;
        }
        arrcount = 0;
    } else {
        printf("\nError opening dictionary file\n");
        exit(EXIT_FAILURE);
    }

    free(pass);
    fclose(passfd);
    free(dict);
    fclose(dictfd);
}

// Helper function to determine hash type
double elapse_time(struct timeval * t0, struct timeval * t1){ //mm2.c function
	double et = (((double) (t1->tv_usec - t0->tv_usec)) / MICROSECONDS_PER_SECOND) + ((double) (t1->tv_sec - t0->tv_sec));
	return et;
}
