
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <crypt.h>
#include <sys/time.h>

// Define Macros
#define BUF_SIZE 1024
#define MICROSECONDS_PER_SECOND 1000000.0
#define OPTIONS "i:d:o:t:nvh"

// Global file and thread variables
static int num_threads = 1;
FILE *outputfile = NULL;
static char **dictArr = NULL;
static char **passArr = NULL;
pthread_t *threads = NULL;
static int *hash_counts = NULL; // Per-thread hash count
int DES, NT, MD5, SHA256, SHA512, YESCRYPT, GOST_YESCRYPT, BCRYPT,  total, failed;

// Global count variables
int dictcount = 0;
int passcount = 0;

// Mutex for thread-safe operations
pthread_mutex_t lock;

// Function declarations
double elapse_time(struct timeval *t0, struct timeval *t1);
void hashfunct(char *hashfile, char *dictfile);
void crackhash(void);
void freelists(void);
void *threaded_crackhash(void *arg);
int find_hashtype(char hash[]);

// Main function
int main(int argc, char *argv[]) {
    double total_time, alloc_time, init_time, comp_time, td_time;
    bool verbose = false;
    int opt = 0;
    char *filename = NULL;
    char *dictionaryfile = NULL;
    struct timeval t0, t1, t2, t3, t4, t5;
    //char acct_file[256];
    //FILE * acct = NULL;
    outputfile = stdout;

    // Handle commands
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
            case 'i': // Input file **Required**
                if (optarg) filename = optarg;
                break;
            case 'd': // Dictionary file **Required**
                dictionaryfile = optarg;
                break;
            case 'o': // Output file
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
    //strncpy(acct_file, filename, strlen(filename) - 4);
    //acct_file[strlen(filename) - 4] = '\0';
    // Append ".acct" to the string
  //  strcat(acct_file, ".acct");
//    acct = fopen(acct_file, "w");

    gettimeofday(&t0, NULL);

    pthread_mutex_init(&lock, NULL);

    gettimeofday(&t1, NULL);

    hashfunct(filename, dictionaryfile);

    gettimeofday(&t2, NULL);

    threads = malloc(num_threads * sizeof(pthread_t));
    hash_counts = calloc(num_threads, sizeof(int)); // Allocate hash counters
    if (!hash_counts) {
        perror("Failed to allocate hash_counts");
        exit(EXIT_FAILURE);
    }

    gettimeofday(&t3, NULL);
    crackhash();
    gettimeofday(&t4, NULL);

    freelists();
    free(hash_counts); // Free hash count array
    gettimeofday(&t5, NULL);

    total_time = elapse_time(&t0, &t5);
    alloc_time = elapse_time(&t2, &t3);
    init_time = elapse_time(&t1, &t2);
    comp_time = elapse_time(&t3, &t4);
    td_time = elapse_time(&t4, &t5);

    //fprintf(acct, "\tDES: %d NT: %d MD5: %d SHA256: %d SHA512: %d YESCRYPT: %d GOST_YESCRYPT: %d BCRYPT: %d total: %d failed: %d\n",
      //     DES, NT, MD5, SHA256, SHA512, YESCRYPT, GOST_YESCRYPT, BCRYPT, total, failed);
    printf("\nTiming Summary:\n");
    printf("Total time: %8.2lf seconds\n", total_time);
    printf("  Alloc time: %8.2lf seconds\n", alloc_time);
    printf("  Init  time: %8.2lf seconds\n", init_time);
    printf("  Comp  time: %8.2lf seconds\n", comp_time);
    printf("  T/D   time: %8.2lf seconds\n", td_time);

    pthread_mutex_destroy(&lock);

    exit(EXIT_SUCCESS);
}

// Threaded hash cracking function
void *threaded_crackhash(void *arg) {
    long thread_id = (long)arg; // Retrieve thread ID
    struct crypt_data data;
    char *ourhash = NULL;
    bool cracked;
    int result;

    for (int i = thread_id; i < passcount; i += num_threads) {
        hash_counts[thread_id]++; // Increment only once per password
	cracked = false;
	result = find_hashtype(passArr[i]);
	switch (result) {
            case 1:  // NT hash
                NT++;  // Increment NT counter
                break;

            case 2:  // MD5 hash
                MD5++;  // Increment MD5 counter
                break;

            case 3:  // SHA-256 hash
                SHA256++;  // Increment SHA256 counter
                break;

            case 4:  // SHA-512 hash
                SHA512++;  // Increment SHA512 counter
                break;

            case 5:  // yescrypt hash
                YESCRYPT++;  // Increment YESCRYPT counter
                break;

            case 6:  // gost-yescrypt hash
                GOST_YESCRYPT++;  // Increment GOST_YESCRYPT counter
                break;

            case 7:  // bcrypt hash
                BCRYPT++;  // Increment BCRYPT counter
                break;

            case 0:  // DES hash
                DES++;  // Increment DES counter
                break;

            default:  // Unknown or unsupported hash types
                fprintf(stderr, "Unsupported hash type for password: %s\n", passArr[i]);
                failed++;
                break;
        }
	total++;
	for (int j = 0; j < dictcount; ++j) {
		memset(&data, 0, sizeof(struct crypt_data)); // Initialize crypt data
            ourhash = crypt_rn(dictArr[j], passArr[i], &data, sizeof(data));

            if (strcmp(ourhash, passArr[i]) == 0) {
                pthread_mutex_lock(&lock); // Protect output
                fprintf(outputfile, "cracked  %s  %s\n", dictArr[j], passArr[i]);
		cracked = true;
                pthread_mutex_unlock(&lock);
		//add to array
                break;
            }

	}
	if(!cracked){
		fprintf(outputfile, "*** failed to crack  %s\n", passArr[i]);
		failed++;
	}
    }

    pthread_exit(NULL);

}

// Crack hashes using threads
void crackhash(void) {
    for (long i = 0; i < num_threads; ++i) {
        if (pthread_create(&threads[i], NULL, threaded_crackhash, (void *)i) != 0) {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }
    }

    for (long i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    }
	// print out how many passwords processed, how many failed to crack. and the amount of time each was running, i think i an do this my doing settimeofday between pthreadreate and ending it after before the print. sotring times in an array for each thread like the current one, also make new arrays for totla passwords tested and failed
    for (int i = 0; i < num_threads; ++i) {
        fprintf(stderr, "Thread %d processed %d words\n", i, hash_counts[i]);
    }

    free(threads);
}

// Free dynamically allocated lists
void freelists(void) {
    for (int i = 0; i < dictcount; i++) {
        free(dictArr[i]);
    }
    free(dictArr);

    for (int i = 0; i < passcount; i++) {
        free(passArr[i]);
    }
    free(passArr);
}

// Calculate elapsed time
double elapse_time(struct timeval *t0, struct timeval *t1) {
    return ((t1->tv_sec - t0->tv_sec) + (t1->tv_usec - t0->tv_usec) / MICROSECONDS_PER_SECOND);
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
int find_hashtype(char hash[]) {
    if (!hash) {
        printf("Hash NULL");
        exit(EXIT_FAILURE);
    }
    if (hash[0] == '$') {
        switch (hash[1]) {
            case '3': return 1; // NT
            case '1': return 2; // MD5
            case '5': return 3; // SHA-256
            case '6': return 4; // SHA-512
            case 'y': return 5; // yescrypt
            case 'g': if (hash[2] == 'y') return 6; break; // gost-yescrypt
            case '2': if (hash[2] == 'b') return 7; break; // bcrypt
            default: return -1;
        }
    }
    return 0; // DES
}
