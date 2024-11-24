//Daniel Huynh, October 24th, 2024
//CS333 Jesse Chaney Lab 3. This program reads and writes archive files using getopt and read() write() functions
//
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "class.h"

//Define Macros
#define BUF_SIZE 1024


# define OPTIONS "i:o:d:hvt:n"
//Main
int main(int argc, char *argv[]) {
	//Define Variables
	char *  filename = NULL;
	int opt = 0;            
	int fd = STDOUT_FILENO;
	int threads =1;
	bool verbose;
	//Handle Commands
	while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
		switch (opt) {
			case 'i': //Input File **Required**
				if(optarg) filename = optarg;
				printf("%s", filename);
				break;
			case 'o': //Output File
				if(optarg) fd = open(optarg, O_WRONLY);
				printf("%d", fd);
				printf("%d", threads);
				break;
			case 'd': // Dictionary File **Required**
				break;
			case 't': // Set Threads
				break;
			case 'n': // Nice Function
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
}
