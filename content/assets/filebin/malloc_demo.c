#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MAX 500

__attribute__((constructor)) void ignore_me(){
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void menu(){
	puts("1. malloc");
	puts("2. read");
	puts("3. edit");
	puts("4. free");
	puts("5. quit");
	printf(">> ");
}

ssize_t read(int fd, void * buf, size_t nbytes){
        return syscall(0, fd, buf, nbytes);
}

long readnum(){
	char buf[100];
	read(0,buf,50);
	fflush(stdin);
	if(strstr(buf,"x") != NULL){
		return strtol(buf, NULL, 16);
	}
	return strtol(buf, NULL, 10);;
}

int main(){
	int index = 0;
	char *chunks[MAX];
	long sizes[MAX];
	int option;
	long size;
	puts("Malloc Sandbox | masoncc");
	while(1){
		menu();
		option = (int) readnum();
		switch(option){
			case 1:
				printf("Size>> ");
				size = readnum();
				chunks[index] = malloc(size);
				sizes[index] = size;
				if(chunks[index] == NULL || index > MAX){
					puts("Allocation error!");
					break;
				}
				index++;
				break;
			case 2:
				printf("Index>> ");
				option = (int) readnum();
				printf("%d", option);
				if(option >= 0 && option < index && chunks[option] != NULL){
					write(1,chunks[option],sizes[option]);
					break;
				}
				puts("\nInvalid option!");
				break;
			case 3:
				printf("Index>> ");
				option = (int) readnum();
				if(option >= 0 && option < index && chunks[option] != NULL){
					printf("Data>> ");
					read(0,chunks[option],sizes[option]-1);
                                        break;
                                }
                                puts("\nInvalid option!");
                                break;
			case 4:
				printf("Index>> ");
                                option = (int) readnum();
                                if(option >= 0 && option < index && chunks[option] != NULL){
					free(chunks[option]);
                                        break;
                                }
                                puts("\nInvalid option!");
                                break;
			case 5:
				return 0;
			default:
				puts("\nInvalid option!");
				break;
		}
	}
}
