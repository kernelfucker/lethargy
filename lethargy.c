/* See LICENSE file for license details */
/* lethargy - yescrypt passwd hasher */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <crypt.h>

#define version "0.2"

void read_passwd(char *buf, size_t s){
	struct termios o, n;
	tcgetattr(STDIN_FILENO, &o);
	n = o;
	n.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &n);
	printf("passwd: "); fflush(stdout);
	if(!fgets(buf, s, stdin)){
		fprintf(stderr, "lethargy: failed to read passwd\n");
		tcsetattr(STDIN_FILENO, TCSANOW, &o);
		exit(1);
	}

	buf[strcspn(buf, "\n")] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &o);
	printf("\n");
}

void yescrypt_last(const char *passwd){
	char *sl = crypt_gensalt("$y$", 0, NULL, 0);
	if(!sl){
		fprintf(stderr, "lethargy: crypt_gensalt failed\n");
		exit(1);
	}

	char *hs = crypt(passwd, sl);
	if(!hs){
		fprintf(stderr, "lethargy: crypt failed\n");
		exit(1);
	}

	printf("yescrypt salt string: %s\n", sl);
	printf("yescrypt hash: %s\n", hs);
}

void help(const char *lethargy){
	printf("usage: %s [options]..\n", lethargy);
	printf("options:\n");
	printf("  -v	show version information\n");
	printf("  -h	display this\n");
	exit(1);
}

void show_version(){
	printf("lethargy-%s\n", version);
	exit(1);
}

int main(int argc, char **argv){
	if(argc == 2){
		if(strcmp(argv[1], "-h") == 0){
			help(argv[0]);
		}

		if(strcmp(argv[1], "-v") == 0){
			show_version();
		}
	}

	char passwd[256];
	read_passwd(passwd, sizeof(passwd));
	yescrypt_last(passwd);
	return 0;
}
