/* See LICENSE file for license details */
/* lethargy - yescrypt passwd hasher */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <crypt.h>

void read_passwd(char *buf, size_t s){
	struct termios o, n;
	tcgetattr(STDIN_FILENO, &o);
	n = o;
	n.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &n);
	printf("passwd: "); fflush(stdout);
	if(!fgets(buf, s, stdin)){
		fprintf(stderr, "failed to read passwd\n");
		tcsetattr(STDIN_FILENO, TCSANOW, &o);
		exit(1);
	}

	buf[strcspn(buf, "\n")] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &o);
	printf("\n");
}

void yescrypt_last(const char *passwd){
	char *salt = crypt_gensalt("$y$", 0, NULL, 0);
	if(!salt){
		fprintf(stderr, "crypt_gensalt failed\n");
		exit(1);
	}

	char *hash = crypt(passwd, salt);
	if(!hash){
		fprintf(stderr, "crypt failed\n");
		exit(1);
	}

	printf("yescrypt salt string: %s\n", salt);
	printf("yescrypt hash: %s\n", hash);
}

int main(){
	char passwd[256];
	read_passwd(passwd, sizeof(passwd));
	yescrypt_last(passwd);
	return 0;
}
