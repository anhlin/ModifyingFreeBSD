#include <stdlib.h>
#include <stdio.h> 
#include <sys/types.h> 
#include <unistd.h>
#include <time.h>
#include <limits.h> 
#include <sys/cdefs.h>
#include <machine/_types.h>

int rng = 0, count = 0;
  
void stall();
void bomb(int i);

int main() 
{ 
    int size = 5;
    srand(time(NULL));
    bomb(size);
    return 0; 
}

void stall() {
    wait(0);
	int i = INT_MAX;
		while(i)
			i--;
}

void bomb(int i) {
    pid_t f = fork();

	if (!i) 
        return;

    rng = (rand() % 39) - 20;
    nice(rng);
    printf("\n[fork() = %d] | [nice() = %d]\n", count++, rng);

    if (!f)
		bomb(--i);
    else
        stall();
}