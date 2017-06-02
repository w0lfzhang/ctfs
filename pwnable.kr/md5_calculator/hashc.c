#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv){    
    int time = atoi(argv[1]);
    int cap = atoi(argv[2]);
    srand(time);
    int i;
    int rands[8];
    for(i = 0; i <= 7; i++)
    {
        rands[i] = rand();
    }
    int rs = rands[1] + rands[2]- rands[3] + \
    rands[4] + rands[5] - rands[6] + rands[7];
    cap -= rs;
    printf("%d",m);
    return 0;
}
