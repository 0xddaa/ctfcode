#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define BUFSIZE 2048

int p1[2], p2[2], p3[2];
int pid;
pthread_t tid1, tid2, tid3;

void* inputHandler(void *args)
{
    int n;
    char buf[BUFSIZE];
    FILE* fp;
    
    while(1)
    {
        n = read(0, buf, BUFSIZE);
        /* important! exit when io is dead */
        if(n == 0) exit(0);

        logInput(buf, n);
        //inputFilter(buf, n);
        write(p1[1], buf, n);
    }
}
void* outputHandler(void *args)
{
    int n;
    char buf[BUFSIZE];
    FILE* fp;

    while(1)
    {
        n = read(p2[0], buf, BUFSIZE);
        /* important! exit when io is dead */
        if(n == 0) exit(0);
        
        logOutput(buf, n);
        //outputFilter(buf, n);
        write(1, buf, n);
    }
}

void* errHandler(void *args)
{
    int n;
    char buf[BUFSIZE];
    FILE* fp;

    while(1)
    {
        n = read(p2[0], buf, BUFSIZE);
        if(n == 0) exit(0);

        if(strstr(buf, "LD_PRELOAD") != NULL)
            continue;
    
        //write(2, buf, n);
    }
}

int main()
{
    init(1);

    pipe(p1);
    pipe(p2);
    pipe(p3);
    
    pid = fork();

    if(pid)  // parent
    {
        close(p1[0]);
        close(p2[1]);
        close(p3[1]);
        pthread_create(&tid1, NULL, &inputHandler, NULL);
        pthread_create(&tid2, NULL, &outputHandler, NULL);
        pthread_create(&tid3, NULL, &errHandler, NULL);
        pthread_join(tid1, NULL);
        pthread_join(tid2, NULL);
        pthread_join(tid3, NULL);
        exit(0);
    }
    else    // child
    {

        close(p1[1]);
        close(p2[0]);
        close(p3[0]);
        dup2(p1[0], 0);
        dup2(p2[1], 1);
        dup2(p3[1], 2);
        runTargetProgram();
        exit(0);
    }
}
