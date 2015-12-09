#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "loggerfilter.h"

const char *dir = "/home/starbound";
const char *flagPath = "/home/flags/starbound";

const char *targetProgramDir = "/home/starbound";
const char *targetProgram = "environment.py";

char inputLogFile[100];
char outputLogFile[100];
char logFile[100];
char flag[100];

FILE *fp_in, *fp_out;

int isThread;

int inputFilter(char *buf, int n)
{
    // if(strstr(buf, "dada"))
    // {
    //  //fprintf(stderr, "pwn?\n");
    //  exit(-1);
    // }
}
void outputFilter(char *buf, int n)
{
    char *base64_flag;
    size_t len;

    if(strstr(buf, flag))
    {
        //fprintf(stderr, "flag leakage?\n");
        exit(-1);   
    }
    else if(strstr(buf, base64_flag))
    {
        //fprintf(stderr, "base64 flag leakage?\n");
        exit(-1);
    }
}

void logInput(char *buf, int n)
{
    time_t t;
    t = time(NULL);
    if(isThread)
    {
        fprintf(fp_in, "%s", ctime(&t));    
    }
    else
    {
        fprintf(fp_in, "[Input] %s", ctime(&t));        
    }
    
    fwrite(buf, 1, n, fp_in);
    fflush(fp_in);
}
void logOutput(char *buf, int n)
{
    time_t t;
    t = time(NULL);
    if(isThread)
    {
        fprintf(fp_out, "%s", ctime(&t));   
    }
    else
    {
        fprintf(fp_out, "[Output] %s", ctime(&t));          
    }
    fwrite(buf, 1, n, fp_out);
    fflush(fp_out);
}

void runTargetProgram()
{
    chdir(targetProgramDir);
    execve(targetProgram, NULL, NULL);
}

void init(int thread)
{
    time_t timer;
    char buf[30];
    struct tm* tm_info;
    FILE *fp;
    char *remote_ip;

    isThread = thread;

    chdir(dir);

    remote_ip = getenv("REMOTE_HOST");
    if(remote_ip == NULL)
        remote_ip = "";

    timer = time(NULL);
    tm_info = localtime(&timer);

    strftime(buf, 30, "%m_%d_%H:%M:%S", tm_info);

    if (thread) // two-thread
    {
        strcat(inputLogFile, "log/input_");
        strcat(inputLogFile, remote_ip);
        strcat(inputLogFile, buf);
        strcat(inputLogFile, ".log");

        strcat(outputLogFile, "log/output_");
        strcat(outputLogFile, remote_ip);
        strcat(outputLogFile, buf);
        strcat(outputLogFile, ".log");  
        fp_in = fopen(inputLogFile, "a+");
        fp_out = fopen(outputLogFile, "a+");
    }
    else
    {
        strcat(logFile, "log/log");
        strcat(logFile, remote_ip);
        strcat(logFile, buf);
        strcat(logFile, ".log");
        fp_in = fp_out = fopen(logFile, "a+");
    }
    

    fp = fopen(flagPath, "r");
    fread(flag, 1, 2048, fp);
    //fprintf(stderr, "%s\n", flag);

}
