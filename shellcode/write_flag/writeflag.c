#include <stdio.h>
#include <fcntl.h>

int main()
{
    int fd = open("./flag", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
    write(fd, "gggggggggg", 10);
    return 0;
}
