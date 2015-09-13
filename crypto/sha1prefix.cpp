#include <bits/stdc++.h>
#include <openssl/sha.h> // man 3 sha1
 
// g++ sha1prefix.cpp -o sha1prefix -Ofast -lcrypto
// ./sha1prefix bSq1cCnBpLTuGv0P
 
int main(int argc, char *argv[]) {
    unsigned char s[64] = {}, h[64];
    strcpy((char*)s, argv[1]);
    for (int i1 = 33; i1 < 127; i1++) {
        s[16] = i1;
        for (int i2 = 33; i2 < 127; i2++) {
            s[17] = i2;
            for (int i3 = 33; i3 < 127; i3++) {
                s[18] = i3;
                for (int i4 = 33; i4 < 127; i4++) {
                    s[19] = i4;
                    for (int i5 = 33; i5 < 127; i5++) {
                        s[20] = i5;
                        SHA1(s, 21, h);
                        if ((h[17] & h[18] & h[19]) == 0xff) goto magic;
                    }
                }
            }
        }
    }
magic:
    puts((char*)s);
}
