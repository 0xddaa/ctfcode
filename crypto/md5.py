def rollLeft(num, cnt):
    num = num & 0xffffffff
    return (num << cnt) | (num >> (32 - cnt))


def add(num1, num2):
    'makesure the sum is 32-bits integer'
    return ((num1 & 0x7fffffff) + (num2 & 0x7fffffff)) ^ (num1 &     0x80000000) ^(num2 & 0x80000000)

def opt(q, a, b, k, s, i):
    return add(b, rollLeft(add(add(add(a, q),k), i),s))
    
def ff(a, b, c, d, k, s, i): return opt((b & c)|((~b) & d), a, b, k, s, i)
def gg(a, b, c, d, k, s, i): return opt((b & d)|(c&(~d)),a,b,k,s,i)
def hh(a, b, c, d, k, s, i): return opt(b^c^d,a,b,k,s,i)
def ii(a, b, c, d, k, s, i): return opt(c^(b|~d),a,b,k,s,i)

def _hex(num):
    'convert a 32-num into hex string'
    s = '%x' %num
    if len(s) < 8:
        s = "00"+s
    return s[6:8]+s[4:6]+s[2:4]+s[0:2]

class md5():
  
    def getmd5Result(self, str):
        a = 0x67452301
        b = 0xEFCDAB89
        c = 0x98BADCFE
        d = 0x10325476
        x = self._initmd5(str)
        size = len(x)
        
        for i in range(0, size, 16):
            olda = a
            oldb = b
            oldc = c
            oldd = d
            
            a = ff(a, b, c, d, x[i+ 0], 7 , 0xD76AA478);
            d = ff(d, a, b, c, x[i+ 1], 12, 0xE8C7B756);
            c = ff(c, d, a, b, x[i+ 2], 17, 0x242070DB);
            b = ff(b, c, d, a, x[i+ 3], 22, 0xC1BDCEEE);
            a = ff(a, b, c, d, x[i+ 4], 7 , 0xF57C0FAF);
            d = ff(d, a, b, c, x[i+ 5], 12, 0x4787C62A);
            c = ff(c, d, a, b, x[i+ 6], 17, 0xA8304613);
            b = ff(b, c, d, a, x[i+ 7], 22, 0xFD469501);
            a = ff(a, b, c, d, x[i+ 8], 7 , 0x698098D8);
            d = ff(d, a, b, c, x[i+ 9], 12, 0x8B44F7AF);
            c = ff(c, d, a, b, x[i+10], 17, 0xFFFF5BB1);
            b = ff(b, c, d, a, x[i+11], 22, 0x895CD7BE);
            a = ff(a, b, c, d, x[i+12], 7 , 0x6B901122);
            d = ff(d, a, b, c, x[i+13], 12, 0xFD987193);
            c = ff(c, d, a, b, x[i+14], 17, 0xA679438E);
            b = ff(b, c, d, a, x[i+15], 22, 0x49B40821);

            a = gg(a, b, c, d, x[i+ 1], 5 , 0xF61E2562);
            d = gg(d, a, b, c, x[i+ 6], 9 , 0xC040B340);
            c = gg(c, d, a, b, x[i+11], 14, 0x265E5A51);
            b = gg(b, c, d, a, x[i+ 0], 20, 0xE9B6C7AA);
            a = gg(a, b, c, d, x[i+ 5], 5 , 0xD62F105D);
            d = gg(d, a, b, c, x[i+10], 9 , 0x02441453);
            c = gg(c, d, a, b, x[i+15], 14, 0xD8A1E681);
            b = gg(b, c, d, a, x[i+ 4], 20, 0xE7D3FBC8);
            a = gg(a, b, c, d, x[i+ 9], 5 , 0x21E1CDE6);
            d = gg(d, a, b, c, x[i+14], 9 , 0xC33707D6);
            c = gg(c, d, a, b, x[i+ 3], 14, 0xF4D50D87);
            b = gg(b, c, d, a, x[i+ 8], 20, 0x455A14ED);
            a = gg(a, b, c, d, x[i+13], 5 , 0xA9E3E905);
            d = gg(d, a, b, c, x[i+ 2], 9 , 0xFCEFA3F8);
            c = gg(c, d, a, b, x[i+ 7], 14, 0x676F02D9);
            b = gg(b, c, d, a, x[i+12], 20, 0x8D2A4C8A);
        
            a = hh(a, b, c, d, x[i+ 5], 4 , 0xFFFA3942);
            d = hh(d, a, b, c, x[i+ 8], 11, 0x8771F681);
            c = hh(c, d, a, b, x[i+11], 16, 0x6D9D6122);
            b = hh(b, c, d, a, x[i+14], 23, 0xFDE5380C);
            a = hh(a, b, c, d, x[i+ 1], 4 , 0xA4BEEA44);
            d = hh(d, a, b, c, x[i+ 4], 11, 0x4BDECFA9);
            c = hh(c, d, a, b, x[i+ 7], 16, 0xF6BB4B60);
            b = hh(b, c, d, a, x[i+10], 23, 0xBEBFBC70);
            a = hh(a, b, c, d, x[i+13], 4 , 0x289B7EC6);
            d = hh(d, a, b, c, x[i+ 0], 11, 0xEAA127FA);
            c = hh(c, d, a, b, x[i+ 3], 16, 0xD4EF3085);
            b = hh(b, c, d, a, x[i+ 6], 23, 0x04881D05);
            a = hh(a, b, c, d, x[i+ 9], 4 , 0xD9D4D039);
            d = hh(d, a, b, c, x[i+12], 11, 0xE6DB99E5);
            c = hh(c, d, a, b, x[i+15], 16, 0x1FA27CF8);
            b = hh(b, c, d, a, x[i+ 2], 23, 0xC4AC5665);
        
            a = ii(a, b, c, d, x[i+ 0], 6 , 0xF4292244);
            d = ii(d, a, b, c, x[i+ 7], 10, 0x432AFF97);
            c = ii(c, d, a, b, x[i+14], 15, 0xAB9423A7);
            b = ii(b, c, d, a, x[i+ 5], 21, 0xFC93A039);
            a = ii(a, b, c, d, x[i+12], 6 , 0x655B59C3);
            d = ii(d, a, b, c, x[i+ 3], 10, 0x8F0CCC92);
            c = ii(c, d, a, b, x[i+10], 15, 0xFFEFF47D);
            b = ii(b, c, d, a, x[i+ 1], 21, 0x85845DD1);
            a = ii(a, b, c, d, x[i+ 8], 6 , 0x6FA87E4F);
            d = ii(d, a, b, c, x[i+15], 10, 0xFE2CE6E0);
            c = ii(c, d, a, b, x[i+ 6], 15, 0xA3014314);
            b = ii(b, c, d, a, x[i+13], 21, 0x4E0811A1);
            a = ii(a, b, c, d, x[i+ 4], 6 , 0xF7537E82);
            d = ii(d, a, b, c, x[i+11], 10, 0xBD3AF235);
            c = ii(c, d, a, b, x[i+ 2], 15, 0x2AD7D2BB);
            b = ii(b, c, d, a, x[i+ 9], 21, 0xEB86D391);
            
           
            a = add(a, olda);
            b = add(b, oldb);
            c = add(c, oldc);
            d = add(d, oldd);
        print a,b,c,d
        return _hex(a) + _hex(b) + _hex(c) + _hex(d)
   
    def _initmd5(self, str):
        size = len(str)
        n = ((size + 8) >> 6) + 1
        m = [0] * (n * 16)
        #each 4 char in str will chanslate into a 32-bits integer.
        i = 0
        while i < size:
            m[i >> 2] |= ord(str[i]) << ((i % 4) * 8)
            i = i + 1

        m[i >> 2] |= 0x80 << ((i % 4) * 8)
        m[n * 16 - 2] = size * 8
        return m

import sys
print md5().getmd5Result(sys.argv[1]) 
