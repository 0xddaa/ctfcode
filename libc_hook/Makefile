all: m32 m64

m64: hook.c
	gcc -fPIC -shared -o hook.so hook.c -ldl
m32: hook.c
	gcc -m32 -fPIC -shared -o hook.so.32 hook.c -ldl
