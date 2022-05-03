bisers: bisers.c
	gcc bisers.c -lpcap -O2 -o bisers

pyping.so: pypingmodule.c
	gcc -fPIC -shared pypingmodule.c -O2 -o pyping.so
