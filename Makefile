all:
	gcc -Wall -O2 packet_mmap.c -o packet_mmap

clean:
	rm -rf packet_mmap
