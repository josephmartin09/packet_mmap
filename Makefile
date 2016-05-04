all:
	gcc -Wall -O2 walk_vector_mmap.c -o walk_vector_mmap

packet_mmap:
	gcc -Wall -O2 packet_mmap.c -o packet_mmap

clean:
	rm -rf packet_mmap walk_vector_mmap
