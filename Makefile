detect_malware_preload:
		gcc -std=c99 -z lazy -g -Wall -m64 -o detpl detect_malware_preload.c -ldl

clean:
	rm -fr detpl 
	rm -fr *.o 
	rm -fr core.*
