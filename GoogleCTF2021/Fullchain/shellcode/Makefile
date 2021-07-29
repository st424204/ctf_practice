all: sc.bin

sc.bin: sc.o
	ld --oformat=binary sc.o -o sc.bin -Ttext 0 -Tbss 0xc00  -Tdata 0x800
sc.o:	sc.c
	gcc -fomit-frame-pointer -fno-stack-protector -nostdlib -fPIE -masm=intel -c sc.c

clean:
	rm sc.bin sc.o

