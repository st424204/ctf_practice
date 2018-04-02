CFLAGS := -fno-stack-protector -m32
all: target

target: target.c
	gcc $(CFLAGS) $^ -o $@
clean:
	rm target
