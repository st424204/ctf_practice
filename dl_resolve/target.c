#include <unistd.h>

void work(){
	char buf[0x10];
	read(0x0,buf,0x100);
}
int main(){
	work();
}
