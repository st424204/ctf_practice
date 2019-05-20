#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
char buf[0x100];
void listdir(char* p){

	chdir(p);
	DIR *dir;
	struct dirent *entry;
	dir = opendir(".");
	while ((entry = readdir(dir)) != NULL){
		if( strcmp(entry->d_name,"flag") == 0){
			puts("Find flag");
			int fd = open("./flag",0);
			int n = read(fd,buf,0x100);
			write(1,buf,n);
			_exit(0);
		} else if( entry->d_type == DT_DIR){
			 if( strcmp(entry->d_name,".") && strcmp(entry->d_name,".."))
				listdir(entry->d_name);
		} else {
		}
	}
	closedir(dir);
	chdir("..");
}



int main() {
	listdir("flag");
}
