#include "maze.h"
#include <cstdint>
#include <queue>
#include <cstdlib>
#include <iostream>
#include <string>
using namespace std;

int moveOff[] = {-16, 16, -1, 1};
char commands[] = "wsadefq";
typedef uint8_t Pos;
vector<Pos> parent(256);
vector<Pos> visit(256);
vector<Pos> direct(256);
int main(int argc,char** argv){
	if(argc<3) return 0;
	Pos start = atoi(argv[1]);
	Pos end = atoi(argv[2]);
	queue<Pos> q;
	q.push(start);
	while(!q.empty()){
		Pos x = q.front();
		q.pop();
		if(x == end){
			while(!q.empty()) q.pop();
			break;
		}
		for(int i=0;i<4;i++){
			Pos val = x+moveOff[i];
			if(mazeDir[x][i] && visit[val] == 0){
				visit[val] = 1;
				parent[val] = x;
				direct[val] = i;
				q.push(val);
			}
		}
	}
	string sol = "";
	while(end != start){
		sol = commands[direct[end]] + sol;
		end = parent[end];
	}
	cout << sol;

}
