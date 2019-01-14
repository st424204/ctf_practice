#include "maze.h"
#include <cstdint>
#include <queue>
#include <cstdlib>
#include <iostream>

using namespace std;

int moveOff[] = {-16, 16, -1, 1};
char commands[] = "wsadefq";
typedef uint8_t Pos;

struct Node{
	Pos pos;
	vector<Pos> path;
	vector<Pos> visit;
};


int main(int argc,char** argv){
	if(argc<3) return 0;
	Pos start = atoi(argv[1]);
	Pos end = atoi(argv[2]);
	queue<Node> q;
	q.push({start,vector<Pos>(),vector<Pos>(256)});
	while(!q.empty()){
		Node x = q.front();
		q.pop();
		if(x.pos == end){
			for(auto p:x.path)
				cout << commands[p];
			break;
		}
		for(int i=0;i<4;i++){
			Pos val = x.pos+moveOff[i];
			if(mazeDir[x.pos][i] && x.visit[val] == 0){
				x.visit[val] = 1;
				x.path.push_back(i);
				Pos tmp = x.pos;
				x.pos = val;
				q.push(x);
				x.visit[val] = 0;
				x.path.pop_back();
				x.pos = tmp;
			}
		}
	}

}
