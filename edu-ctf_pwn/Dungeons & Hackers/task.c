#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "maze.h"

#define MAXITEMS 0x40
#define MAXDEPTH 5
#define MAXHP 5
#define FLAG1SCORE 100
#define ATK 2
#define BUFSZ 2

typedef uint8_t Pos;

Pos player = 0;
Pos monster = 0;
int score = 0;
int HP = MAXHP;
Pos items[MAXITEMS];
int nitems = 0;

char* getFlag1() {
    char buf[100];
    int fd = open("flag", O_RDONLY);
    if (fd < 0){
        printf("Open error");
        exit(-1);
    }
    read(fd, buf, 50);
    close(fd);
    return strdup(buf);
}

void initMap(char* buf) {
    memcpy(buf, mazeStr, sizeof(mazeStr));
}

void draw(char* buf, Pos pos, char c) {
    buf[mazePos[pos]] = c;
}

void putnc(int n, char c) {
    for (int i=0; i<n; i++) {
        printf("%c", c);
    }
}

/*
''''''''''''''''''''''''''''''''x''''''''''''''''''''''''''''''''
Score                     Dungeons v1                          HP
00000                                                       xxxxx
 */
void render() {
    static char* flag1 = NULL;
    static int prefix = 0, suffix = 0;
    if (!flag1) {
        flag1 = getFlag1();
        int len = strlen(flag1);
        prefix = (55 - len) / 2;
        suffix = 55 - prefix - len;
    }
    
    char buf[sizeof(mazeStr)];
    initMap(buf);
    draw(buf, player, 'O');
    for (int i=0; i<nitems; i++) {
        Pos pos = items[i];
        if (pos == player) {
            draw(buf, pos, 'G');
        } else {
            draw(buf, pos, 'i');
        }
    }
    
    if (monster == player) {
        draw(buf, monster, 'B');
    } else {
        draw(buf, monster, 'M');
    }
    
    puts("");
    puts("Score                   Dungeons v1.0.0                        HP");
    printf("%05d", score);
    if (score < FLAG1SCORE) {
        putnc(55, ' ');
    } else {
        putnc(prefix, ' ');
        printf("%s", flag1);
        putnc(suffix, ' ');
    }
    putnc(5 - HP, ' ');
    putnc(HP, 'x');
    puts("");
    printf("%s", buf);
}

void checkWall(Pos pos, int dir) {
    if (!mazeDir[pos][dir]) {
        puts("[!] Boom!!");
        exit(0);
    }
}

char commands[] = "wsadefq";
char cAct;
char *sAct;
char *RET;
int getAction() {
    char buf[BUFSZ] = {0};
    
    printf("[>] action: ");
    RET = fgets(buf, 10, stdin);
    if (RET != buf || !buf[0]) {
        exit(0);
    }
    cAct = buf[0];
    memset(buf, 0, sizeof(buf));
    
    sAct = strchr(commands, cAct);
    if (!sAct) {
        return -1;
    }
    
    return sAct - commands;
}

int moveOff[] = {-16, 16, -1, 1};
void move(int dir) {
    checkWall(player, dir);
    player += moveOff[dir];
}

int attack() {
    if (player == monster) {
        items[nitems++] = player;
        while (monster == player)
            monster = rand() % 256;
        if (nitems == MAXITEMS) {
            puts("[!] WAT??");
            exit(0);
        }
        score += 1;
        return 1;
    } else {
        puts("[!] Boom!!");
        exit(0);
    }
    return 0;
}

void pick() {
    int ind = nitems - 1;
    while (ind >= 0 && items[ind] != player) {
        ind--;
    }
    
    if (ind < 0){
        puts("[!] Boom!!");
        exit(0);
    }
    
    memcpy(&items[ind], &items[ind + 1], (nitems - ind - 1) * sizeof(items[0]));
    HP += 1;
    HP = (HP > MAXHP) ? MAXHP : HP;
    nitems -= 1;
}

int dfs (Pos pos, int depth, int last) {
    if (depth == MAXDEPTH)
        return -1;
    if (player == pos)
        return pos;
    for (int dir=0; dir<4; dir++) {
        if ((last ^ 1) == dir)
            continue;
        if (mazeDir[pos][dir]) {
            int newPos = pos + moveOff[dir];
            if (dfs(newPos, depth + 1, dir) != -1) {
                return newPos;
            }
        }
    }
    return -1;
}

void monsterAttack() {
    if (player == monster) {
        HP -= rand() % ATK + 1;
        if (HP <= 0) {
            puts("[-] Game over");
            exit(0);
        }
    }
}

void moveMonster() {
    int newPos = dfs(monster, 0, 42);
    monster = (newPos == -1) ? monster : newPos;
}

int main() {
    srand(time(NULL));
    player = rand() & 255;
    monster = rand() & 255;
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    
    char buf[100];
    printf("[>] Who r u? ");
    fgets(buf, 100, stdin);
    if (strstr(buf, "jery") || strstr(buf, "ddaa") || strstr(buf, "angelboy") || strstr(buf, "217") || strstr(buf, "orange") || strstr(buf, "joe")){
        puts("[!] Go away QAQ");
        exit(0);
    }
    printf("Welcome %s\n", buf);
    memset(buf, 0, 100);
    
    while (1) {
        render();
        int act = getAction();
        if (act < 0) {
        } else if (act < 4) {
            monsterAttack();
            move(act);
        } else if (act == 4) {
            pick();
        } else if (act == 5) {
            if (attack()) continue;
        } else if (act == 6) {
            return 0;
        }
        monsterAttack();
        moveMonster();
    }
    return 0;
}
