#include<stdio.h>

int main(int argc, char** argv){
    if(argc != 2){
        printf("usage: airodump <interface>\n");
        return 1;
    }
    return 0;
}
