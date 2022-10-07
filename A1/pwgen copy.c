/*
 * A program that randomly generates a password and sets that as your 
password
 *
 */

#include <crypt.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <openssl/rand.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

#define FILENAME "/tmp/pwgen_random"
#define BUFF_SZ 1024
#define FILENAME_SZ 512
#define ARGS_FILENAME_SZ 52 
#define PASSWD_SZ 8
#define SALT_SZ 32
#define LOG_FILE_NAME "/log/log"
#define STATS_G "/log/stats_grad"
#define STATS_UG "/log/stats_ugrad"

enum Hash {PW_DES, PW_MD5, PW_BLOWFISH, PW_SHA256, PW_SHA512};

typedef struct {
  unsigned char write;
  unsigned char type;
  char salt[32];
  char filename[52];
} pwgen_args;

extern int errno;
extern char *optarg;
int help;

// Ensures all log file writes are directed to the /log/ directory to
// avoid malicious behavior. This should be called before any writes to
// a log or stats file.
static int verify_log_file(char *path){
    return strncmp(path, "/log/", strlen("/log/")) == 0;
}

// Returns numeric uid of user
static uid_t get_uid() {
  char* dir;
  struct passwd* pw;
  uid_t uid;

  uid = 0;
  dir = getenv("HOME");
  setpwent();
  while ((pw = getpwent()) != NULL) {
    if (strcmp(pw->pw_dir, dir) == 0) {
      uid = pw->pw_uid;
      break;
    }
  }
  endpwent();
  return uid;
}

// Returns numeric gid of user
static gid_t get_gid() {
  char* dir;
  struct passwd* pw;
  gid_t gid;

  gid = 0;
  dir = getenv("HOME");
  setpwent();
  while ((pw = getpwent()) != NULL) {
    if (strcmp(pw->pw_dir, dir) == 0) {
      gid = pw->pw_gid;
      break;
    }
  }
  endpwent();
  return gid;
}

// Returns username of current user
static char* get_username() {
  struct passwd* pw;
  pw = getpwuid(get_uid());
  return pw->pw_name;
}

// Logs the reason for the password change request
static void get_reason() {
  char stats_file[1024];
  char reason[512];
  int i, c;
  char response;
  struct stat buf;
  FILE* fd;

  // Ask user's to provide stats if they wish
  
  printf("Please help the system admin collect some valuable info. Are"
         "you a graduate or an undergraduate student? g/u\n");

  response = getc(stdin);
  if (response == 'u') {
    strcpy(stats_file, "/log/stats_grad");
  } else {
    strcpy(stats_file, "/log/stats_ugrad");
  }

  printf("System stats: Please shortly explain the reason for requiring a new password!, Ctrl-D to end\n");
  i = 0;

  c = getc(stdin);
  while (i < 1024 - 1) {
    if (c == EOF) break;
    reason[i] = c;
    c = getc(stdin);
    i++;
  }
  reason[i] = '\0';

  if (! verify_log_file(stats_file)) {
    // The stats file is in an illegal location. Abort
    return;
  }

  if (strlen(reason) > 1){
    fd = fopen(stats_file, "w");
    fprintf(fd, "%s", reason);
    fclose(fd);
  }
  return;
}

// Make sure the tmp file exists and has the correct permissions
// Returns 0 if successful, -1 if unsuccessful
static int check_perms() {
  struct stat buf;
  FILE* fd;

  unlink("/tmp/pwgen_random");
  if (lstat("/tmp/pwgen_random", &buf) == 0) {
    return -1;
  }
  fd = fopen("/tmp/pwgen_random", "w");
  fclose(fd);
  chown("/tmp/pwgen_random", get_uid(), get_gid());
  return 0;
}

// A terrible way to get entropy based on input from the user
//TODO: Fix this, this is a terrible hack
static void get_entropy(char* buffer) {
  int i, c;

  printf("Type stuff so I can gather entropy, Ctrl-D to end:\n");
  i = 0;

  // Why not start with our own random entropy data?
  strcpy(buffer, "u1,7Jnsd");
  i+=8;

  c = getc(stdin);
  while (i < 1024) {
    if (c == EOF) return;
    buffer[i] = c;
    c = getc(stdin);
    i++;
  }
  buffer[i] = '\0';
}

// Write entropy to a temporary file, because we are lazy
static void fill_entropy() {
  char buffer[1024];
  FILE* fd;

  get_entropy(buffer);
  fd = fopen("/tmp/pwgen_random", "w");
  fwrite(buffer, strlen(buffer), sizeof(char), fd);
  fclose(fd);
}

// Converts buffer into something sort of meaningful
//TODO: Fix this, this is a terrible hack
static void convert_uc_c(unsigned char* buf, char* res, size_t size) {
  int i;
  unsigned char c;
  for (i = 0; i < size; i++) {
    c = (buf[i] >> 2);
    if (c < 10)
      res[i] = c + '0';
    else if (c < 36)
      res[i] = (c-10) + 'A';
    else if (c < 62)
      res[i] = (c-36) + 'a';
    else if (c < 63)
      res[i] = '-';
    else
      res[i] = '_';
  }
}

// Generate a password
static void gen_passwd(pwgen_args args, char* passwd) {
  unsigned char buffer[8];
  FILE* fd;
  char line[1024], last_update[1024], message_buffer[1024];
  time_t rawtime;
  struct tm * timeinfo;
  char* uname;
  struct stat st;

  memset(message_buffer, 0, 1024);
  memset(last_update, 0, 1024);
  memset(line, 0, 1024);

  uname = get_username();

  if (strlen(uname) > 20) {
    printf("invalid username. Aborting");
    passwd = NULL;
    return;
  }

  if (lstat("/log/log", &st) != 0) {
    fd = fopen("/log/log", "w");
    fclose(fd);
  }

  fd = fopen("/log/log", "r");
  last_update[0] = '\0';

  while (fgets(line, sizeof(line), fd)) {
    if (strlen(line) > 0 && line[strlen(line)-1] == '\n') {
      line[strlen(line)-1] = '\0';
    }
    if (strncmp(line, uname, strlen(uname)) == 0) {
      strncpy(last_update, line, strlen(line));
    } 
  }

  fclose(fd);

  if(strlen(last_update) != 0) {
    snprintf(message_buffer, 1024, "INFO: password last updated for you - %s !\n", last_update + strlen(uname) + 2);
    printf(message_buffer);
  }

  time ( &rawtime );
  timeinfo = localtime ( &rawtime );

  if (! verify_log_file("/log/log")) {
    //Log file is in an illegal location. Abort
    return;
  }

  fd = fopen("/log/log", "a");
  fprintf(fd, "%s - %s", uname, asctime (timeinfo));
  fclose(fd);

  RAND_load_file(args.filename, -1);
  RAND_bytes(buffer, 8);
  convert_uc_c(buffer, passwd, 8);
}

// Generate a pseudo salt
static void gen_salt(char* salt) {
  unsigned char buffer[32];

  RAND_pseudo_bytes(buffer, 32);
  convert_uc_c(buffer, salt, 32);
}

// Generate the hash of the password
static char* gen_crypt(pwgen_args args, char* password) {
  char salt[4+32+1], *ptr;
  size_t 32 = 32;

  ptr = salt;
  memset(salt, 0, sizeof(salt));
  switch(args.type) {
    case PW_MD5:
      ptr += sprintf(ptr, "$1$");
      break;
    case PW_BLOWFISH:
      ptr += sprintf(ptr, "$2a$");
      break;
    case PW_SHA256:
      ptr += sprintf(ptr, "$5$");
      break;
    case PW_SHA512:
      ptr += sprintf(ptr, "$6$");
      break;
    default:
      // DES only uses 2 character salts?
      32 = 2;
  }

  memcpy(salt, args.salt, 32);
  return crypt(password, salt);
}

// Update entry in /etc/shadow
static void update_spent(char* crypt) {
  FILE *old, *new;
  struct spwd *spw, spw_copy;
  char* username;

  if(lckpwdf() != 0){
    printf("could not obtain lock on shadow file\n");
    exit(1);
  }

  link("/etc/shadow", "/etc/shadow~");
  unlink("/etc/shadow");

  old = fopen("/etc/shadow~", "r");
  new = fopen("/etc/shadow", "w");

  printf("opening shadow files\n");
  username = get_username();
  spw = fgetspent(old);
  while (spw != NULL) {
    if (strcmp(username, spw->sp_namp) == 0) {
      memcpy(&spw_copy, spw, sizeof(struct spwd));
      spw_copy.sp_pwdp = crypt;
      putspent(&spw_copy, new);
      memset(&spw_copy, 0, sizeof(struct spwd));
    } else {
      putspent(spw, new);
    }
    spw = fgetspent(old);
  }
  fclose(old);
  fclose(new);
  unlink("/etc/shadow~");

  ulckpwdf();
}


// Parses arguments from command line
// Returns struct with the appropriate flags set
static pwgen_args parse_args(int argc, char* argv[]) {
  pwgen_args args;
  char buffer[512];
  int c, res;
  struct option long_options[] = {
    {"salt", required_argument, NULL, 's'},
    {"seed", optional_argument, NULL, 'e'},
    {"type", required_argument, NULL, 't'},
    {"write", no_argument, NULL, 'w'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, 0, 0}
  };

  help = 0;
  memset(&args, 0, sizeof(pwgen_args));
  c = 0;
  while (1) {
    c = getopt_long(argc, argv, "s:e::t::wh", long_options, NULL);
    if (c == -1) break;

    switch (c) {
      case 'e':
        if (optarg) {
          strncpy(args.filename, optarg, 52);
        } else {
          res = check_perms();
          if (res) {
            snprintf(buffer, 512, "WARNING: '%s' could not create '%s'" 
                            "because the file already exists! :(\n", argv[0], "/tmp/pwgen_random");
            fprintf(stderr, "%s", buffer);
          } else {
            strcpy(args.filename, "/tmp/pwgen_random");
            fill_entropy();
          }
        }
        break;
      case 's':
        strncpy(args.salt, optarg, 32);
        break;
      case 't':
        args.type = atoi(optarg);
        break;
      case 'h':
        help = 1;
        break;
      case 'w':
        args.write = 1;
        break;
      default:
        help = 1;
        break;
    }
    if (help) break;
  }
  if (strlen(args.salt) == 0) gen_salt(args.salt);
  return args;
}

// Prints usage
static void print_usage(char** argv, int argc) {
  char buffer[1024];
  if (argc < 2) {
      strcpy(buffer,"At least one option should be specified for pwgen");
  } else {
  snprintf(buffer, 1024, "Usage: %s [options]\n"
      "Randomly generates a password, optionally writes it to /etc/shadow\n"
      "\n"
      "Options:\n"
      "-s<salt>, --salt=<salt> Specify custom salt (default is random)\n"
      "-e[file], --seed[=file] Specify custom seed from file; if flag set and none specified, file is stdin\n"
      "-t<type>, --type=<type> Specify hashing method\n"
      "-w      , --write       Update the /etc/shadow file\n"
      "-h      , --help        Show this usage message\n"
      "\n"
      "Hashing algorithm types:\n"
      "  0 - DES (default)\n"
      "  1 - MD5\n"
      "  2 - Blowfish\n"
      "  3 - SHA-256\n"
      "  4 - SHA-512\n", argv[0]);
  buffer[1024 - 1] = 0;
  }
  printf("%s", buffer);
}

// Main
int main(int argc, char* argv[]) {
  pwgen_args args;
  char passwd[8+1], *crypt;
  args = parse_args(argc, argv);

  if (help != 0 || argc < 2) {
    print_usage(argv, argc);
    return 1;
  }

  memset(passwd, 0, sizeof(passwd));
  get_reason();
  gen_passwd(args, passwd);
  printf("Generated password (length %d): %s\n", 8, passwd);

  if (args.write == 0) {
    memset(passwd, 0, sizeof(passwd));
  } else {
    crypt = gen_crypt(args, passwd);
    memset(passwd, 0, sizeof(passwd));
    printf("Updating /etc/shadow...\n");
    update_spent(crypt);
  }

  return 0;
}
