#include <errno.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <gio/gio.h>
#include <mqueue.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "pgp.h"

#ifdef DEBUG
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...)
#endif

#define gcry_perror(err, message) fprintf(stderr, message " : %s in %s\n",\
     gcry_strerror(err), gcry_strsource(err))

#define MQNAME "/pgpcrack-mq-9e74305fffc8"
#define MAX_KEY_LEN 64
#define MAX_OUTPUT_BUF_LEN 64

static int signal_caught = 0;
static unsigned int opt_fork = 1;

static GOptionEntry opt_entries[] =
{
  { "fork", 'f', 1, G_OPTION_ARG_INT, &opt_fork, "number of worker processus to fork", NULL},
  { NULL}
};

static void handler(int signum) {
  signal_caught = 1;
}

static int init_options(int argc, char *argv[], struct pgp_data *pdata) {
  GError *error = NULL;
  GOptionContext *opt_context;
  FILE *pgp;

  debug("Parsing options...\n");
  opt_context = g_option_context_new("");
  g_option_context_set_summary(opt_context, "./john --wordlist=list --rules --stdout | crack -f 8 <pgp symmetric file>");
  g_option_context_add_main_entries(opt_context, opt_entries, NULL);
  if (!g_option_context_parse(opt_context, &argc, &argv, &error)) {
    g_printerr ("Error parsing options: %s\n", error->message);
    g_error_free(error);
    g_option_context_free(opt_context);
    return -1;
  }

  if (argc != 2) {
    g_printerr("Error, missing pgp file to bruteforce.\n");
    return -1;
  }

  if ((pgp = fopen(argv[1], "r")) == NULL) {
    g_printerr("Error opening %s : %s\n", argv[1], strerror(errno));
    return -1;
  }

  printf("Using libgcrypt %s.\n", gcry_check_version(NULL));
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
  return parse_pgp(pgp, pdata);
}

static int worker(struct pgp_data *pdata, const char *file) {
  mqd_t queue;
  size_t buff_size = 256;
  char keybuffer[MAX_KEY_LEN];
  char buffer[buff_size+1];
  int blocksize = algos[pdata->key_fmt.algorithm].blocksize;
  size_t keysize = algos[pdata->key_fmt.algorithm].keysize;
  unsigned char output_buffer[2*blocksize];
  char gpg_output[1024];
  gpg_error_t gerror;
  gcry_cipher_hd_t cipher;

  memset(keybuffer, 0, MAX_KEY_LEN);
  if ((gerror = gcry_cipher_open(&cipher, algos[pdata->key_fmt.algorithm].gcry_equiv,
                                 GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_ENABLE_SYNC)) != 0) {
    gcry_perror(gerror, "Failure creating cipher handle");
    return -1;
  }

  if ((queue = mq_open(MQNAME, O_RDONLY)) == -1) {
    perror("Error opening message queue ");
    return -1;
  }

  while (1) {
    ssize_t ret = mq_receive(queue, buffer, buff_size, NULL);
    if (ret == -1) {
      switch(errno) {
       case EBADF:
         perror("mq_receive ");
         return 0;
       case EINTR:
         continue;
       case EMSGSIZE:
         perror("WTF, message buffer too small ");
       default:
         perror("Error receiving message ");
         return -1;
      }
    }

    if (buffer[ret-1] != '\0' || buffer[ret-2] == '\n') {
      fprintf(stderr, "Error, received ill-formated passphrase\n");
      return -1;
    }

    if (ret == 1) {
      debug("No more passphrases to test.\n");
      return 0;
    }

    debug("Received passphrase : %s\n", buffer);
    if ((gerror = gcry_kdf_derive(buffer, ret-1, GCRY_KDF_ITERSALTED_S2K,
                                  halgos[pdata->s2k_fmt.algorithm].gcry_equiv,
                                  pdata->s2k_fmt.salt, 8, pdata->s2k_count,
                                  keysize, keybuffer)) != 0) {
      gcry_perror(gerror, "Failure");
      return -1;
    }

    if ((gerror = gcry_cipher_setiv(cipher, NULL, 0)) != 0) {
      // undocumented gcrypt feature : NULL here is treated as a null iv.
      gcry_perror(gerror, "Failure setting null iv");
      return -1;
    }

    if ((gerror = gcry_cipher_setkey(cipher, keybuffer, keysize)) != 0) {
      gcry_perror(gerror, "Failure setting cipher key");
      return -1;
    }

    if ((gerror = gcry_cipher_decrypt(cipher, output_buffer, blocksize+2,
                                      pdata->enc_data, blocksize+2)) != 0) {
      gcry_perror(gerror, "Failure decrypting data");
      return -1;
    }

    if ((gerror = gcry_cipher_sync(cipher) != 0)) {
      gcry_perror(gerror, "Failure to sync cipher");
      return -1;
    }

    if (output_buffer[blocksize-2] != output_buffer[blocksize] ||
        output_buffer[blocksize-1] != output_buffer[blocksize+1]) {
      debug("bad passphrase\n");
    } else {
      pid_t gpg_proc = 0;
      sprintf(gpg_output, "%s-%s.clear", file, buffer);
      printf("Found candidate : %s\n", buffer);
      if ((gpg_proc = fork()) == 0) {
        execlp("gpg", "--decrypt", "--batch", "--passphrase", buffer, "--output", gpg_output, file, NULL);
      } else {
        int stat;
        waitpid(gpg_proc, &stat, 0);
        if (WIFEXITED(stat) && WEXITSTATUS(stat) == 0) {
          printf("FOUND PASSPHRASE : %s\n", buffer);
          return 1;
        }
      }
    }
  }

  return 0;
}

static void terminate(pid_t *workers, mqd_t queue) {
  mq_close(queue);
  for (int i = 0; i<opt_fork && workers[i] != 0; i++) {
    kill(workers[i], SIGTERM);
    debug("Killing child %d.\n", workers[i]);
  }
}

static void cleanup(pid_t *workers, mqd_t queue) {
  int child_ret;
  for (int i = 0; i<opt_fork; i++) {
    debug("Sending termination message.\n");
    mq_timedsend(queue, "", 1, 1, &(struct timespec){time(NULL)+2, 0});
  }
  for (int i = 0; i<opt_fork && workers[i] != 0; i++) {
    if (waitpid(workers[i], &child_ret, 0) == -1 && errno == EINTR) {
      i--;
      continue;
    }

    debug("Child %d is dead.\n", workers[i]);
  }
  mq_unlink(MQNAME);
}

int main(int argc, char *argv[]) {
  pid_t *workers = NULL;
  mqd_t queue;
  size_t buff_size = 256;
  char buffer[buff_size];
  struct pgp_data pdata;
  struct mq_attr attrs;
  struct sigaction sa;
  uint64_t tried = 0;
  struct timespec time_start;
  struct timespec time_end;

  if (init_options(argc, argv, &pdata) == -1) {
    return -1;
  }

  printf("Symmetric OpenPGP file.\n");
  printf("\tS2K hash function %s.\n", halgos[pdata.s2k_fmt.algorithm].name);
  printf("\tS2K count %u\n", pdata.s2k_count);
  printf("\tS2K salt 0x%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
         pdata.s2k_fmt.salt[0], pdata.s2k_fmt.salt[1], pdata.s2k_fmt.salt[2],
         pdata.s2k_fmt.salt[3], pdata.s2k_fmt.salt[4], pdata.s2k_fmt.salt[5],
         pdata.s2k_fmt.salt[6], pdata.s2k_fmt.salt[7]);
  printf("\tSymmetric algorithm %s.\n", algos[pdata.key_fmt.algorithm].name);

  if ((workers = malloc(opt_fork*sizeof(pid_t))) == NULL) {
    perror("Error in malloc ");
    return -1;
  }

  mq_unlink(MQNAME);
  attrs.mq_flags = 0;
  attrs.mq_msgsize = 256;
  attrs.mq_maxmsg = 10;
  if ((queue = mq_open(MQNAME, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, &attrs)) == -1) {
    perror("Error creating message queue ");
    return -1;
  }

  mq_getattr(queue, &attrs);
  debug("max_msgs %ld, msgsize %ld\n", attrs.mq_maxmsg, attrs.mq_msgsize);
  memset(workers, 0, sizeof(pid_t)*opt_fork);
  for (int i = 0; i<opt_fork; i++) {
    pid_t ret = fork();
    switch(ret) {
      case 0:
        exit(worker(&pdata, argv[1]));
      case -1:
        perror("Error in fork ");
        terminate(workers, queue);
        cleanup(workers, queue);
        return -1;
      default:
        debug("New child worker with pid %d\n", ret);
        workers[i] = ret;
        break;
    }
  }

  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1 ||
      sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("Error installing signal handler ");
    terminate(workers, queue);
    cleanup(workers, queue);
    return -1;
  }

  clock_gettime(CLOCK_MONOTONIC, &time_start);
  while (!signal_caught) {
    size_t len;
    if (fgets(buffer, buff_size, stdin) == NULL) {
      break;
    }

    // beurk.
    len = strlen(buffer);
    if (buffer[len-1] == '\n') {
      len--;
      buffer[len] = '\0';
    }

    if (len == 0) {
      continue;
    }

    debug("sending passphrase %s.\n", buffer);
    tried++;
    mq_send(queue, buffer, len+1, 1);
  }

  debug("Cleaning up\n");
  clock_gettime(CLOCK_MONOTONIC, &time_end);
  cleanup(workers, queue);
  printf("Tried %lu password in %lu seconds.\n", tried, time_end.tv_sec - time_start.tv_sec);
  printf("Rate : %lu password/second.\n", tried / (time_end.tv_sec - time_start.tv_sec + 1));
  return 0;
}
