#include <errno.h>
#include <fcntl.h>
#include <gio/gio.h>
#include <gpgme.h>
#include <mqueue.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef DEBUG
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...)
#endif

#define MQNAME "/pgpcrack-mq-9e74305fffc8"

static unsigned int opt_fork = 1;

static GOptionEntry opt_entries[] =
{
  { "fork", 'f', 1, G_OPTION_ARG_INT, &opt_fork, "number of worker processus to fork", NULL},
  { NULL}
};

int init_options(int argc, char *argv[], gpgme_data_t *pgp_data) {
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

  if (gpgme_data_new_from_stream(pgp_data, pgp) != GPG_ERR_NO_ERROR) {
    g_printerr("Error creating data buffer, not enought memory.\n");
    return -1;
  }

  return 0;
}

int decipher(gpgme_data_t passphrase, gpgme_data_t data) {
  return -1;
}

int worker(gpgme_data_t pgp_data) {
  mqd_t queue;
  size_t buff_size = 8192;
  char buffer[buff_size+1];

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

    buffer[ret] = '\0';
    printf("Received passphrase : %s\n", buffer);
  }

  return 0;
}

void cleanup(pid_t *workers, mqd_t queue) {
  int child_ret;
  mq_close(queue);
  mq_unlink(MQNAME);
  for (int i = 0; i<opt_fork && workers[i] != 0; i++) {
    kill(workers[i], SIGTERM);
    if (waitpid(workers[i], &child_ret, 0) == -1 && errno == EINTR) {
      i--;
      continue;
    }

    debug("Child %d is dead.\n", workers[i]);
  }
}

int main(int argc, char *argv[]) {
  pid_t *workers = NULL;
  gpgme_data_t pgp_data;
  mqd_t queue;
  struct mq_attr attrs;

  if (init_options(argc, argv, &pgp_data) == -1) {
    return -1;
  }

  if ((workers = malloc(opt_fork*sizeof(pid_t))) == NULL) {
    perror("Error in malloc ");
    return -1;
  }

  mq_unlink(MQNAME);
  if ((queue = mq_open(MQNAME, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, NULL)) == -1) {
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
        exit(worker(pgp_data));
      case -1:
        perror("Error in fork ");
        cleanup(workers, queue);
        return -1;
      default:
        debug("New child worker with pid %d\n", ret);
        workers[i] = ret;
        break;
    }
  }

  sleep(4);
  printf("Cleaning up\n");
  cleanup(workers, queue);
  return 0;
}
