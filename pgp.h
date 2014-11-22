#ifndef PGP_H_
#define PGP_H_

#include <stdint.h>
#include <stdio.h>

#define ENC_BUFFER_SIZE 256

struct sym_algo {
  int gcry_equiv;
  uint8_t keysize;
  uint8_t blocksize;
  char *name;
};

struct hash_algo {
  int gcry_equiv;
  char *name;
};

extern struct hash_algo halgos[];
extern struct sym_algo algos[];

struct sym_enc_key {
  uint8_t version;
  uint8_t algorithm;
  uint8_t s2k_type;
};

struct s2k {
  uint8_t algorithm;
  unsigned char salt[8];
  uint8_t count;
};

struct pgp_data {
  struct sym_enc_key key_fmt;
  struct s2k s2k_fmt;
  uint32_t s2k_count;
  char enc_data[ENC_BUFFER_SIZE];
};

int parse_pgp(FILE *pgp, struct pgp_data *data);


#endif // PGP_H_
