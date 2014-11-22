#ifndef PGP_H_
#define PGP_H_

#include <stdint.h>
#include <stdio.h>

#define ENC_BUFFER_SIZE 8196
struct sym_enc_key {
  uint8_t version;
  uint8_t algorithm;
  uint8_t s2k_type;
};

struct s2k {
  uint8_t hash_alg;
  char salt[8];
  uint8_t count;
};


struct pgp_data {
  struct sym_enc_key key_fmt;
  struct s2k s2k_fmt;
  char enc_data[ENC_BUFFER_SIZE];
};

int parse_pgp(FILE *pgp, struct pgp_data *data);


#endif // PGP_H_
