#include <gcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "pgp.h"

#ifdef DEBUG
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...)
#endif

#define B7 0x80
#define B6 0x40
#define B5 0x20
#define B4 0x10
#define B3 0x08
#define B2 0x04
#define B1 0x02
#define B0 0x01

#define NEW_TAG(head) head & ~(B7 | B6)
#define OLD_TAG(head) (head & ~(B7 | B6)) >> 2
#define LENGTH_TYPE(head) (head & (B0 | B1))

#define SYM_KEY_ENC_KEY 3
#define SYM_KEY_ENC_DATA 9
#define LITERAL 11
#define SYM_KEY_ENC_MDC_DATA 18

struct sym_algo algos[] = {
  {GCRY_CIPHER_NONE, 0, 0, "Plaintext"},
  {GCRY_CIPHER_IDEA, 16, 8, "IDEA"},
  {GCRY_CIPHER_3DES, 24, 8, "TripleDES"},
  {GCRY_CIPHER_CAST5, 16, 8, "CAST5"},
  {GCRY_CIPHER_BLOWFISH, 16, 8, "Blowfish"},
  {GCRY_CIPHER_SAFER_SK128, 16, 8, "Reserved"},
  {GCRY_CIPHER_DES_SK, 0, 0, "Reserved"},
  {GCRY_CIPHER_AES128, 16, 16, "AES 128"},
  {GCRY_CIPHER_AES192, 24, 16, "AES 192"},
  {GCRY_CIPHER_AES256, 32, 16, "AES 256"},
  {GCRY_CIPHER_TWOFISH, 32, 16, "Twofish"},
};

struct hash_algo halgos[] = {
  {GCRY_MD_NONE, "None"},
  {GCRY_MD_MD5, "MD5"},
  {GCRY_MD_SHA1, "SHA1"},
  {GCRY_MD_RMD160, "RIPEMD160"},
  {-1, "Reserved"},
  {-1, "Reserved"},
  {-1, "Reserved"},
  {-1, "Reserved"},
  {GCRY_MD_SHA256, "SHA256"},
  {GCRY_MD_SHA384, "SHA384"},
  {GCRY_MD_SHA512, "SHA512"},
  {GCRY_MD_SHA224, "SHA224"},
};

ssize_t get_new_length(FILE *pgp) {
  uint32_t len = 0;
  uint32_t l2;
  if (fread(&len, 1, 1, pgp) != 1) {
    perror("Error reading old packet length from pgp file ");
    return -1;
  }

  debug("First length byte is %u.\n", len);
  if (len >= 192 && len < 224) {
    fread(&l2, 1, 1, pgp);
    len = ((len - 192) << 8 ) + l2 + 192;
  } else if (len >= 224 && len < 255) {
    // We don't care about the whole packet, the first part is enough for
    // our needs. (I hope.)
    len = 1 << (len & 0x1f);
  } else if (len == 255) {
    fread(&l2, 4, 1, pgp);
    len = l2;
  }

  return len;
}

ssize_t get_old_length(uint8_t head, FILE *pgp) {
  uint32_t len = 0;
  if (LENGTH_TYPE(head) == 3) {
    fprintf(stderr, "Error, unsupported indeterminate length in pgp packet\n");
    return -1;
  }

  if (fread(&len, 1 << LENGTH_TYPE(head), 1, pgp) != 1) {
    perror("Error reading old packet length from pgp file ");
    return -1;
  }

  return len;
}

int get_tag_and_length(uint8_t head, FILE *pgp, uint8_t *tag, uint32_t *length) {
  if (head & B6) {
    *tag = NEW_TAG(head);
    if (((*length) = get_new_length(pgp)) == -1) {
      return -1;
    }
  } else {
    *tag = OLD_TAG(head);
    if (((*length) = get_old_length(head, pgp)) == -1) {
      return -1;
    }
  }

  return 0;
}

int parse_packets(FILE *pgp, uint8_t head, struct pgp_data *data) {
  uint8_t tag = 0;
  uint32_t length = 0;

  if (get_tag_and_length(head, pgp, &tag, &length) == -1) {
    return -1;
  }

  switch (tag) {
    case LITERAL:
      debug("Literal data packet, skipping.\n");
      break;
    case SYM_KEY_ENC_KEY:
      debug("Symmetrically encrypted key packet, reading 0x%x bytes, %lu, %lu\n",
            length, sizeof(struct s2k), sizeof(struct sym_enc_key));
      if (fread(&data->key_fmt, sizeof(struct sym_enc_key), 1, pgp) != 1) {
        perror("Error reading key spec from pgp file ");
        return -1;
      } else if (data->key_fmt.version != 4) {
        fprintf(stderr, "Error, unsupported symmetric key format version : %hhu",
                data->key_fmt.version);
        return -1;
      } else if (data->key_fmt.s2k_type != 3) {
        fprintf(stderr, "Error, only iterated and salted s2k are supported\n");
        return -1;
      }

      length -= sizeof(struct sym_enc_key);
      if (length < 0) {
        fprintf(stderr,
                "Error, symmetrically encrypted key packet is bigger than packet length.\n");
        return -1;
      }

      if (data->key_fmt.algorithm == 5 || data->key_fmt.algorithm == 6) {
        fprintf(stderr, "Error, unsupported reserved algorithm number : %hhu.\n",
                data->key_fmt.algorithm);
        return -1;
      }

      if (fread(&data->s2k_fmt, sizeof(struct s2k), 1, pgp) != 1) {
        perror("Error reading s2k spec from pgp file ");
        return -1;
      }

      length -= sizeof(struct s2k);
      if (length != 0) {
        fprintf(stderr, "Error, invalid symmetrically encrypted key packet size.\n");
        return -1;
      }

      if (data->s2k_fmt.algorithm == 0 || data->key_fmt.algorithm == 4 ||
          data->key_fmt.algorithm == 5 || data->key_fmt.algorithm == 6 ||
          data->key_fmt.algorithm == 7) {
        fprintf(stderr, "Error, unsupported reserved algorithm number : %hhu.\n",
                data->key_fmt.algorithm);
        return -1;
      }

      data->s2k_count = 16 + (data->s2k_fmt.count & 15);
      data->s2k_count = data->s2k_count << ((data->s2k_fmt.count >> 4) + 6);
      break;
    case SYM_KEY_ENC_MDC_DATA:
      debug("Symmetrically encrypted data and mdc packet. Reading 0x%x bytes.\n", length);
      if (length > ENC_BUFFER_SIZE) {
        fprintf(stderr, "Error, unsupported (too big) packet size %u.\n", length);
        return -1;
      }

      if (fread(&data->enc_data, length, 1, pgp) != 1) {
        fprintf(stderr, "Error, unexpected end of pgp file before end of data packet.\n");
        return -1;
      }

      return 1; // We shouldn't need any more than that to bruteforce.
    default:
      fprintf(stderr, "Error, unsupported tag %u\n", tag);
      return -1;
  }

  return 0;
}

int parse_pgp(FILE *pgp, struct pgp_data *data) {

  memset(&data->key_fmt, 0, sizeof(struct sym_enc_key));
  memset(&data->s2k_fmt, 0, sizeof(struct s2k));

  while (1) {
    uint8_t head = 0x0;
    if (fread(&head, 1, 1, pgp) != 1) {
      perror("Error reading from pgp file ");
      return -1;
    }

    debug("header byte : %x\n", head);
    if ((head & B7) == 0) {
      fprintf(stderr, "Error, not an OpenPGP file");
      return -1;
    }

    switch(parse_packets(pgp, head, data)) {
      case -1:
        return -1;
      case 1:
        return 0;
    }
  }

  return 0;
}


