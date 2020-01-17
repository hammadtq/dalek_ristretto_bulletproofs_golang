// skip include guards
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

extern int generate(char* slice, size_t len);

void generate_ristretto_random(char* slice, size_t len);

void generate_ristretto_range_proof(const uint64_t *vals,
                                    size_t vals_len,
                                    uint8_t *proof_buf,
                                    size_t proof_buf_len,
                                    uint8_t *commitments,
                                    size_t commitments_len);

bool verify_ristretto_range_proof(const uint8_t *proof_buf,
                                  size_t proof_buf_len,
                                  const uint8_t *commitments,
                                  size_t commitments_len);