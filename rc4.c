#include <stdlib.h>
#include <assert.h>
#include "rc4.h"

struct rc4_state {
    uint8_t s[256];
    int i;
    int j;
};

static inline void swap(uint8_t *array, int i, int j) {
    uint8_t tmp;

    tmp = array[i];
    array[i] = array[j];
    array[j] = tmp;
}

static uint8_t rc4_generatekey(rc4_state_t *state) {
    state->i = (state->i + 1) & 0xff;
    state->j = (state->j + state->s[state->i]) & 0xff;

    swap(state->s, state->i, state->j);

    return state->s[(state->s[state->i] + state->s[state->j]) & 0xff];
}

void rc4_crypt(rc4_state_t *state, uint8_t *buf, int buflen) {
    int i;
    uint8_t key;

    for (i = 0; i < buflen; i++) {
        key = rc4_generatekey(state);
        buf[i] ^= key;
    }
}

void rc4_init(rc4_state_t *state, uint8_t *key, int keysize) {
    int i, j;

    assert(state);
    assert(key);

    state->i = 0;
    state->j = 0;

    for (i = 0; i < 256; i++) {
        state->s[i] = i;
    }

    for (i = j = 0; i < 256; i++) {
        j = (j + state->s[i] + key[i % keysize]) & 0xff;

        swap(state->s, i, j);
    }
}

rc4_state_t *rc4_create(uint8_t *key, int keysize) {
    rc4_state_t *state = NULL;

    state = malloc(sizeof(rc4_state_t));
    if (NULL == state) {
        return NULL;
    }

    rc4_init(state, key, keysize);

    return state;
}

void rc4_destroy(rc4_state_t *state) {
    free(state);
}
