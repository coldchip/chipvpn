#include "chipvpn.h"

void pow_mod_faster(struct bn* a, struct bn* b, struct bn* n, struct bn* res) {
  bignum_from_int(res, 1); /* r = 1 */

  struct bn tmpa;
  struct bn tmpb;
  struct bn tmp;
  bignum_assign(&tmpa, a);
  bignum_assign(&tmpb, b);

  while (1)
  {
    if (tmpb.array[0] & 1)     /* if (b % 2) */
    {
      bignum_mul(res, &tmpa, &tmp);  /*   r = r * a % m */
      bignum_mod(&tmp, n, res);
    }
    bignum_rshift(&tmpb, &tmp, 1); /* b /= 2 */
    bignum_assign(&tmpb, &tmp);

    if (bignum_is_zero(&tmpb))
      break;

    bignum_mul(&tmpa, &tmpa, &tmp);
    bignum_mod(&tmp, n, &tmpa);
  }
}