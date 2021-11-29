/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@coldchip.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README for more details.
 */

#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdbool.h>
#include "packet.h"
#include "list.h"

typedef enum {
	RULE_ALLOW,
	RULE_BLOCK
} VPNRuleMode;

typedef struct _VPNRule {
	ListNode node;
	uint32_t ip;
	uint32_t mask;
	VPNRuleMode mode;
} VPNRule;

VPNRule *chipvpn_firewall_new_rule(const char *cidr, VPNRuleMode mode);
bool chipvpn_firewall_add_rule(List *list, const char *cidr, VPNRuleMode mode);
bool chipvpn_firewall_match_rule(List *list, uint32_t ip);
void chipvpn_firewall_free_rule(VPNRule *rule);

#endif
