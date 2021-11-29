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

#include "chipvpn.h"
#include "firewall.h"
#include "packet.h"
#include <stdbool.h>
#include <stdlib.h>

VPNRule *chipvpn_firewall_new_rule(const char *cidr, VPNRuleMode mode) {
	uint32_t ip, mask;
	if(cidr_to_ip_and_mask(cidr, &ip, &mask)) {
		VPNRule *rule = malloc(sizeof(VPNRule));
		rule->ip     = ip;
		rule->mask   = mask;
		rule->mode   = mode;
		return rule;
	}
	return NULL;
}

bool chipvpn_firewall_add_rule(List *list, const char *cidr, VPNRuleMode mode) {
	VPNRule *rule = chipvpn_firewall_new_rule(cidr, mode);
	if(rule) {
		list_insert(list_end(list), rule);
		return true;
	}
	return false;
}

bool chipvpn_firewall_match_rule(List *list, uint32_t ip) {
	bool result = false;
	for(ListNode *i = list_begin(list); i != list_end(list); i = list_next(i)) {
		VPNRule *rule = (VPNRule*)i;
		uint32_t start = rule->ip & rule->mask;
		uint32_t end   = rule->ip | ~rule->mask;
		if(ip >= start && ip <= end) {
			if(rule->mode == RULE_ALLOW) {
				result = true;
			} else {
				result = false;
			}
		}
	}
	return result;
}

void chipvpn_firewall_free_rule(VPNRule *rule) {
	free(rule);
}