#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare Gateway Agent Based Check for CheckMK
Monitors Cloudflare Gateway: account provider, tag, rules
"""

from typing import Dict, Optional, Any
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    Service,
    State,
    Metric,
    StringTable,
    check_levels,
)


def parse_cloudflare_gateway(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_gateway section"""
    parsed: Dict[str, Any] = {'account': {}, 'rules': {}}
    
    for line in string_table:
        if len(line) < 1:
            continue
        
        key_value = line[0].split('=', 1)
        if len(key_value) != 2:
            continue
        
        key, value = key_value[0].strip(), key_value[1].strip()
        
        if key.startswith('gateway.account.'):
            metric_name = key.replace('gateway.account.', '')
            parsed['account'][metric_name] = value
        elif key.startswith('gateway.rules_total'):
            try:
                parsed['rules_total'] = int(value)
            except ValueError:
                pass
        elif key.startswith('gateway.rules_action.'):
            action = key.replace('gateway.rules_action.', '')
            try:
                parsed['rules'][action] = int(value)
            except ValueError:
                pass
    
    return parsed if parsed else None


agent_section_cloudflare_gateway = AgentSection(
    name="cloudflare_gateway",
    parse_function=parse_cloudflare_gateway,
)


def discover_cloudflare_gateway(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare Gateway"""
    if section is not None:
        yield Service(item="gateway")


def check_cloudflare_gateway(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare Gateway"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No Gateway data available")
        return
    
    # Account information
    account_data = section.get('account', {})
    provider = account_data.get('provider', 'unknown')
    tag = account_data.get('tag', 'unknown')
    
    # Rules information
    rules_total = section.get('rules_total', 0)
    rules_data = section.get('rules', {})
    
    # Create metrics for rules
    if rules_total >= 0:
        if 'rules_total' in params:
            yield from check_levels(
                rules_total,
                levels_upper=params['rules_total'],
                metric_name='cloudflare_gateway_rules_total',
                label='Total Rules',
            )
        else:
            yield Metric('cloudflare_gateway_rules_total', rules_total)
    
    # Build summary
    summary_parts = []
    if provider != 'unknown':
        summary_parts.append(f"Provider: {provider}")
    if tag != 'unknown':
        summary_parts.append(f"Tag: {tag}")
    if rules_total > 0:
        summary_parts.append(f"Rules: {rules_total}")
    
    if not summary_parts:
        summary_parts.append("Gateway configured")
    
    yield Result(state=State.OK, summary=" | ".join(summary_parts))
    
    # Details - rules by action
    details = []
    if rules_data:
        for action, count in rules_data.items():
            details.append(f"{action.capitalize()}: {count}")
            # Create metrics for each action type
            if count >= 0:
                metric_name = f'cloudflare_gateway_rules_{action}'
                yield Metric(metric_name, count)
    
    if details:
        yield Result(state=State.OK, notice=" | ".join(details))


check_plugin_cloudflare_gateway = CheckPlugin(
    name="cloudflare_gateway",
    sections=["cloudflare_gateway"],
    service_name="Cloudflare Gateway %s",
    discovery_function=discover_cloudflare_gateway,
    check_function=check_cloudflare_gateway,
    check_ruleset_name="cloudflare_gateway",
    check_default_parameters={},
)

