#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare Firewall Agent Based Check for CheckMK
Monitors Cloudflare Firewall events: blocked, challenged, allowed
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


def parse_cloudflare_firewall(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_firewall section"""
    parsed: Dict[str, Any] = {}
    
    for line in string_table:
        if len(line) < 1:
            continue
        
        key_value = line[0].split('=', 1)
        if len(key_value) != 2:
            continue
        
        key, value = key_value[0].strip(), key_value[1].strip()
        
        if key.startswith('zone.'):
            # Remove 'zone.' prefix
            rest = key[5:]  # len('zone.') = 5
            # Split to get zone name and metric path
            parts = rest.split('.')
            if len(parts) >= 3 and parts[1] == 'firewall':
                zone_name = parts[0]
                metric_name = '.'.join(parts[2:])
                
                if zone_name not in parsed:
                    parsed[zone_name] = {}
                
                try:
                    parsed[zone_name][metric_name] = int(value)
                except ValueError:
                    parsed[zone_name][metric_name] = value
    
    return parsed if parsed else None


agent_section_cloudflare_firewall = AgentSection(
    name="cloudflare_firewall",
    parse_function=parse_cloudflare_firewall,
)


def discover_cloudflare_firewall(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare Firewall zones"""
    if section is not None:
        for zone_name in section.keys():
            yield Service(item=zone_name)


def check_cloudflare_firewall(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare Firewall metrics"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No Firewall data available")
        return
    
    if item not in section:
        yield Result(state=State.UNKNOWN, summary=f"Zone '{item}' not found")
        return
    
    zone_data = section[item]
    blocked_total = zone_data.get('blocked_total', 0)
    challenged_total = zone_data.get('challenged_total', 0)
    allowed_total = zone_data.get('allowed_total', 0)
    events_total = zone_data.get('events_total', 0)
    
    # Create metrics
    if isinstance(blocked_total, int) and blocked_total >= 0:
        if 'blocked_total' in params:
            yield from check_levels(
                blocked_total,
                levels_upper=params['blocked_total'],
                metric_name='cloudflare_firewall_blocked',
                label='Blocked',
            )
        else:
            yield Metric('cloudflare_firewall_blocked', blocked_total)
    
    if isinstance(challenged_total, int) and challenged_total >= 0:
        if 'challenged_total' in params:
            yield from check_levels(
                challenged_total,
                levels_upper=params['challenged_total'],
                metric_name='cloudflare_firewall_challenged',
                label='Challenged',
            )
        else:
            yield Metric('cloudflare_firewall_challenged', challenged_total)
    
    if isinstance(allowed_total, int) and allowed_total >= 0:
        yield Metric('cloudflare_firewall_allowed', allowed_total)
    
    if isinstance(events_total, int) and events_total >= 0:
        yield Metric('cloudflare_firewall_events_total', events_total)
    
    # Build summary
    summary_parts = []
    if events_total > 0:
        summary_parts.append(f"Events: {events_total}")
    if blocked_total > 0:
        summary_parts.append(f"Blocked: {blocked_total}")
    if challenged_total > 0:
        summary_parts.append(f"Challenged: {challenged_total}")
    if allowed_total > 0:
        summary_parts.append(f"Allowed: {allowed_total}")
    
    if not summary_parts:
        summary_parts.append("No firewall events")
    
    yield Result(state=State.OK, summary=" | ".join(summary_parts))
    
    # Details
    details = []
    if blocked_total > 0 or challenged_total > 0:
        details.append(f"Blocked: {blocked_total}, Challenged: {challenged_total}")
    if allowed_total > 0:
        details.append(f"Allowed: {allowed_total}")
    
    if details:
        yield Result(state=State.OK, notice=" | ".join(details))


check_plugin_cloudflare_firewall = CheckPlugin(
    name="cloudflare_firewall",
    sections=["cloudflare_firewall"],
    service_name="Cloudflare Firewall %s",
    discovery_function=discover_cloudflare_firewall,
    check_function=check_cloudflare_firewall,
    check_ruleset_name="cloudflare_firewall",
    check_default_parameters={},
)

