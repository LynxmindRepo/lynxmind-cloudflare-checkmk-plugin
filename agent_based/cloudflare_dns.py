#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare DNS Agent Based Check for CheckMK
Monitors Cloudflare DNS records: total records and counts by type
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


def parse_cloudflare_dns(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_dns section"""
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
            rest = key[5:]
            # Handle dns_records_total and dns_records_type.{type}
            # Format: zone.{zone}.dns_records_total or zone.{zone}.dns_records_type.{type}
            if '.dns_records_type.' in rest:
                # Format: zone.{zone}.dns_records_type.{type}
                idx = rest.find('.dns_records_type.')
                zone_name = rest[:idx]
                metric_name = rest[idx+1:]  # Keep 'dns_records_type.{type}'
            else:
                # Format: zone.{zone}.dns_records_total
                parts = rest.rsplit('.', 1)
                if len(parts) == 2:
                    zone_name = parts[0]
                    metric_name = parts[1]
                else:
                    continue
            
            if zone_name not in parsed:
                parsed[zone_name] = {}
            
            parsed[zone_name][metric_name] = value
    
    return parsed if parsed else None


agent_section_cloudflare_dns = AgentSection(
    name="cloudflare_dns",
    parse_function=parse_cloudflare_dns,
)


def discover_cloudflare_dns(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare DNS zones"""
    if section is not None:
        for zone_name in section.keys():
            yield Service(item=zone_name)


def check_cloudflare_dns(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare DNS records"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No DNS data available")
        return
    
    if item not in section:
        yield Result(state=State.UNKNOWN, summary=f"Zone '{item}' not found")
        return
    
    zone_data = section[item]
    dns_records_total = None
    
    if 'dns_records_total' in zone_data and zone_data['dns_records_total']:
        try:
            dns_records_total = int(zone_data['dns_records_total'])
            if dns_records_total >= 0:  # Only create metric if value is valid
                # Apply threshold for DNS records total
                if 'dns_records_total' in params:
                    yield from check_levels(
                        dns_records_total,
                        levels_upper=params['dns_records_total'],
                        metric_name='cloudflare_dns_records_total',
                        label='DNS Records Total',
                    )
                else:
                    yield Metric('cloudflare_dns_records_total', dns_records_total)
        except (ValueError, TypeError):
            pass
    
    # Get type counts and create metrics
    type_counts = {}
    for key, value in zone_data.items():
        if key.startswith('dns_records_type.'):
            record_type = key.replace('dns_records_type.', '')
            try:
                count = int(value)
                if count > 0:  # Only create metric if count is greater than 0
                    type_counts[record_type] = count
                    # Create metric for each record type (sanitize metric name)
                    metric_name = f'cloudflare_dns_records_type_{record_type.lower().replace("-", "_")}'
                    yield Metric(metric_name, count)
            except (ValueError, TypeError):
                pass
    
    # Build summary with more information
    summary_parts = []
    if dns_records_total is not None:
        try:
            dns_int = int(dns_records_total)
            summary_parts.append(f"Total: {dns_int:,}")
        except (ValueError, TypeError):
            summary_parts.append(f"Total: {dns_records_total}")
    
    # Add type counts to summary if available
    if type_counts:
        type_summary = ", ".join([f"{rtype}: {count}" for rtype, count in sorted(type_counts.items()) if count > 0])
        if type_summary:
            summary_parts.append(f"Types: {type_summary}")
    
    if summary_parts:
        yield Result(state=State.OK, summary=" | ".join(summary_parts))
    else:
        yield Result(state=State.OK, summary="DNS records: 0")
    
    # Additional details if we have more type information
    if type_counts and len(type_counts) > 3:
        details = []
        for rtype, count in sorted(type_counts.items()):
            try:
                count_int = int(count)
                details.append(f"{rtype}: {count_int:,}")
            except (ValueError, TypeError):
                details.append(f"{rtype}: {count}")
        if details:
            yield Result(state=State.OK, notice=" | ".join(details))


check_plugin_cloudflare_dns = CheckPlugin(
    name="cloudflare_dns",
    sections=["cloudflare_dns"],
    service_name="Cloudflare DNS %s",
    discovery_function=discover_cloudflare_dns,
    check_function=check_cloudflare_dns,
    check_ruleset_name="cloudflare_dns",
    check_default_parameters={},
)

