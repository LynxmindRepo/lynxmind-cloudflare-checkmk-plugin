#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare SSL/TLS Agent Based Check for CheckMK
Monitors Cloudflare SSL/TLS status for zones
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
    StringTable,
)


def parse_cloudflare_ssl_tls(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_ssl_tls section"""
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
            # Format: zone.{zone}.ssl_status or zone.{zone}.ssl_status_alt
            parts = rest.rsplit('.', 1)
            if len(parts) == 2:
                zone_name = parts[0]
                metric_name = parts[1]
                
                if zone_name not in parsed:
                    parsed[zone_name] = {}
                
                parsed[zone_name][metric_name] = value
    
    return parsed if parsed else None


agent_section_cloudflare_ssl_tls = AgentSection(
    name="cloudflare_ssl_tls",
    parse_function=parse_cloudflare_ssl_tls,
)


def discover_cloudflare_ssl_tls(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare SSL/TLS zones"""
    if section is not None:
        for zone_name in section.keys():
            yield Service(item=zone_name)


def check_cloudflare_ssl_tls(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare SSL/TLS status"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No SSL/TLS data available")
        return
    
    if item not in section:
        yield Result(state=State.UNKNOWN, summary=f"Zone '{item}' not found")
        return
    
    zone_data = section[item]
    ssl_status = zone_data.get('ssl_status', 'unknown')
    
    # Determine state based on SSL status and params
    state = State.OK
    if ssl_status != 'unknown':
        ssl_status_warn = params.get('ssl_status_warn', 'flexible')
        ssl_status_crit = params.get('ssl_status_crit', 'off')
        
        if ssl_status_crit != 'none' and ssl_status == ssl_status_crit:
            state = State.CRIT
        elif ssl_status_warn != 'none' and ssl_status == ssl_status_warn:
            state = State.WARN
    elif ssl_status == 'unknown':
        state = State.UNKNOWN
    
    yield Result(state=state, summary=f"SSL status: {ssl_status}")
    
    # Additional SSL info
    if 'ssl_status_alt' in zone_data:
        yield Result(state=State.OK, notice=f"SSL status (alt): {zone_data['ssl_status_alt']}")


check_plugin_cloudflare_ssl_tls = CheckPlugin(
    name="cloudflare_ssl_tls",
    sections=["cloudflare_ssl_tls"],
    service_name="Cloudflare SSL/TLS %s",
    discovery_function=discover_cloudflare_ssl_tls,
    check_function=check_cloudflare_ssl_tls,
    check_ruleset_name="cloudflare_ssl_tls",
    check_default_parameters={},
)

