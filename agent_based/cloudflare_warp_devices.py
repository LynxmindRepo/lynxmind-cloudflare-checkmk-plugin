#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare WARP Devices Agent Based Check for CheckMK
Monitors Cloudflare WARP devices: name, platform, version, status, last_seen
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


def parse_cloudflare_warp_devices(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_warp_devices section"""
    parsed: Dict[str, Any] = {'devices_total': 0, 'devices': {}}
    
    for line in string_table:
        if len(line) < 1:
            continue
        
        key_value = line[0].split('=', 1)
        if len(key_value) != 2:
            continue
        
        key, value = key_value[0].strip(), key_value[1].strip()
        
        if key == 'warp.devices_total':
            try:
                parsed['devices_total'] = int(value)
            except ValueError:
                pass
        elif key.startswith('warp.device.'):
            parts = key.split('.')
            if len(parts) >= 4:
                device_id = parts[2]
                metric_name = '.'.join(parts[3:])
                
                if device_id not in parsed['devices']:
                    parsed['devices'][device_id] = {}
                
                parsed['devices'][device_id][metric_name] = value
    
    return parsed if parsed else None


agent_section_cloudflare_warp_devices = AgentSection(
    name="cloudflare_warp_devices",
    parse_function=parse_cloudflare_warp_devices,
)


def discover_cloudflare_warp_devices(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare WARP devices"""
    if section is not None and 'devices' in section:
        for device_id in section['devices'].keys():
            yield Service(item=device_id)


def check_cloudflare_warp_devices(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare WARP device"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No WARP devices data available")
        return
    
    if 'devices' not in section or item not in section['devices']:
        yield Result(state=State.UNKNOWN, summary=f"Device '{item}' not found")
        return
    
    device_data = section['devices'][item]
    device_name = device_data.get('name', 'unknown')
    platform = device_data.get('platform', 'unknown')
    version = device_data.get('version', 'unknown')
    status = device_data.get('status', 'unknown')
    last_seen = device_data.get('last_seen', '')
    
    # Determine state based on status and params
    device_state = State.OK
    if status != 'unknown':
        device_status_warn = params.get('device_status_warn', 'revoked')
        device_status_crit = params.get('device_status_crit', 'none')
        
        if device_status_crit != 'none' and status == device_status_crit:
            device_state = State.CRIT
        elif device_status_warn != 'none' and status == device_status_warn:
            device_state = State.WARN
    elif status == 'unknown':
        device_state = State.UNKNOWN
    
    # Build summary
    summary_parts = [f"Name: {device_name}"]
    if status != 'unknown':
        summary_parts.append(f"Status: {status}")
    
    yield Result(state=device_state, summary=" | ".join(summary_parts))
    
    # Details
    details = []
    if platform != 'unknown':
        details.append(f"Platform: {platform}")
    if version != 'unknown':
        details.append(f"Version: {version}")
    if last_seen:
        details.append(f"Last seen: {last_seen}")
    
    if details:
        yield Result(state=State.OK, notice=" | ".join(details))


check_plugin_cloudflare_warp_devices = CheckPlugin(
    name="cloudflare_warp_devices",
    sections=["cloudflare_warp_devices"],
    service_name="Cloudflare WARP Device %s",
    discovery_function=discover_cloudflare_warp_devices,
    check_function=check_cloudflare_warp_devices,
    check_ruleset_name="cloudflare_warp_devices",
    check_default_parameters={},
)

