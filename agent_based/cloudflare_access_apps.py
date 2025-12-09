#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare Access Apps Agent Based Check for CheckMK
Monitors Cloudflare Access Applications: name, domain, type, policies, destinations, idps
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


def parse_cloudflare_access_apps(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_access_apps section"""
    parsed: Dict[str, Any] = {'apps_total': 0, 'apps': {}}
    
    for line in string_table:
        if len(line) < 1:
            continue
        
        key_value = line[0].split('=', 1)
        if len(key_value) != 2:
            continue
        
        key, value = key_value[0].strip(), key_value[1].strip()
        
        if key == 'access.apps_total':
            try:
                parsed['apps_total'] = int(value)
            except ValueError:
                pass
        elif key.startswith('access.app.'):
            parts = key.split('.')
            if len(parts) >= 4:
                app_id = parts[2]
                metric_name = '.'.join(parts[3:])
                
                if app_id not in parsed['apps']:
                    parsed['apps'][app_id] = {}
                
                parsed['apps'][app_id][metric_name] = value
    
    return parsed if parsed else None


agent_section_cloudflare_access_apps = AgentSection(
    name="cloudflare_access_apps",
    parse_function=parse_cloudflare_access_apps,
)


def discover_cloudflare_access_apps(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare Access Applications"""
    if section is not None and 'apps' in section:
        for app_id in section['apps'].keys():
            yield Service(item=app_id)


def check_cloudflare_access_apps(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare Access Application"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No Access Apps data available")
        return
    
    if 'apps' not in section or item not in section['apps']:
        yield Result(state=State.UNKNOWN, summary=f"App '{item}' not found")
        return
    
    app_data = section['apps'][item]
    app_name = app_data.get('name', 'unknown')
    domain = app_data.get('domain', 'unknown')
    app_type = app_data.get('type', 'unknown')
    updated_at = app_data.get('updated_at', '')
    
    # Get numeric metrics
    policies_count = None
    destinations_count = None
    idps_count = None
    
    if 'policies_count' in app_data and app_data['policies_count']:
        try:
            policies_count = int(app_data['policies_count'])
            if policies_count >= 0:
                if 'policies_count' in params:
                    yield from check_levels(
                        policies_count,
                        levels_upper=params['policies_count'],
                        metric_name='cloudflare_access_policies_count',
                        label='Policies Count',
                    )
                else:
                    yield Metric('cloudflare_access_policies_count', policies_count)
        except (ValueError, TypeError):
            pass
    
    if 'destinations_count' in app_data and app_data['destinations_count']:
        try:
            destinations_count = int(app_data['destinations_count'])
            if destinations_count >= 0:
                if 'destinations_count' in params:
                    yield from check_levels(
                        destinations_count,
                        levels_upper=params['destinations_count'],
                        metric_name='cloudflare_access_destinations_count',
                        label='Destinations Count',
                    )
                else:
                    yield Metric('cloudflare_access_destinations_count', destinations_count)
        except (ValueError, TypeError):
            pass
    
    if 'idps_count' in app_data and app_data['idps_count']:
        try:
            idps_count = int(app_data['idps_count'])
            if idps_count >= 0:
                if 'idps_count' in params:
                    yield from check_levels(
                        idps_count,
                        levels_upper=params['idps_count'],
                        metric_name='cloudflare_access_idps_count',
                        label='IDPs Count',
                    )
                else:
                    yield Metric('cloudflare_access_idps_count', idps_count)
        except (ValueError, TypeError):
            pass
    
    # Build summary
    summary_parts = [f"Name: {app_name}"]
    if domain != 'unknown':
        summary_parts.append(f"Domain: {domain}")
    if app_type != 'unknown':
        summary_parts.append(f"Type: {app_type}")
    
    yield Result(state=State.OK, summary=" | ".join(summary_parts))
    
    # Details
    details = []
    if policies_count is not None:
        details.append(f"Policies: {policies_count}")
    if destinations_count is not None:
        details.append(f"Destinations: {destinations_count}")
    if idps_count is not None:
        details.append(f"IDPs: {idps_count}")
    if updated_at:
        details.append(f"Updated: {updated_at}")
    
    if details:
        yield Result(state=State.OK, notice=" | ".join(details))


check_plugin_cloudflare_access_apps = CheckPlugin(
    name="cloudflare_access_apps",
    sections=["cloudflare_access_apps"],
    service_name="Cloudflare Access App %s",
    discovery_function=discover_cloudflare_access_apps,
    check_function=check_cloudflare_access_apps,
    check_ruleset_name="cloudflare_access_apps",
    check_default_parameters={},
)

