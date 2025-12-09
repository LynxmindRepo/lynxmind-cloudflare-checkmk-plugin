#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare D1 Agent Based Check for CheckMK
Monitors Cloudflare D1 databases: UUID, size
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
    render,
)


def parse_cloudflare_d1(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_d1 section"""
    parsed: Dict[str, Any] = {'databases_total': 0, 'databases': {}}
    
    for line in string_table:
        if len(line) < 1:
            continue
        
        key_value = line[0].split('=', 1)
        if len(key_value) != 2:
            continue
        
        key, value = key_value[0].strip(), key_value[1].strip()
        
        if key == 'd1.databases_total':
            try:
                parsed['databases_total'] = int(value)
            except ValueError:
                pass
        elif key.startswith('d1.db.'):
            parts = key.split('.')
            if len(parts) >= 4:
                db_name = parts[2]
                metric_name = '.'.join(parts[3:])
                
                if db_name not in parsed['databases']:
                    parsed['databases'][db_name] = {}
                
                parsed['databases'][db_name][metric_name] = value
    
    return parsed if parsed else None


agent_section_cloudflare_d1 = AgentSection(
    name="cloudflare_d1",
    parse_function=parse_cloudflare_d1,
)


def discover_cloudflare_d1(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare D1 databases"""
    if section is not None and 'databases' in section:
        for db_name in section['databases'].keys():
            yield Service(item=db_name)


def check_cloudflare_d1(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare D1 database"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No D1 data available")
        return
    
    if 'databases' not in section or item not in section['databases']:
        yield Result(state=State.UNKNOWN, summary=f"Database '{item}' not found")
        return
    
    db_data = section['databases'][item]
    db_uuid = db_data.get('uuid', 'unknown')
    db_size = None
    db_created_at = db_data.get('created_at', '')
    db_version = db_data.get('version', '')
    
    if 'size' in db_data and db_data['size']:
        try:
            db_size = int(db_data['size'])
            if db_size >= 0:  # Only create metric if size is valid (>= 0)
                # Apply threshold for D1 size
                if 'd1_size' in params:
                    yield from check_levels(
                        db_size,
                        levels_upper=params['d1_size'],
                        metric_name='cloudflare_d1_size',
                        label='D1 Size',
                        render_func=render.bytes,
                    )
                else:
                    yield Metric('cloudflare_d1_size', db_size)
        except (ValueError, TypeError):
            pass
    
    # Only create metric for databases_total if it exists in section
    if 'databases_total' in section:
        databases_total = section.get('databases_total', 0)
        if databases_total >= 0:  # Only create metric if value is valid
            # Apply threshold for total databases
            if 'databases_total' in params:
                yield from check_levels(
                    databases_total,
                    levels_upper=params['databases_total'],
                    metric_name='cloudflare_d1_databases_total',
                    label='Total Databases',
                )
            else:
                yield Metric('cloudflare_d1_databases_total', databases_total)
    
    # Build summary with more information
    summary_parts = [f"UUID: {db_uuid}"]
    if db_size is not None:
        summary_parts.append(f"Size: {render.bytes(db_size)}")
    if db_version:
        summary_parts.append(f"Version: {db_version}")
    
    yield Result(state=State.OK, summary=" | ".join(summary_parts))
    
    # Details
    details = []
    if db_created_at:
        details.append(f"Created: {db_created_at}")
    
    if details:
        yield Result(state=State.OK, notice=" | ".join(details))


check_plugin_cloudflare_d1 = CheckPlugin(
    name="cloudflare_d1",
    sections=["cloudflare_d1"],
    service_name="Cloudflare D1 %s",
    discovery_function=discover_cloudflare_d1,
    check_function=check_cloudflare_d1,
    check_ruleset_name="cloudflare_d1",
    check_default_parameters={},
)

