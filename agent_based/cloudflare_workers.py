#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare Workers Agent Based Check for CheckMK
Monitors Cloudflare Workers: ID, created_on, modified_on
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


def parse_cloudflare_workers(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_workers section"""
    parsed: Dict[str, Any] = {}
    
    for line in string_table:
        if len(line) < 1:
            continue
        
        key_value = line[0].split('=', 1)
        if len(key_value) != 2:
            continue
        
        key, value = key_value[0].strip(), key_value[1].strip()
        
        if key.startswith('worker.'):
            parts = key.split('.')
            if len(parts) >= 3:
                worker_name = parts[1]
                metric_name = '.'.join(parts[2:])
                
                if worker_name not in parsed:
                    parsed[worker_name] = {}
                
                parsed[worker_name][metric_name] = value
    
    return parsed if parsed else None


agent_section_cloudflare_workers = AgentSection(
    name="cloudflare_workers",
    parse_function=parse_cloudflare_workers,
)


def discover_cloudflare_workers(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare Workers"""
    if section is not None:
        for worker_name in section.keys():
            yield Service(item=worker_name)


def check_cloudflare_workers(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare Worker"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No Workers data available")
        return
    
    if item not in section:
        yield Result(state=State.UNKNOWN, summary=f"Worker '{item}' not found")
        return
    
    worker_data = section[item]
    worker_id = worker_data.get('id', item)
    created_on = worker_data.get('created_on', 'unknown')
    modified_on = worker_data.get('modified_on', 'unknown')
    usage_model = worker_data.get('usage_model', '')
    etag = worker_data.get('etag', '')
    
    # Build summary with more information
    summary_parts = [f"ID: {worker_id}"]
    if usage_model:
        summary_parts.append(f"Usage: {usage_model}")
    
    # Add dates to summary if available
    if created_on != 'unknown':
        summary_parts.append(f"Created: {created_on}")
    
    yield Result(state=State.OK, summary=" | ".join(summary_parts))
    
    # Details
    details = []
    if modified_on != 'unknown':
        details.append(f"Modified: {modified_on}")
    if etag:
        details.append(f"ETag: {etag}")
    
    if details:
        yield Result(state=State.OK, notice=" | ".join(details))


check_plugin_cloudflare_workers = CheckPlugin(
    name="cloudflare_workers",
    sections=["cloudflare_workers"],
    service_name="Cloudflare Worker %s",
    discovery_function=discover_cloudflare_workers,
    check_function=check_cloudflare_workers,
    check_ruleset_name="cloudflare_workers",
    check_default_parameters={},
)

