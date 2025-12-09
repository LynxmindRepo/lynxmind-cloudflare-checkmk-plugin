#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare Secrets Agent Based Check for CheckMK
Monitors Cloudflare Secrets stores: ID, secrets count
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


def parse_cloudflare_secrets(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_secrets section"""
    parsed: Dict[str, Any] = {'stores_total': 0, 'stores': {}}
    
    for line in string_table:
        if len(line) < 1:
            continue
        
        key_value = line[0].split('=', 1)
        if len(key_value) != 2:
            continue
        
        key, value = key_value[0].strip(), key_value[1].strip()
        
        if key == 'secrets.stores_total':
            try:
                parsed['stores_total'] = int(value)
            except ValueError:
                pass
        elif key.startswith('secrets.store.'):
            parts = key.split('.')
            if len(parts) >= 4:
                store_name = parts[2]
                metric_name = '.'.join(parts[3:])
                
                if store_name not in parsed['stores']:
                    parsed['stores'][store_name] = {}
                
                parsed['stores'][store_name][metric_name] = value
    
    return parsed if parsed else None


agent_section_cloudflare_secrets = AgentSection(
    name="cloudflare_secrets",
    parse_function=parse_cloudflare_secrets,
)


def discover_cloudflare_secrets(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare Secrets stores"""
    if section is not None and 'stores' in section:
        for store_name in section['stores'].keys():
            yield Service(item=store_name)


def check_cloudflare_secrets(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare Secrets store"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No Secrets data available")
        return
    
    if 'stores' not in section or item not in section['stores']:
        yield Result(state=State.UNKNOWN, summary=f"Store '{item}' not found")
        return
    
    store_data = section['stores'][item]
    store_id = store_data.get('id', 'unknown')
    secrets_count = None
    
    if 'secrets_count' in store_data and store_data['secrets_count']:
        try:
            secrets_count = int(store_data['secrets_count'])
            if secrets_count >= 0:  # Only create metric if value is valid
                # Apply threshold for secrets count
                if 'secrets_count' in params:
                    yield from check_levels(
                        secrets_count,
                        levels_upper=params['secrets_count'],
                        metric_name='cloudflare_secrets_count',
                        label='Secrets Count',
                    )
                else:
                    yield Metric('cloudflare_secrets_count', secrets_count)
        except (ValueError, TypeError):
            pass
    
    # Only create metric for stores_total if it exists in section
    if 'stores_total' in section:
        stores_total = section.get('stores_total', 0)
        if stores_total >= 0:  # Only create metric if value is valid
            # Apply threshold for stores total
            if 'stores_total' in params:
                yield from check_levels(
                    stores_total,
                    levels_upper=params['stores_total'],
                    metric_name='cloudflare_secrets_stores_total',
                    label='Total Stores',
                )
            else:
                yield Metric('cloudflare_secrets_stores_total', stores_total)
    
    # Build summary with more information
    summary_parts = [f"Store ID: {store_id}"]
    if secrets_count is not None:
        try:
            secrets_int = int(secrets_count)
            summary_parts.append(f"Secrets: {secrets_int:,}")
        except (ValueError, TypeError):
            summary_parts.append(f"Secrets: {secrets_count}")
    
    yield Result(state=State.OK, summary=" | ".join(summary_parts))


check_plugin_cloudflare_secrets = CheckPlugin(
    name="cloudflare_secrets",
    sections=["cloudflare_secrets"],
    service_name="Cloudflare Secrets %s",
    discovery_function=discover_cloudflare_secrets,
    check_function=check_cloudflare_secrets,
    check_ruleset_name="cloudflare_secrets",
    check_default_parameters={},
)

