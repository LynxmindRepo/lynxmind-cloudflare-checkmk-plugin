#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare CDN Cache Agent Based Check for CheckMK
Monitors Cloudflare CDN Cache metrics: cache level, requests, bandwidth, cache hit rate
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


def parse_cloudflare_cdn_cache(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_cdn_cache section"""
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
            # Split from the right to get zone name and metric name
            parts = rest.rsplit('.', 1)
            if len(parts) == 2:
                zone_name = parts[0]
                metric_name = parts[1]
                
                if zone_name not in parsed:
                    parsed[zone_name] = {}
                
                parsed[zone_name][metric_name] = value
    
    return parsed if parsed else None


agent_section_cloudflare_cdn_cache = AgentSection(
    name="cloudflare_cdn_cache",
    parse_function=parse_cloudflare_cdn_cache,
)


def discover_cloudflare_cdn_cache(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare CDN Cache zones"""
    if section is not None:
        for zone_name in section.keys():
            yield Service(item=zone_name)


def check_cloudflare_cdn_cache(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare CDN Cache metrics"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No CDN Cache data available")
        return
    
    if item not in section:
        yield Result(state=State.UNKNOWN, summary=f"Zone '{item}' not found")
        return
    
    zone_data = section[item]
    cache_level = zone_data.get('cache_level', 'unknown')
    
    # Validate cache_level and set state
    cache_level_state = State.OK
    if cache_level != 'unknown':
        cache_level_warn = params.get('cache_level_warn', 'none')
        cache_level_crit = params.get('cache_level_crit', 'off')
        
        if cache_level_crit != 'none' and cache_level == cache_level_crit:
            cache_level_state = State.CRIT
        elif cache_level_warn != 'none' and cache_level == cache_level_warn:
            cache_level_state = State.WARN
    
    # Get numeric metrics
    requests_total = None
    bandwidth_total = None
    cached_requests = None
    cache_hit_rate = None
    
    if 'requests_total' in zone_data and zone_data['requests_total']:
        try:
            requests_total = int(zone_data['requests_total'])
            if requests_total >= 0:  # Only create metric if value is valid
                # Apply threshold for requests total
                if 'requests_total' in params:
                    yield from check_levels(
                        requests_total,
                        levels_upper=params['requests_total'],
                        metric_name='cloudflare_requests_total',
                        label='Total Requests',
                    )
                else:
                    yield Metric('cloudflare_requests_total', requests_total)
        except (ValueError, TypeError):
            pass
    
    if 'bandwidth_total' in zone_data and zone_data['bandwidth_total']:
        try:
            bandwidth_total = int(zone_data['bandwidth_total'])
            if bandwidth_total >= 0:  # Only create metric if value is valid
                # Apply threshold for bandwidth total
                if 'bandwidth_total' in params:
                    yield from check_levels(
                        bandwidth_total,
                        levels_upper=params['bandwidth_total'],
                        metric_name='cloudflare_bandwidth_total',
                        label='Total Bandwidth',
                        render_func=render.bytes,
                    )
                else:
                    yield Metric('cloudflare_bandwidth_total', bandwidth_total)
        except (ValueError, TypeError):
            pass
    
    if 'cached_requests' in zone_data and zone_data['cached_requests']:
        try:
            cached_requests = int(zone_data['cached_requests'])
            if cached_requests >= 0:  # Only create metric if value is valid
                # Apply threshold for cached requests
                if 'cached_requests' in params:
                    yield from check_levels(
                        cached_requests,
                        levels_upper=params['cached_requests'],
                        metric_name='cloudflare_cached_requests',
                        label='Cached Requests',
                    )
                else:
                    yield Metric('cloudflare_cached_requests', cached_requests)
        except (ValueError, TypeError):
            pass
    
    if 'cache_hit_rate' in zone_data and zone_data['cache_hit_rate']:
        try:
            cache_hit_rate_str = zone_data['cache_hit_rate'].rstrip('%')
            cache_hit_rate = float(cache_hit_rate_str)
            if cache_hit_rate >= 0:  # Only create metric if value is valid
                # Apply threshold for cache hit rate (lower is worse)
                if 'cache_hit_rate' in params:
                    yield from check_levels(
                        cache_hit_rate,
                        levels_lower=params['cache_hit_rate'],
                        metric_name='cloudflare_cache_hit_rate',
                        label='Cache Hit Rate',
                        render_func=render.percent,
                    )
                else:
                    yield Metric('cloudflare_cache_hit_rate', cache_hit_rate)
        except (ValueError, TypeError):
            pass
    
    # Build summary
    summary_parts = [f"Cache level: {cache_level}"]
    
    # Check if we have any analytics data
    has_analytics = any([
        requests_total is not None,
        bandwidth_total is not None,
        cached_requests is not None,
        cache_hit_rate is not None
    ])
    
    if has_analytics:
        if requests_total is not None:
            try:
                requests_int = int(requests_total)
                summary_parts.append(f"Requests: {requests_int:,}")
            except (ValueError, TypeError):
                summary_parts.append(f"Requests: {requests_total}")
        if cache_hit_rate is not None:
            try:
                # Ensure cache_hit_rate is a number, not a string with %
                if isinstance(cache_hit_rate, str):
                    cache_hit_rate_float = float(cache_hit_rate.rstrip('%'))
                else:
                    cache_hit_rate_float = float(cache_hit_rate)
                summary_parts.append(f"Hit rate: {cache_hit_rate_float:.2f}%")
            except (ValueError, TypeError):
                # If conversion fails, just show the value as-is without %
                cache_hit_rate_str = str(cache_hit_rate).rstrip('%')
                summary_parts.append(f"Hit rate: {cache_hit_rate_str}%")
    else:
        # Check if analytics keys exist but are empty/zero
        analytics_keys = ['requests_total', 'bandwidth_total', 'cached_requests', 'cache_hit_rate']
        has_analytics_keys = any(key in zone_data for key in analytics_keys)
        
        if has_analytics_keys:
            # Keys exist but values might be 0 or empty
            summary_parts.append("(No analytics data - values may be 0)")
        else:
            # Analytics keys don't exist at all
            summary_parts.append("(Analytics not collected)")
    
    # Use the worst state between cache_level_state and OK
    yield Result(state=cache_level_state, summary=" | ".join(summary_parts))
    
    # Details
    details = []
    if bandwidth_total is not None:
        try:
            bandwidth_int = int(bandwidth_total)
            details.append(f"Bandwidth: {bandwidth_int:,} bytes")
        except (ValueError, TypeError):
            details.append(f"Bandwidth: {bandwidth_total} bytes")
    if cached_requests is not None:
        try:
            cached_int = int(cached_requests)
            details.append(f"Cached requests: {cached_int:,}")
        except (ValueError, TypeError):
            details.append(f"Cached requests: {cached_requests}")
    
    if details:
        yield Result(state=State.OK, notice=" | ".join(details))
    elif not has_analytics:
        # Show what data is available for debugging
        available_metrics = [k for k in zone_data.keys() if k != 'cache_level']
        if available_metrics:
            yield Result(
                state=State.OK, 
                notice=f"Analytics metrics not available. Available keys: {', '.join(available_metrics)}"
            )
        else:
            yield Result(
                state=State.OK, 
                notice="Analytics metrics (requests_total, bandwidth_total, cached_requests, cache_hit_rate) not available. Ensure --cdn-cache flag is used and analytics API returns data."
            )


check_plugin_cloudflare_cdn_cache = CheckPlugin(
    name="cloudflare_cdn_cache",
    sections=["cloudflare_cdn_cache"],
    service_name="Cloudflare CDN Cache %s",
    discovery_function=discover_cloudflare_cdn_cache,
    check_function=check_cloudflare_cdn_cache,
    check_ruleset_name="cloudflare_cdn_cache",
    check_default_parameters={},
)

