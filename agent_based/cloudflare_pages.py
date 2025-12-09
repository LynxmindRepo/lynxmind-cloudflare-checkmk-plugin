#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare Pages Agent Based Check for CheckMK
Monitors Cloudflare Pages projects: ID, branch, created_on
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


def parse_cloudflare_pages(string_table: StringTable) -> Optional[Dict[str, Any]]:
    """Parse cloudflare_pages section"""
    parsed: Dict[str, Any] = {'projects_total': 0, 'projects': {}}
    
    for line in string_table:
        if len(line) < 1:
            continue
        
        key_value = line[0].split('=', 1)
        if len(key_value) != 2:
            continue
        
        key, value = key_value[0].strip(), key_value[1].strip()
        
        if key == 'pages.projects_total':
            try:
                parsed['projects_total'] = int(value)
            except ValueError:
                pass
        elif key.startswith('pages.project.'):
            parts = key.split('.')
            if len(parts) >= 4:
                project_name = parts[2]
                metric_name = '.'.join(parts[3:])
                
                if project_name not in parsed['projects']:
                    parsed['projects'][project_name] = {}
                
                parsed['projects'][project_name][metric_name] = value
    
    return parsed if parsed else None


agent_section_cloudflare_pages = AgentSection(
    name="cloudflare_pages",
    parse_function=parse_cloudflare_pages,
)


def discover_cloudflare_pages(section: Optional[Dict[str, Any]]) -> DiscoveryResult:
    """Discover Cloudflare Pages projects"""
    if section is not None and 'projects' in section:
        for project_name in section['projects'].keys():
            yield Service(item=project_name)


def check_cloudflare_pages(
    item: str,
    params: Dict,
    section: Optional[Dict[str, Any]],
) -> CheckResult:
    """Check Cloudflare Pages project"""
    if section is None:
        yield Result(state=State.UNKNOWN, summary="No Pages data available")
        return
    
    if 'projects' not in section or item not in section['projects']:
        yield Result(state=State.UNKNOWN, summary=f"Project '{item}' not found")
        return
    
    project_data = section['projects'][item]
    project_id = project_data.get('id', 'unknown')
    created_on = project_data.get('created_on', 'unknown')
    production_branch = project_data.get('production_branch', 'unknown')
    latest_deployment_id = project_data.get('latest_deployment_id', '')
    latest_deployment_status = project_data.get('latest_deployment_status', '')
    domains_count = project_data.get('domains_count', None)
    build_command = project_data.get('build_command', '')
    
    # Create metric for domains count if available and valid
    if domains_count is not None and domains_count != '':
        try:
            domains_count_int = int(domains_count)
            if domains_count_int >= 0:  # Only create metric if value is valid
                yield Metric('cloudflare_pages_domains_count', domains_count_int)
        except (ValueError, TypeError):
            pass
    
    # Only create metric for projects_total if it exists in section
    if 'projects_total' in section:
        projects_total = section.get('projects_total', 0)
        if projects_total >= 0:  # Only create metric if value is valid
            # Apply threshold for projects total
            if 'projects_total' in params:
                yield from check_levels(
                    projects_total,
                    levels_upper=params['projects_total'],
                    metric_name='cloudflare_pages_projects_total',
                    label='Total Projects',
                )
            else:
                yield Metric('cloudflare_pages_projects_total', projects_total)
    
    # Build summary with more information
    summary_parts = [f"ID: {project_id}"]
    if production_branch != 'unknown':
        summary_parts.append(f"Branch: {production_branch}")
    if latest_deployment_status:
        summary_parts.append(f"Deploy: {latest_deployment_status}")
    if domains_count is not None:
        try:
            domains_count_int = int(domains_count)
            summary_parts.append(f"Domains: {domains_count_int}")
        except (ValueError, TypeError):
            pass
    
    yield Result(state=State.OK, summary=" | ".join(summary_parts))
    
    # Details
    details = []
    if created_on != 'unknown':
        details.append(f"Created: {created_on}")
    if latest_deployment_id:
        details.append(f"Latest Deploy: {latest_deployment_id}")
    if build_command:
        details.append(f"Build: {build_command}")
    
    if details:
        yield Result(state=State.OK, notice=" | ".join(details))


check_plugin_cloudflare_pages = CheckPlugin(
    name="cloudflare_pages",
    sections=["cloudflare_pages"],
    service_name="Cloudflare Pages %s",
    discovery_function=discover_cloudflare_pages,
    check_function=check_cloudflare_pages,
    check_ruleset_name="cloudflare_pages",
    check_default_parameters={},
)

