#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

from collections.abc import Iterator
from pydantic import BaseModel, validator

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)

class Params(BaseModel):
    """params validator"""
    email: str
    api_token: Secret
    timeout: int | None = None
    cdn_cache: bool | None = None
    dns: bool | None = None
    ssl_tls: bool | None = None
    firewall: bool | None = None
    workers_pages: bool | None = None
    d1: bool | None = None
    secrets: bool | None = None
    fetch_all: bool | None = None
    verbose: bool | None = None
    
    @validator('timeout', pre=True)
    def validate_timeout(cls, v):
        if v is None:
            return None
        if isinstance(v, (int, float)) and (v <= 0 or v > 300):
            raise ValueError('Timeout must be between 1 and 300 seconds')
        return int(v) if isinstance(v, (int, float)) else v

def _agent_cloudflare_arguments(
    params: Params, host_config: HostConfig
) -> Iterator[SpecialAgentCommand]:

    command_arguments: list[str | Secret] = []

    # Email is always required
    command_arguments += ["--email", params.email]

    # API Token is always required
    command_arguments += ["--api-token", params.api_token.unsafe()]

    if params.timeout is not None:
        command_arguments += ["--timeout", str(params.timeout)]

    # Add resource flags
    if params.fetch_all is True:
        command_arguments.append("--all")
    else:
        # Add individual resource flags
        if params.cdn_cache is True:
            command_arguments.append("--cdn-cache")
        
        if params.dns is True:
            command_arguments.append("--dns")
        
        if params.ssl_tls is True:
            command_arguments.append("--ssl-tls")
        
        if params.firewall is True:
            command_arguments.append("--firewall")
        
        if params.workers_pages is True:
            command_arguments.append("--workers-pages")
        
        if params.d1 is True:
            command_arguments.append("--d1")
        
        if params.secrets is True:
            command_arguments.append("--secrets")

    if params.verbose is True:
        command_arguments.append("--verbose")

    yield SpecialAgentCommand(command_arguments=command_arguments)

special_agent_cloudflare = SpecialAgentConfig(
    name="cloudflare",
    parameter_parser=Params.model_validate,
    commands_function=_agent_cloudflare_arguments,
)

