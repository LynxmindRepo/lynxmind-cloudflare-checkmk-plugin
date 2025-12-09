#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

from typing import Mapping
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    Password,
    String,
    migrate_to_password,
    validators,
    BooleanChoice,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic
from cmk.rulesets.v1 import Title, Help, Label


def _migrate_element_names(value: object) -> Mapping[str, object]:
    """Migrate old parameter names to new ones for backward compatibility"""
    if not isinstance(value, dict):
        raise ValueError("Invalid value for Cloudflare")
    
    # Migrate old structure to new structure (api_token only)
    if "api_token" not in value:
        # Try to get from old field names
        api_token = value.get("api-token") or value.get("api_token")
        if api_token:
            value["api_token"] = api_token
            value.pop("api-token", None)
    
    # Remove old auth structure if present
    if "auth" in value:
        # Extract api_token from auth structure
        auth = value.pop("auth")
        if isinstance(auth, tuple) and len(auth) == 2:
            auth_type, auth_value = auth
            if auth_type == "api_token":
                value["api_token"] = auth_value
        elif isinstance(auth, dict):
            api_token = auth.get("api_token") or auth.get("choice")
            if api_token:
                value["api_token"] = api_token
    
    # Remove old api_key fields
    value.pop("api_key", None)
    value.pop("api-key", None)
    
    return value


def _form_cloudflare() -> Dictionary:
    """Define the form elements for Cloudflare special agent configuration"""
    return Dictionary(
        elements={
            "email": DictElement(
                parameter_form=String(
                    title=Title("Cloudflare Email"),
                    help_text=Help("Your Cloudflare account email address (required)."),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
                required=True,
            ),
            "api_token": DictElement(
                parameter_form=Password(
                    title=Title("API Token"),
                    help_text=Help(
                        "Your Cloudflare API Token. "
                        "Create a custom token at: https://dash.cloudflare.com/profile/api-tokens"
                    ),
                    migrate=migrate_to_password,
                ),
                required=True,
            ),
            "timeout": DictElement(
                parameter_form=Integer(
                    title=Title("Timeout"),
                    help_text=Help("Timeout in seconds for API requests"),
                    prefill=DefaultValue(30),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=300),),
                ),
                required=False,
            ),
            "cdn_cache": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("CDN/Cache Collection"),
                    help_text=Help("Enable CDN/Cache settings and analytics collection for zones"),
                    label=Label("Enable CDN/Cache Collection"),
                ),
                required=False,
            ),
            "dns": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("DNS Records Collection"),
                    help_text=Help("Enable DNS records collection for zones"),
                    label=Label("Enable DNS Records Collection"),
                ),
                required=False,
            ),
            "ssl_tls": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("SSL/TLS Collection"),
                    help_text=Help("Enable SSL/TLS settings collection for zones"),
                    label=Label("Enable SSL/TLS Collection"),
                ),
                required=False,
            ),
            "firewall": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Firewall/DDoS Collection"),
                    help_text=Help("Enable Firewall/DDoS events collection for zones"),
                    label=Label("Enable Firewall/DDoS Collection"),
                ),
                required=False,
            ),
            "workers_pages": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Workers/Pages Collection"),
                    help_text=Help("Enable Workers and Pages projects collection (requires account_id)"),
                    label=Label("Enable Workers/Pages Collection"),
                ),
                required=False,
            ),
            "d1": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("D1 Databases Collection"),
                    help_text=Help("Enable D1 databases collection (requires account_id)"),
                    label=Label("Enable D1 Databases Collection"),
                ),
                required=False,
            ),
            "secrets": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Secrets Stores Collection"),
                    help_text=Help("Enable Secrets stores collection (requires account_id)"),
                    label=Label("Enable Secrets Stores Collection"),
                ),
                required=False,
            ),
            "fetch_all": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Fetch All Resources"),
                    help_text=Help(
                        "If enabled, fetch all resources (CDN/Cache, DNS, SSL/TLS, Firewall, Workers/Pages, D1, Secrets). "
                        "If disabled and no specific flags are set, all resources are fetched by default."
                    ),
                    label=Label("Fetch All Resources"),
                ),
                required=False,
            ),
            "verbose": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Debug Mode"),
                    help_text=Help("Enable verbose output for debugging purposes"),
                    label=Label("Enable Debug Logging"),
                ),
                required=False,
            ),
        },
        title=Title("Cloudflare"),
        migrate=_migrate_element_names,
    )


rule_spec_cloudflare = SpecialAgent(
    name="cloudflare",
    title=Title("Cloudflare"),
    topic=Topic.CLOUD,
    parameter_form=_form_cloudflare,
)

