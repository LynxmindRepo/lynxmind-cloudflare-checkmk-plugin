#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

from cmk.rulesets.v1 import Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    LevelDirection,
    SimpleLevels,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic


def _parameter_form_dns() -> Dictionary:
    """Define Levels for Cloudflare DNS metrics"""
    return Dictionary(
        elements={
            "dns_records_total": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(100.0, 500.0)),
                    title=Title("DNS Records Total Levels"),
                ),
                required=False,
            ),
        }
    )


rule_spec_cloudflare_dns = CheckParameters(
    name="cloudflare_dns",
    topic=Topic.CLOUD,
    parameter_form=_parameter_form_dns,
    title=Title("Cloudflare DNS Monitoring"),
    condition=HostAndItemCondition(item_title=Title("Cloudflare DNS")),
)

