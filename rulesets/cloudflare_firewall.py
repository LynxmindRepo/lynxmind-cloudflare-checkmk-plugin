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


def _parameter_form_firewall() -> Dictionary:
    """Define Levels for Cloudflare Firewall metrics"""
    return Dictionary(
        elements={
            "blocked_total": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(1000.0, 5000.0)),
                    title=Title("Blocked Requests Levels"),
                ),
                required=False,
            ),
            "challenged_total": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(500.0, 2000.0)),
                    title=Title("Challenged Requests Levels"),
                ),
                required=False,
            ),
            "events_total": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(10000.0, 50000.0)),
                    title=Title("Total Firewall Events Levels"),
                ),
                required=False,
            ),
        }
    )


rule_spec_cloudflare_firewall = CheckParameters(
    name="cloudflare_firewall",
    topic=Topic.CLOUD,
    parameter_form=_parameter_form_firewall,
    title=Title("Cloudflare Firewall Monitoring"),
    condition=HostAndItemCondition(item_title=Title("Cloudflare Firewall")),
)

