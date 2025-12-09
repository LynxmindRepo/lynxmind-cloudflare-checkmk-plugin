#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
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


def _parameter_form_d1() -> Dictionary:
    """Define Levels for Cloudflare D1 metrics"""
    return Dictionary(
        elements={
            "d1_size": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(1073741824.0, 5368709120.0)),  # 1GB, 5GB
                    title=Title("D1 Database Size Levels (only if size data is collected)"),
                ),
                required=False,
            ),
            "databases_total": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(10.0, 50.0)),
                    title=Title("Total Databases Count Levels (only if multiple databases exist)"),
                ),
                required=False,
            ),
        }
    )


rule_spec_cloudflare_d1 = CheckParameters(
    name="cloudflare_d1",
    topic=Topic.CLOUD,
    parameter_form=_parameter_form_d1,
    title=Title("Cloudflare D1 Database Monitoring"),
    condition=HostAndItemCondition(item_title=Title("Cloudflare D1")),
)

