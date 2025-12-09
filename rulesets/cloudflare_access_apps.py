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


def _parameter_form_access_apps() -> Dictionary:
    """Define Levels for Cloudflare Access Apps metrics"""
    return Dictionary(
        elements={
            "policies_count": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(50.0, 100.0)),
                    title=Title("Policies Count Levels"),
                ),
                required=False,
            ),
            "destinations_count": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(20.0, 50.0)),
                    title=Title("Destinations Count Levels"),
                ),
                required=False,
            ),
            "idps_count": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(10.0, 20.0)),
                    title=Title("IDPs Count Levels"),
                ),
                required=False,
            ),
        }
    )


rule_spec_cloudflare_access_apps = CheckParameters(
    name="cloudflare_access_apps",
    topic=Topic.CLOUD,
    parameter_form=_parameter_form_access_apps,
    title=Title("Cloudflare Access Apps Monitoring"),
    condition=HostAndItemCondition(item_title=Title("Cloudflare Access App")),
)

