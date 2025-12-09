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


def _parameter_form_pages() -> Dictionary:
    """Define Levels for Cloudflare Pages metrics"""
    return Dictionary(
        elements={
            "projects_total": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(10.0, 50.0)),
                    title=Title("Total Projects Count Levels"),
                ),
                required=False,
            ),
        }
    )


rule_spec_cloudflare_pages = CheckParameters(
    name="cloudflare_pages",
    topic=Topic.CLOUD,
    parameter_form=_parameter_form_pages,
    title=Title("Cloudflare Pages Monitoring"),
    condition=HostAndItemCondition(item_title=Title("Cloudflare Pages")),
)

