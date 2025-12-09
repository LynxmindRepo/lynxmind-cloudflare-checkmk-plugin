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
    SingleChoice,
    SingleChoiceElement,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic


def _parameter_form_cdn_cache() -> Dictionary:
    """Define Levels for Cloudflare CDN Cache metrics"""
    return Dictionary(
        elements={
            "cache_level_crit": DictElement(
                parameter_form=SingleChoice(
                    elements=[
                        SingleChoiceElement(name="off", title=Title("Critical if cache level is 'off'")),
                        SingleChoiceElement(name="basic", title=Title("Critical if cache level is 'basic'")),
                        SingleChoiceElement(name="simplified", title=Title("Critical if cache level is 'simplified'")),
                        SingleChoiceElement(name="aggressive", title=Title("Critical if cache level is 'aggressive'")),
                        SingleChoiceElement(name="none", title=Title("No critical for cache level")),
                    ],
                    prefill=DefaultValue("off"),
                    title=Title("Cache Level Critical State"),
                ),
                required=False,
            ),
            "cache_level_warn": DictElement(
                parameter_form=SingleChoice(
                    elements=[
                        SingleChoiceElement(name="off", title=Title("Warn if cache level is 'off'")),
                        SingleChoiceElement(name="basic", title=Title("Warn if cache level is 'basic'")),
                        SingleChoiceElement(name="simplified", title=Title("Warn if cache level is 'simplified'")),
                        SingleChoiceElement(name="aggressive", title=Title("Warn if cache level is 'aggressive'")),
                        SingleChoiceElement(name="none", title=Title("No warning for cache level")),
                    ],
                    prefill=DefaultValue("none"),
                    title=Title("Cache Level Warning State"),
                ),
                required=False,
            ),
            "requests_total": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(1000000.0, 5000000.0)),  # 1M, 5M requests
                    title=Title("Total Requests Levels (only if analytics data is available)"),
                ),
                required=False,
            ),
            "bandwidth_total": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(107374182400.0, 536870912000.0)),  # 100GB, 500GB
                    title=Title("Total Bandwidth Levels (only if analytics data is available)"),
                ),
                required=False,
            ),
            "cached_requests": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(500000.0, 2500000.0)),  # 500K, 2.5M requests
                    title=Title("Cached Requests Levels (only if analytics data is available)"),
                ),
                required=False,
            ),
            "cache_hit_rate": DictElement(
                parameter_form=SimpleLevels(
                    level_direction=LevelDirection.LOWER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue(value=(70.0, 50.0)),  # Warning if < 70%, Critical if < 50%
                    title=Title("Cache Hit Rate Levels (only if analytics data is available)"),
                ),
                required=False,
            ),
        }
    )


rule_spec_cloudflare_cdn_cache = CheckParameters(
    name="cloudflare_cdn_cache",
    topic=Topic.CLOUD,
    parameter_form=_parameter_form_cdn_cache,
    title=Title("Cloudflare CDN Cache Monitoring"),
    condition=HostAndItemCondition(item_title=Title("Cloudflare CDN Cache")),
)

