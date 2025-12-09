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
    SingleChoice,
    SingleChoiceElement,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic


def _parameter_form_ssl_tls() -> Dictionary:
    """Define Levels for Cloudflare SSL/TLS status"""
    return Dictionary(
        elements={
            "ssl_status_warn": DictElement(
                parameter_form=SingleChoice(
                    elements=[
                        SingleChoiceElement(name="off", title=Title("Warn if SSL status is 'off'")),
                        SingleChoiceElement(name="flexible", title=Title("Warn if SSL status is 'flexible'")),
                        SingleChoiceElement(name="full", title=Title("Warn if SSL status is 'full'")),
                        SingleChoiceElement(name="strict", title=Title("Warn if SSL status is 'strict'")),
                        SingleChoiceElement(name="none", title=Title("No warning for SSL status")),
                    ],
                    prefill=DefaultValue("flexible"),
                    title=Title("SSL Status Warning State"),
                ),
                required=False,
            ),
            "ssl_status_crit": DictElement(
                parameter_form=SingleChoice(
                    elements=[
                        SingleChoiceElement(name="off", title=Title("Critical if SSL status is 'off'")),
                        SingleChoiceElement(name="flexible", title=Title("Critical if SSL status is 'flexible'")),
                        SingleChoiceElement(name="full", title=Title("Critical if SSL status is 'full'")),
                        SingleChoiceElement(name="strict", title=Title("Critical if SSL status is 'strict'")),
                        SingleChoiceElement(name="none", title=Title("No critical for SSL status")),
                    ],
                    prefill=DefaultValue("off"),
                    title=Title("SSL Status Critical State"),
                ),
                required=False,
            ),
        }
    )


rule_spec_cloudflare_ssl_tls = CheckParameters(
    name="cloudflare_ssl_tls",
    topic=Topic.CLOUD,
    parameter_form=_parameter_form_ssl_tls,
    title=Title("Cloudflare SSL/TLS Monitoring"),
    condition=HostAndItemCondition(item_title=Title("Cloudflare SSL/TLS")),
)

