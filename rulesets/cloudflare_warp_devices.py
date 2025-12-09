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


def _parameter_form_warp_devices() -> Dictionary:
    """Define Levels for Cloudflare WARP Devices status"""
    return Dictionary(
        elements={
            "device_status_warn": DictElement(
                parameter_form=SingleChoice(
                    elements=[
                        SingleChoiceElement(name="revoked", title=Title("Warn if device status is 'revoked'")),
                        SingleChoiceElement(name="active", title=Title("Warn if device status is 'active'")),
                        SingleChoiceElement(name="none", title=Title("No warning for device status")),
                    ],
                    prefill=DefaultValue("revoked"),
                    title=Title("Device Status Warning State"),
                ),
                required=False,
            ),
            "device_status_crit": DictElement(
                parameter_form=SingleChoice(
                    elements=[
                        SingleChoiceElement(name="revoked", title=Title("Critical if device status is 'revoked'")),
                        SingleChoiceElement(name="active", title=Title("Critical if device status is 'active'")),
                        SingleChoiceElement(name="none", title=Title("No critical for device status")),
                    ],
                    prefill=DefaultValue("none"),
                    title=Title("Device Status Critical State"),
                ),
                required=False,
            ),
        }
    )


rule_spec_cloudflare_warp_devices = CheckParameters(
    name="cloudflare_warp_devices",
    topic=Topic.CLOUD,
    parameter_form=_parameter_form_warp_devices,
    title=Title("Cloudflare WARP Devices Monitoring"),
    condition=HostAndItemCondition(item_title=Title("Cloudflare WARP Device")),
)

