#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare D1 Metrics Graphing Plugin for CheckMK

Graphs for Cloudflare D1 database metrics.
"""

from cmk.gui.i18n import _
from cmk.gui.plugins.metrics import metric_info, graph_info

# ============================================================================
# D1 Metrics
# ============================================================================

metric_info["cloudflare_d1_size"] = {
    "title": _("D1 Database Size"),
    "unit": "bytes",
    "color": "#0066cc",
}

metric_info["cloudflare_d1_databases_total"] = {
    "title": _("D1 Databases Total"),
    "unit": "",
    "color": "#00cc66",
}

# ============================================================================
# Graphs - D1
# ============================================================================

graph_info["cloudflare_d1_size"] = {
    "title": _("Cloudflare D1 Database Size"),
    "metrics": [
        ("cloudflare_d1_size", "area", _("Database Size")),
    ],
}

graph_info["cloudflare_d1_databases"] = {
    "title": _("Cloudflare D1 Databases"),
    "metrics": [
        ("cloudflare_d1_databases_total", "line", _("Total Databases")),
    ],
}

