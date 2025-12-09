#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare Secrets Metrics Graphing Plugin for CheckMK

Graphs for Cloudflare Secrets metrics.
"""

from cmk.gui.i18n import _
from cmk.gui.plugins.metrics import metric_info, graph_info

# ============================================================================
# Secrets Metrics
# ============================================================================

metric_info["cloudflare_secrets_count"] = {
    "title": _("Secrets Count"),
    "unit": "",
    "color": "#0066cc",
}

metric_info["cloudflare_secrets_stores_total"] = {
    "title": _("Secrets Stores Total"),
    "unit": "",
    "color": "#00cc66",
}

# ============================================================================
# Graphs - Secrets
# ============================================================================

graph_info["cloudflare_secrets"] = {
    "title": _("Cloudflare Secrets"),
    "metrics": [
        ("cloudflare_secrets_count", "line", _("Secrets Count")),
        ("cloudflare_secrets_stores_total", "line", _("Stores Total")),
    ],
}

