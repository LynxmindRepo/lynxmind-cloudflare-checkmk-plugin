#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare DNS Metrics Graphing Plugin for CheckMK

Graphs for Cloudflare DNS metrics.
"""

from cmk.gui.i18n import _
from cmk.gui.plugins.metrics import metric_info, graph_info

# ============================================================================
# DNS Metrics
# ============================================================================

metric_info["cloudflare_dns_records_total"] = {
    "title": _("DNS Records Total"),
    "unit": "",
    "color": "#0066cc",
}

# Dynamic DNS record type metrics (created at runtime)
# These will be registered dynamically for each record type found
# Format: cloudflare_dns_records_type_{type} (e.g., cloudflare_dns_records_type_a)

# ============================================================================
# Graphs - DNS
# ============================================================================

graph_info["cloudflare_dns_records"] = {
    "title": _("Cloudflare DNS Records"),
    "metrics": [
        ("cloudflare_dns_records_total", "line", _("Total Records")),
    ],
}

