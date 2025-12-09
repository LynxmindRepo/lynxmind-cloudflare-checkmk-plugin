#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare Pages Metrics Graphing Plugin for CheckMK

Graphs for Cloudflare Pages metrics.
"""

from cmk.gui.i18n import _
from cmk.gui.plugins.metrics import metric_info, graph_info

# ============================================================================
# Pages Metrics
# ============================================================================

metric_info["cloudflare_pages_projects_total"] = {
    "title": _("Pages Projects Total"),
    "unit": "",
    "color": "#0066cc",
}

metric_info["cloudflare_pages_domains_count"] = {
    "title": _("Pages Domains Count"),
    "unit": "",
    "color": "#00cc66",
}

# ============================================================================
# Graphs - Pages
# ============================================================================

graph_info["cloudflare_pages_projects"] = {
    "title": _("Cloudflare Pages Projects"),
    "metrics": [
        ("cloudflare_pages_projects_total", "line", _("Total Projects")),
    ],
}

graph_info["cloudflare_pages_domains"] = {
    "title": _("Cloudflare Pages Domains"),
    "metrics": [
        ("cloudflare_pages_domains_count", "line", _("Domains Count")),
    ],
}

