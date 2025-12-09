#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2

"""
Cloudflare CDN Cache Metrics Graphing Plugin for CheckMK

Graphs for Cloudflare CDN Cache metrics.
"""

from cmk.gui.i18n import _
from cmk.gui.plugins.metrics import metric_info, graph_info

# ============================================================================
# CDN Cache Metrics
# ============================================================================

metric_info["cloudflare_requests_total"] = {
    "title": _("Total Requests"),
    "unit": "",
    "color": "#0066cc",
}

metric_info["cloudflare_bandwidth_total"] = {
    "title": _("Total Bandwidth"),
    "unit": "bytes",
    "color": "#00cc66",
}

metric_info["cloudflare_cached_requests"] = {
    "title": _("Cached Requests"),
    "unit": "",
    "color": "#cc0066",
}

metric_info["cloudflare_cache_hit_rate"] = {
    "title": _("Cache Hit Rate"),
    "unit": "%",
    "color": "#cc6600",
}

# ============================================================================
# Graphs - CDN Cache
# ============================================================================

graph_info["cloudflare_requests"] = {
    "title": _("Cloudflare Requests"),
    "metrics": [
        ("cloudflare_requests_total", "line", _("Total Requests")),
        ("cloudflare_cached_requests", "line", _("Cached Requests")),
    ],
}

graph_info["cloudflare_bandwidth"] = {
    "title": _("Cloudflare Bandwidth"),
    "metrics": [
        ("cloudflare_bandwidth_total", "area", _("Total Bandwidth")),
    ],
}

graph_info["cloudflare_cache_hit_rate"] = {
    "title": _("Cloudflare Cache Hit Rate"),
    "metrics": [
        ("cloudflare_cache_hit_rate", "line", _("Cache Hit Rate")),
    ],
}

