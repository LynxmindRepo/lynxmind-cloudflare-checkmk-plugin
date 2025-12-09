# Cloudflare CheckMK Plugin

A comprehensive CheckMK plugin for monitoring Cloudflare infrastructure and services. This plugin provides agent-based checks for monitoring essential Cloudflare resources through the Cloudflare API v4.

## Features

This plugin monitors the following Cloudflare resources:

- **CDN & Cache**: Cache level settings, requests, bandwidth, and cache hit rates
- **DNS**: DNS records and statistics by type
- **SSL/TLS**: SSL/TLS status and certificate configurations
- **Firewall/DDoS**: Firewall events (blocked, challenged, allowed)
- **Workers & Pages**: Serverless resources (Workers scripts and Pages projects)
- **D1 Databases**: Database size, count, and metadata
- **Secrets Stores**: Secrets count and store information
- **WARP Devices**: Device status, platform, version, and last seen
- **Access Apps**: Access application policies, destinations, and IDPs
- **Gateway**: Gateway rules and account configuration

## Plugin Structure

```
cloud_flare/
├── agent_based/
│   ├── cloudflare_cdn_cache.py
│   ├── cloudflare_dns.py
│   ├── cloudflare_ssl_tls.py
│   ├── cloudflare_firewall.py
│   ├── cloudflare_workers.py
│   ├── cloudflare_pages.py
│   ├── cloudflare_d1.py
│   ├── cloudflare_secrets.py
│   ├── cloudflare_warp_devices.py
│   ├── cloudflare_access_apps.py
│   └── cloudflare_gateway.py
├── special_agents/
│   └── cloudflare.py          # Main script for fetching data from API
├── server_side_calls/
│   └── special_agent.py       # Special agent configuration
├── rulesets/
│   ├── cloudflare_cdn_cache.py
│   ├── cloudflare_dns.py
│   ├── cloudflare_ssl_tls.py
│   ├── cloudflare_firewall.py
│   ├── cloudflare_workers.py
│   ├── cloudflare_pages.py
│   ├── cloudflare_d1.py
│   ├── cloudflare_secrets.py
│   ├── cloudflare_warp_devices.py
│   ├── cloudflare_access_apps.py
│   ├── cloudflare_gateway.py
│   └── datasource_program.py  # Datasource program (SpecialAgent)
├── graphing/
│   ├── cloudflare_cdn_cache.py
│   ├── cloudflare_dns.py
│   ├── cloudflare_pages.py
│   ├── cloudflare_d1.py
│   └── cloudflare_secrets.py
├── libexec/
│   └── agent_cloudflare       # Wrapper script
└── README.md
```

## Requirements

- Python 3.8+
- CheckMK 2.4+
- Python libraries:
  - `aiohttp` (for async HTTP requests)
  - `tenacity` (for retry logic)

## Installation

### Option 1: Install via MKP Package (Recommended)

1. Download the latest `.mkp` package from the [releases page](https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin/releases) or clone the repository:
   ```bash
   git clone https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin.git
   cd lynxmind-cloudflare-checkmk-plugin
   ```

2. Install the MKP package using CheckMK's MKP tool:
   ```bash
   # As root or with sudo
   mkp install cloudflare-1.0.0.mkp
   
   # Or for a specific site
   mkp install cloudflare-1.0.0.mkp --site <site-name>
   ```

3. Activate the changes in CheckMK:
   ```bash
   omd restart <site>
   ```

### Option 2: Manual Installation

1. Copy the `cloud_flare` directory to your CheckMK site's local plugin directory:
   ```bash
   cp -r cloud_flare /omd/sites/<site>/local/lib/python3/cmk_addons/plugins/
   ```

2. Restart CheckMK to load the plugin:
   ```bash
   omd restart <site>
   ```

### Building the MKP Package

If you need to build the MKP package from source:

1. Ensure you have the CheckMK development environment set up
2. Use the `mkp` tool to create the package:
   ```bash
   mkp package cloud_flare
   ```
   
   This will create a `.mkp` file that can be distributed and installed on CheckMK sites.

**Note:** The pre-built MKP package (`cloudflare-1.0.0.mkp`) is available in the repository for direct installation.

## Configuration

### Authentication

The plugin supports two authentication methods:

- **API Key (Global API Key)**: Requires `email` and `api_key`
- **API Token**: Requires only `api_token` (recommended for security)

To obtain your credentials:
- **API Key**: https://dash.cloudflare.com/profile/api-tokens
- **API Token**: https://dash.cloudflare.com/profile/api-tokens (create custom token)

**Required API Token Permissions:**
- Zone: Read
- Account: Read (for Workers, Pages, D1, Secrets, WARP Devices, Access Apps, Gateway)
- Analytics: Read (for CDN analytics)

### CheckMK Configuration

#### Option 1: Via Datasource Program (Recommended)

1. Navigate to **Setup** > **Agents, programs & checks** > **Datasource programs**
2. Select **Cloudflare** from the list
3. Configure the parameters:
   - `email`: Your Cloudflare account email
   - `api_key` or `api_token`: Your API key or token (at least one is required)
   - `account_id`: (Optional) Account ID for account-level resources (auto-detected if not provided)
   - `timeout`: API call timeout in seconds (default: 30)
   - Resource flags:
     - `cdn_cache`: Fetch CDN/Cache settings and analytics
     - `dns`: Fetch DNS records
     - `ssl_tls`: Fetch SSL/TLS settings
     - `firewall`: Fetch Firewall/DDoS events
     - `workers_pages`: Fetch Workers and Pages projects
     - `d1`: Fetch D1 Databases
     - `secrets`: Fetch Secrets Stores
     - `devices`: Fetch WARP devices
     - `apps`: Fetch Access Applications
     - `gateway`: Fetch Gateway configuration
     - `analytics`: Fetch Cloudflare One Analytics (if available)
     - `all`: Fetch all resources (default if no flags specified)
   - `verbose`: Enable detailed output for debugging

#### Option 2: Via Special Agent

1. Navigate to **Setup** > **Agents, programs & checks** > **Special agents**
2. Configure the `cloudflare` special agent with the same parameters as above

### Collected Metrics

#### CDN & Cache (`--cdn-cache`)
- Cache level configuration (aggressive, basic, simplified, off)
- Total requests (last 24 hours)
- Total bandwidth used (last 24 hours)
- Cached requests count
- Cache hit rate percentage

#### DNS (`--dns`)
- Total DNS records per zone
- Count by record type (A, AAAA, CNAME, MX, TXT, etc.)

#### SSL/TLS (`--ssl-tls`)
- SSL/TLS status (full, strict, flexible, off)
- Certificate configuration

#### Firewall/DDoS (`--firewall`)
- Total blocked events
- Total challenged events
- Total allowed events
- Total firewall events

#### Workers & Pages (`--workers-pages`)
- **Workers**: ID, creation date, modification date, usage model, ETag
- **Pages**: Projects, production branches, latest deployments, deployment status, domains count

#### D1 Databases (`--d1`)
- Database UUID
- Database size (bytes)
- Creation date
- Version (production/staging)

#### Secrets Stores (`--secrets`)
- Store ID
- Secrets count per store
- Total stores count

#### WARP Devices (`--devices`)
- Device name
- Platform (Windows, macOS, Linux, iOS, Android)
- OS version
- Device status (active, revoked)
- Last seen timestamp

#### Access Apps (`--apps`)
- Application name and domain
- Application type
- Policies count
- Destinations count
- Identity providers (IDPs) count
- Last updated timestamp

#### Gateway (`--gateway`)
- Account provider
- Gateway tag/ID
- Total rules count
- Rules by action (block, allow, log)

## Ruleset Configuration (Thresholds)

All checks support configurable thresholds through CheckMK rulesets:

### CDN Cache
- Cache level warnings/critical states
- Total requests (default: warn=1M, crit=5M)
- Total bandwidth (default: warn=100GB, crit=500GB)
- Cached requests (default: warn=500K, crit=2.5M)
- Cache hit rate (default: warn<70%, crit<50%)

### DNS
- DNS records total (default: warn=100, crit=500)

### SSL/TLS
- SSL status warnings (default: warn on 'flexible', crit on 'off')

### Firewall
- Blocked requests (default: warn=1000, crit=5000)
- Challenged requests (default: warn=500, crit=2000)
- Total events (default: warn=10K, crit=50K)

### D1 Databases
- Database size (default: warn=1GB, crit=5GB)
- Total databases (default: warn=10, crit=50)

### Pages
- Total projects (default: warn=10, crit=50)

### Secrets
- Secrets count (default: warn=100, crit=500)
- Total stores (default: warn=10, crit=50)

### Access Apps
- Policies count (default: warn=50, crit=100)
- Destinations count (default: warn=20, crit=50)
- IDPs count (default: warn=10, crit=20)

### Gateway
- Total rules (default: warn=100, crit=500)

### WARP Devices
- Device status warnings (default: warn on 'revoked')

## Manual Usage

To test the plugin manually:

```bash
# Collect all resources
python3 special_agents/cloudflare.py \
  --email your-email@example.com \
  --api-token your-api-token \
  --all \
  --verbose

# Collect specific resources
python3 special_agents/cloudflare.py \
  --email your-email@example.com \
  --api-token your-api-token \
  --cdn-cache \
  --dns \
  --ssl-tls \
  --firewall \
  --workers-pages \
  --d1 \
  --secrets \
  --devices \
  --apps \
  --gateway \
  --verbose
```

### Available Options

- `--cdn-cache`: Collect CDN/Cache data
- `--dns`: Collect DNS records
- `--ssl-tls`: Collect SSL/TLS settings
- `--firewall`: Collect Firewall/DDoS events
- `--workers-pages`: Collect Workers and Pages projects
- `--d1`: Collect D1 Databases
- `--secrets`: Collect Secrets Stores
- `--devices`: Collect WARP devices
- `--apps`: Collect Access Applications
- `--gateway`: Collect Gateway configuration
- `--analytics`: Collect Cloudflare One Analytics (if available via API)
- `--all`: Collect all resources above (default if no flags specified)
- `--verbose`, `-v`: Enable verbose output

## Output Format

The plugin generates output in CheckMK format:

```
<<<cloudflare_cdn_cache>>>
zone.example.com.cache_level=aggressive
zone.example.com.requests_total=12345
zone.example.com.bandwidth_total=1048576
zone.example.com.cached_requests=9876
zone.example.com.cache_hit_rate=80.00%

<<<cloudflare_dns>>>
zone.example.com.dns_records_total=15
zone.example.com.dns_records_type.A=5
zone.example.com.dns_records_type.CNAME=3

<<<cloudflare_ssl_tls>>>
zone.example.com.ssl_status=full

<<<cloudflare_firewall>>>
zone.example.com.firewall.blocked_total=12
zone.example.com.firewall.challenged_total=5
zone.example.com.firewall.allowed_total=12228
zone.example.com.firewall.events_total=12245

<<<cloudflare_workers>>>
worker.my-worker.id=my-worker
worker.my-worker.created_on=2025-11-24T10:00:00Z
worker.my-worker.modified_on=2025-11-24T15:30:00Z
worker.my-worker.usage_model=standard

<<<cloudflare_pages>>>
pages.projects_total=2
pages.project.my-project.id=abc123
pages.project.my-project.created_on=2025-11-24T10:00:00Z
pages.project.my-project.production_branch=main
pages.project.my-project.latest_deployment_status=success
pages.project.my-project.domains_count=1

<<<cloudflare_d1>>>
d1.databases_total=1
d1.db.my-database.uuid=ee80c38e-d3b9-43be-9509-5364f25b6e0c
d1.db.my-database.size=12288
d1.db.my-database.created_at=2025-11-28T16:00:55.937Z
d1.db.my-database.version=production

<<<cloudflare_secrets>>>
secrets.stores_total=1
secrets.store.default_secrets_store.id=cdba88410d8d4b788c6474326e7f0314
secrets.store.default_secrets_store.secrets_count=1

<<<cloudflare_warp_devices>>>
warp.devices_total=1
warp.device.e4d851d0-d107-11f0-8b01-aa2b96deef4b.name=Device-Name
warp.device.e4d851d0-d107-11f0-8b01-aa2b96deef4b.platform=windows
warp.device.e4d851d0-d107-11f0-8b01-aa2b96deef4b.version=10.0.26200
warp.device.e4d851d0-d107-11f0-8b01-aa2b96deef4b.status=active
warp.device.e4d851d0-d107-11f0-8b01-aa2b96deef4b.last_seen=2025-12-04T17:03:06.903137Z

<<<cloudflare_access_apps>>>
access.apps_total=1
access.app.31061026-3714-4fb4-8a65-6bb8eed91c3d.name=My_Access_App
access.app.31061026-3714-4fb4-8a65-6bb8eed91c3d.domain=example.cloudflareaccess.com
access.app.31061026-3714-4fb4-8a65-6bb8eed91c3d.type=warp
access.app.31061026-3714-4fb4-8a65-6bb8eed91c3d.policies_count=1
access.app.31061026-3714-4fb4-8a65-6bb8eed91c3d.destinations_count=0
access.app.31061026-3714-4fb4-8a65-6bb8eed91c3d.idps_count=0

<<<cloudflare_gateway>>>
gateway.account.provider=Cloudflare
gateway.account.tag=bfdcb227ab5af6be1593cbcfee059505
gateway.rules_total=0
```

## Supported API Resources

### ✅ Implemented

1. **CDN + Cache**
   - Endpoint: `/zones/:zone_id/settings/cache_level`
   - Endpoint: `/zones/:zone_id/analytics/dashboard`
   - Metrics: Cache level, requests, bandwidth, cache hit rate

2. **DNS**
   - Endpoint: `/zones/:zone_id/dns_records`
   - Metrics: Total records, count by type

3. **SSL/TLS**
   - Endpoint: `/zones/:zone_id/settings/ssl`
   - Metrics: SSL/TLS status

4. **Firewall/DDoS**
   - Endpoint: `/zones/:zone_id/security/events`
   - Metrics: Blocked, challenged, allowed events

5. **Workers & Pages**
   - Endpoint: `/accounts/:account_id/workers/scripts`
   - Endpoint: `/accounts/:account_id/pages/projects`
   - Metrics: Workers and Pages projects

6. **D1 Databases**
   - Endpoint: `/accounts/:account_id/d1/database`
   - Metrics: Database size, count, metadata

7. **Secrets Stores**
   - Endpoint: `/accounts/:account_id/secrets_store/stores`
   - Endpoint: `/accounts/:account_id/secrets_store/stores/:store_id/secrets`
   - Metrics: Secrets count, stores count

8. **WARP Devices**
   - Endpoint: `/accounts/:account_id/devices/physical-devices`
   - Metrics: Device status, platform, version, last seen

9. **Access Applications**
   - Endpoint: `/accounts/:account_id/access/apps`
   - Metrics: Policies, destinations, IDPs count

10. **Gateway**
    - Endpoint: `/accounts/:account_id/gateway`
    - Endpoint: `/accounts/:account_id/gateway/rules`
    - Metrics: Rules count, account configuration

### ⚠️ Note on Analytics

Cloudflare One Analytics endpoints (Access Analytics, Gateway HTTP/Network/DNS Analytics, Zero Trust Seats) are not available via REST API v4. These metrics are typically accessed through the GraphQL Analytics API, which requires a different implementation approach. The plugin includes placeholder functions for these endpoints that gracefully handle unavailability.

## Troubleshooting

### Authentication Errors
- Verify that your email and API key/token are correct
- Ensure the token has adequate permissions:
  - Zone: Read (for zones, DNS, SSL/TLS, Firewall)
  - Account: Read (for Workers, Pages, D1, Secrets, WARP Devices, Access Apps, Gateway)
  - Analytics: Read (for CDN analytics)

### Timeout Issues
- Increase the `timeout` value if you have many zones
- Use specific resource flags instead of `--all` to reduce API calls
- Check your network connectivity to Cloudflare API

### No Data Returned
- Verify that you have zones/resources in your Cloudflare account
- Use `--verbose` to see detailed logs
- Check API token permissions
- Some endpoints may not be available for all account types

### API Errors (405/400)
- Some endpoints (like Analytics) may return 405 (Not Allowed) or 400 (Bad Request) if not available via REST API v4
- These errors are handled gracefully and logged as DEBUG messages
- The plugin continues to function even if some endpoints are unavailable

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

GNU General Public License v2

## Authors

- Ricardo and Elicarlos - checkmk@lynxmind.com
- Thanks to: Lynxmind CloudFlare team

## Repository

https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin

## Version

Current version: **1.0.0**

The MKP package file (`cloudflare-1.0.0.mkp`) is included in the repository and can be directly installed on CheckMK exchange.
