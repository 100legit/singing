import { getAllOutbounds, Sub, OutboundConfig, OutboundSelectorSpec } from './outbound.js'
import { RuleSet, allRuleSets } from './ruleset.js';

/**
 * Root configuration for sing-box
 */
interface SingBoxConfig {
  log?: LogConfig;
  dns?: DNSConfig;
  ntp?: NTPConfig;
  certificate?: CertificateConfig;
  endpoints?: EndpointConfig[];
  inbounds?: any[];
  outbounds?: OutboundConfig[];
  route?: RouteConfig;
  experimental?: ExperimentalConfig;
}

interface LogConfig {
  disabled?: boolean; // If true, disables logging.
  level?: "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic"; // Log level.
  output?: string; // File path for log output.
  timestamp?: boolean; // If true, includes timestamps in log entries.
}

interface DNSConfig {
  servers?: LegacyDNSServer[]; // List of legacy DNS servers.
  rules: DNSRule[]; // List of DNS rules.
  strategy?: "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only"; // DNS resolution strategy.
  disable_cache?: boolean; // If true, disables DNS caching.
  disable_expire?: boolean; // If true, disables DNS cache expiration.
  independent_cache?: boolean; // If true, each DNS server has its own independent cache.
  cache_capacity?: number; // LRU cache capacity.
  reverse_mapping?: boolean; // If true, stores reverse mapping of IPs to domain names.
  client_subnet?: string; // EDNS client subnet value.
  final?: string; // Default DNS server tag.
  fakeip?: FakeIPConfig; // deprecated
}

interface FakeIPConfig {
  enabled: boolean;
  inet4_range: string;
  inet6_range: string;
}

interface LegacyDNSServer {
  tag?: string; // Tag for the DNS server.
  address: string; // Address of the DNS server.
  address_resolver?: string; // Tag of the server used to resolve the address.
  address_strategy?: "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only"; // Address resolution strategy.
  strategy?: "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only"; // Domain resolution strategy.
  detour?: string; // Tag of the outbound used to connect to the DNS server.
  client_subnet?: string; // EDNS client subnet value.
}

interface DNSRule {
  inbound?: string[];
  ip_version?: 4 | 6;
  query_type?: (number | "A" | "AAAA" | "HTTPS")[];
  network?: "tcp" | "udp";
  auth_user?: string[];
  protocol?: string[];
  domain?: string[];
  domain_suffix?: string[];
  domain_keyword?: string[];
  domain_regex?: string[];
  source_ip_cidr?: string[];
  source_ip_is_private?: boolean;
  ip_cidr?: string[];
  ip_is_private?: boolean;
  source_port?: number[];
  source_port_range?: string[];
  port?: number[];
  port_range?: string[];
  process_name?: string[];
  process_path?: string[];
  process_path_regex?: string[];
  package_name?: string[];
  user?: string[];
  user_id?: number[];
  clash_mode?: "direct" | "rule" | "global";
  network_type?: ("wifi" | "cellular" | "ethernet" | "other")[];
  network_is_expensive?: boolean;
  network_is_constrained?: boolean;
  wifi_ssid?: string[];
  wifi_bssid?: string[];
  rule_set?: string[];
  rule_set_ipcidr_match_source?: boolean; // Deprecated
  rule_set_ip_cidr_match_source?: boolean;
  rule_set_ip_cidr_accept_empty?: boolean;
  invert?: boolean;
  outbound?: string[]; // Deprecated
  action?: string; // Action to take for matching rules.
}

interface NTPConfig {
  enabled?: boolean; // If true, enables NTP service.
  server: string; // NTP server address.
  server_port?: number; // NTP server port, default is 123.
  interval?: string; // Synchronization interval, e.g., "30m".
  detour?: string; // Outbound tag for NTP traffic.
}

interface CertificateConfig {
  store?: "system" | "mozilla" | "none"; // Certificate store.
  certificate?: string[]; // Inline certificates in PEM format.
  certificate_path?: string[]; // Paths to certificate files.
  certificate_directory_path?: string[]; // Paths to directories containing certificates.
}

interface EndpointConfig {
  type: "wireguard" | "tailscale"; // Type of endpoint.
  tag: string; // Tag for the endpoint.
  // Additional fields depend on the endpoint type.
}

interface RouteConfig {
  rules?: RouteRule[]; // List of routing rules.
  rule_set?: RuleSet[]; // List of rule sets.
  final?: string; // Default outbound tag.
  auto_detect_interface?: boolean; // If true, auto-detects the default network interface.
  override_android_vpn?: boolean; // If true, allows tun traffic to go through Android VPN.
  default_interface?: string; // Default network interface to bind to.
  default_mark?: number; // Default routing mark for Linux.
  default_domain_resolver?: string; // Default domain resolver tag.
  default_network_strategy?: "default" | "hybrid" | "fallback"; // Default network strategy.
  default_network_type?: ("wifi" | "cellular" | "ethernet" | "other")[]; // Preferred network types.
  default_fallback_network_type?: ("wifi" | "cellular" | "ethernet" | "other")[]; // Fallback network types.
  default_fallback_delay?: string; // Delay before trying fallback networks.
}

interface RouteRule {
  inbound?: string[]; // Tags of inbounds to match.
  ip_version?: 4 | 6; // IP version to match.
  domain?: string[]; // Full domain names to match.
  domain_suffix?: string[]; // Domain suffixes to match.
  domain_keyword?: string[]; // Keywords in domain names to match.
  domain_regex?: string[]; // Regular expressions to match domain names.
  ip_cidr?: string[]; // IP ranges to match.
  ip_is_private?: boolean; // If true, matches private IPs.
  action?: string; // Action to take for matching rules.
  outbound?: string; // Tag of the outbound to use.
}

interface ExperimentalConfig {
  cache_file?: CacheFileConfig;
  clash_api?: ClashAPIConfig;
  v2ray_api?: V2RayAPIConfig;
}

interface CacheFileConfig {
  enabled?: boolean; // If true, enables caching.
  path?: string; // Path to the cache file.
  cache_id?: string; // Identifier for the cache.
  store_fakeip?: boolean; // If true, stores fake IP mappings in the cache.
  store_rdrc?: boolean; // If true, stores rejected DNS responses in the cache.
  rdrc_timeout?: string; // Timeout for rejected DNS responses.
}

interface ClashAPIConfig {
  external_controller?: string; // Address for the RESTful API.
  secret?: string; // Secret for the API.
  default_mode?: string; // Default mode for Clash, e.g., "Rule".
  external_ui?: string; // relative path to web UI resources.
  external_ui_download_url?: string; // URL to download the web UI.
  external_ui_download_detour?: string; // Outbound tag for downloading the web UI.
}

interface V2RayAPIConfig {
  listen?: string; // Address for the gRPC API.
  stats?: V2RayStatsConfig; // Traffic statistics settings.
}

interface V2RayStatsConfig {
  enabled?: boolean; // If true, enables traffic statistics.
  inbounds?: string[]; // Tags of inbounds to monitor.
  outbounds?: string[]; // Tags of outbounds to monitor.
  users?: string[]; // Users to monitor.
}

const ENABLE_TUN_AUTO_ROUTE = true;
const ENABLE_TPROXY = true;
const ENABLE_TUN = true;
const LOG_LEVEL = "debug";
const CLASH_API_SECRET = "123";
const template: SingBoxConfig = {
  "log": {
    "disabled": false,
    "level": LOG_LEVEL,
    // "output": "box.log",
    "timestamp": true
  },
  "ntp": {
    "enabled": true,
    "server": "ntp.aliyun.com",
    "server_port": 123,
    "interval": "30m",
    "detour": "direct"
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "store_fakeip": true,
      "store_rdrc": false
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": CLASH_API_SECRET,
      "external_ui": "ui",
      "external_ui_download_url": "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip",
      "external_ui_download_detour": "proxy",
      "default_mode": "rule"
    }
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "::",
      "listen_port": 7080
    },
    ENABLE_TPROXY ? {
      "type": "tproxy",
      "tag": "tproxy-in",
      "listen": "::",
      "listen_port": 1536
    } : undefined,
    ENABLE_TUN ? {
      "tag": "tun-in",
      "type": "tun",
      "interface_name": "singbox",
      "address": [
        "172.19.0.1/30",
        "fdfe:2952:8964::1/126"
      ],
      "stack": "system",
      "auto_route": ENABLE_TUN_AUTO_ROUTE,
      "strict_route": false
    } : undefined,
  ].filter(Boolean),
}

export interface SiteRouteSpec {
  tag: string;
  rulesetTags: string[];
  default: string;
}
const siteRouteSpecs: SiteRouteSpec[] = [
  { "tag": "telegram", "rulesetTags": ["S/ni/telegram", "S/ip/telegram"], "default": "香港" },
  { "tag": "ai-services", "rulesetTags": ["S/ni/ai"], "default": "日本" },
  { tag: "youtube", rulesetTags: ["M/ds/youtube"], default: "香港" },
  { tag: "stream", rulesetTags: ["S/ni/stream", "S/ip/stream"], default: "香港" },
  //{ "tag": "apple", "rulesetTags": ["S/ni/apple_services"] }
]
function getSiteRules(siteRouteSpec: SiteRouteSpec[]): RouteRule[] {
  return siteRouteSpec.map((rule) => {
    return {
      "rule_set": rule.rulesetTags,
      "outbound": rule.tag
    }
  });
}

const dnsServers: LegacyDNSServer[] = [
  {
    "tag": "dns_proxy",
    "address": "tls://1.1.1.1",
    "detour": "proxy",
  },
  {
    "tag": "dns_direct",
    "address": "https://223.5.5.5/dns-query",
    "detour": "direct",
  },
  {
    "tag": "dns_direct_v6only",
    "address": "https://223.5.5.5/dns-query",
    "detour": "direct",
    strategy: "ipv6_only",
  },
  {
    "tag": "block",
    "address": "rcode://success"
  },
  {
    "tag": "nxdomain",
    "address": "rcode://name_error"
  },
  {
    "tag": "fakeip",
    "address": "fakeip"
  }
]
const dnsRules = [
  // TODO: deprecated
  {
    "outbound": "any",
    "action": "route",
    "server": "dns_direct"
  },
  // TODO: migrate to DNS Rule action
  {
    "rule_set": ["W/ds/pt"],
    "action": "route",
    "server": "dns_direct_v6only"
  },
  {
    "clash_mode": "Direct",
    "action": "route",
    "server": "dns_direct"
  },
  {
    "clash_mode": "Global",
    "action": "route",
    "server": "dns_proxy"
  },
  {
    "rule_set": [
      "S/ds/apple_cdn",
      "S/ni/apple_cn",
      "S/ni/apple_services", // Apple 非国区服务域名, 直连
      "S/ni/microsoft_cdn"
    ],
    "action": "route",
    "server": "dns_direct"
  },
  {
    "rule_set": [
      "S/ds/reject"
    ],
    "action": "route",
    "server": "nxdomain"
  },
  {
    "rule_set": [
      "M/ds/cn",
      "S/ni/domestic",
      "S/ni/lan"
    ],
    "action": "route",
    "server": "dns_direct"
  },
  {
    "type": "logical",
    "mode": "and",
    "rules": [
      {
        "rule_set": [
          ...siteRouteSpecs.map((rule) => rule.rulesetTags).flat().filter((tag) => !tag.includes("ip")),
          "S/ni/my_proxy",
        ],
      },
      {
        "rule_set": "W/ds/nofakeip",
        "invert": true,
      }
    ],
    "action": "route",
    server: "fakeip"
  },
  {
    "rule_set": [
      "S/ip/domestic",
      "S/ip/china_ip"
    ],
    "action": "route",
    "server": "dns_direct"
  },
]

const routePriorSiteRules = [
  { "action": "sniff" },
  { "protocol": "dns", "action": "hijack-dns" },
  { "protocol": "quic", "action": "reject" },
  {
    "protocol": "bittorrent",
    "action": "route",
    "outbound": "direct"
  },

  { "clash_mode": "Direct", "outbound": "direct" },
  { "clash_mode": "Global", "outbound": "proxy" },

  // 广告域名拦截
  {
    "rule_set": "S/ds/reject",
    "action": "reject",
    "no_drop": false
  },
  {
    "rule_set": "S/ni/reject-drop",
    "action": "reject",
    "mode": "drop"
  },
  {
    "rule_set": "S/ni/reject-no-drop",
    "action": "reject",
    "no_drop": true
  },
]

const routeAfterSiteRules = [
  // 国外 CDN 域名
  {
    "rule_set": [
      "S/ds/cdn",
      "S/ni/cdn"
    ],
    "outbound": "proxy"
  },

  // Apple 服务域名，直连
  {
    "rule_set": [
      "S/ds/apple_cdn",
      "S/ni/apple_cn",
      "S/ni/apple_services", // Apple 非国区服务域名, 直连
      "S/ni/microsoft_cdn"
    ],
    "outbound": "direct"
  },

  {
    "rule_set": [
      "M/ds/notcn",
      "S/ni/my_proxy"
    ],
    "outbound": "proxy"
  },
  {
    "rule_set": [
      "S/ni/domestic",
      "S/ni/lan"
    ],
    "outbound": "direct"
  },

  {
    "action": "resolve"
  },
  {
    "rule_set": [
      "S/ip/domestic", // 手工维护的腾讯云 AIA Anycast 业务的 IP 段和阿里云 Anycast 业务的 IP 段
      "S/ip/china_ip", // chnroutes2 with minor fix
      "S/ip/china_ip_ipv6",
    ],
    "outbound": "direct"
  },
  {
    "ip_is_private": true,
    "outbound": "direct"
  }
];

function getConfig(outbounds: OutboundConfig[]): SingBoxConfig {
  const siteRules = getSiteRules(siteRouteSpecs);
  const routeRules = [
    ...routePriorSiteRules,
    ...siteRules,
    ...routeAfterSiteRules,
  ];
  const dnsConfig: DNSConfig = {
    "rules": dnsRules as DNSRule[],
    "servers": dnsServers,
    "final": "dns_proxy",
    "strategy": "ipv4_only",
    disable_cache: false,
    disable_expire: false,
    independent_cache: true,
    cache_capacity: 4096,
    reverse_mapping: false,
    "fakeip": {
      "enabled": true,
      "inet4_range": "198.18.0.0/15",
      "inet6_range": "fc00::/18"
    }
  }
  // filter out rulesets that are not used
  const usedRulesetTags = getUsedRulesetTags(routeRules, dnsConfig.rules);
  const usedRulesets = allRuleSets.filter((ruleset) => usedRulesetTags.includes(ruleset.tag));
  return {
    ...template,
    dns: dnsConfig,
    outbounds,
    route: {
      rules: routeRules,
      rule_set: usedRulesets,
      final: "final",
      auto_detect_interface: true,
    }
  }
}

const regionSelectorSpecs: OutboundSelectorSpec[] = [
  { "tag": "香港", "regex": /HK|香港/ },
  { "tag": "实验性", "regex": /实验性/ },
  { "tag": "台湾", "regex": /TW|台湾/ },
  { "tag": "新加坡", "regex": /SG|新加坡/ },
  { "tag": "美国", "regex": /US|美国/ },
  { "tag": "日本", "regex": /JP|日本/ },
  { "tag": "智利", "regex": /智利/ }
];

async function asyncmain() {
  const subs: Sub[] = [
  ];
  const outbounds = await getAllOutbounds(subs, regionSelectorSpecs, siteRouteSpecs, 2);
  const config = getConfig(outbounds);
  console.log(JSON.stringify(config, null, 2));
}

asyncmain();

function getUsedRulesetTags(routeRules: RouteRule[], dnsRules: DNSRule[]): string[] {
  // filter out rulesets that are not used
  // @ts-ignore: Bypassing TypeScript's type checking for rule_set property
  const usedRulesetTags: string[] = routeRules.flatMap((rule) => rule.rule_set);
  const dnsUsedRulesetTags: string[] = dnsRules.flatMap((rule) => {
    if (rule.rule_set) {
      return rule.rule_set;
      // @ts-ignore: Bypassing TypeScript's type checking for rule_set property
    } else if (rule.rules) {
      // @ts-ignore: Bypassing TypeScript's type checking for rule_set property
      return rule.rules.flatMap((rule) => rule.rule_set);
    }
  });
  usedRulesetTags.push(...dnsUsedRulesetTags);
  return usedRulesetTags
}