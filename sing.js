function isNode(outbound) {
  return 'server' in outbound;
}

class NodeSource {
  constructor(url, user_agent) {
    this.url = url;
    this.user_agent = user_agent;
  }
  async get() {
    const response = await fetch(this.url, {
      headers: {
        'User-Agent': this.user_agent
      }
    });
    return response.text();
  }
}

class SingBoxNodeSource extends NodeSource {
  constructor(url, user_agent = 'sing-box') {
    super(url, user_agent);
  }
  async get() {
    const text = await super.get();
    return JSON.parse(text)["outbounds"].filter(isNode);
  }
}

class SIP008NodeSource extends NodeSource {
  constructor(url, user_agent = 'Shadowsocks') {
    super(url, user_agent);
  }
  async get() {
    const text = await super.get();
    const servers = JSON.parse(text);
    return servers.map(sip008Node => {
      return {
        type: "shadowsocks",
        tag: sip008Node.remarks,
        server: sip008Node.server,
        server_port: parseInt(sip008Node.server_port),
        method: sip008Node.method,
        password: sip008Node.password,
        ...(sip008Node.plugin ? {
          "plugin": sip008Node.plugin,
          "plugin_opts": sip008Node.plugin_opts
        } : {})
      };
    });
  }
}

class Outbound {
  tag;
}

class Direct extends Outbound {
  static tag = "DirectOut";
  static routing_mark = null;
  static get() {
    return {
      tag: Direct.tag,
      type: "direct",
      ...(Direct.routing_mark ? { routing_mark: Direct.routing_mark } : {})
    }
  }
}

/**
 * Selector config. For selecting nodes.
 */
class Selector extends Outbound {
  constructor(tag = "blank", outbounds, _default, interrupt_exist_connections = false) {
    super();
    this.tag = tag;
    if (outbounds) {
      this.outbounds = outbounds.map(outbound => {
        if (typeof outbound === 'string') {
          return outbound;
        } else {
          return outbound.tag;
        }
      });
    }
    if (typeof _default === 'string') {
      this.default = _default;
    } else if (_default && 'tag' in _default) {
      this.default = _default.tag;
    } else {
      this.default = this.outbounds[0];
    }
    this.interrupt_exist_connections = interrupt_exist_connections;
  }
  get() {
    if (!this.outbounds || this.outbounds.length === 0) {
      return null;
    }
    return {
      tag: this.tag,
      type: "selector",
      outbounds: this.outbounds,
      ...(this.default ? { default: this.default } : {}),
      ...(this.interrupt_exist_connections ? { interrupt_exist_connections: this.interrupt_exist_connections } : {})
    }
  }
}

class ProxySelector extends Selector {
  static tag = "ProxySel";
  constructor(outbounds, _default) {
    super(ProxySelector.tag, outbounds, _default);
  }
}

class FinalSelector extends Selector {
  static tag = "FinalSel";
  constructor(outbounds, _default) {
    super(FinalSelector.tag, outbounds, _default);
  }
}

class RegionSelector extends Selector {
  constructor(spec, nodes) {
    if (!spec) {
      throw new TypeError('Region selector spec not found');
    }
    if (!spec.tag || typeof spec.tag !== 'string') {
      throw new TypeError('Region tag must be a string');
    } else if (!spec.regex || typeof spec.regex !== 'object') {
      throw new TypeError('Region regex not found');
    }
    super(spec.tag, nodes.filter((n) => spec.regex.test(n.tag)), spec.default);
  }
}

class SiteSelector extends Selector {
  constructor(siteSpec, outbounds) {
    if (!siteSpec) {
      throw new TypeError('Site selector spec not found');
    }
    if (!siteSpec.tag || typeof siteSpec.tag !== 'string') {
      throw new TypeError('Site tag must be a string');
    }
    super(siteSpec.tag, outbounds, siteSpec.default);
  }
}

class DnsServer {
  constructor(tag, address, detour, strategy) {
    if (!tag || typeof tag !== 'string') {
      throw new TypeError('DNS tag must be a string');
    }
    this.tag = tag;
    this.address = address;
    this.detour = detour;
    this.strategy = strategy;
  }
  getLegacy() {
    return {
      tag: this.tag,
      address: this.address,
      ...(this.detour ? { detour: this.detour } : {}),
      ...(this.strategy ? { strategy: this.strategy } : {})
    }
  }
}

class DirectDnsServer extends DnsServer {
  static tag = "DirectDNS";
  constructor(address, strategy) {
    super(DirectDnsServer.tag, address, Direct.tag, strategy);
  }
}
class ProxyDnsServer extends DnsServer {
  static tag = "ProxyDNS";
  constructor(address, strategy) {
    super(ProxyDnsServer.tag, address, ProxySelector.tag, strategy);
  }
}
class DirectPreferV6DnsServer extends DnsServer {
  static tag = "DirectPreferV6DNS";
  static strategy = "prefer_ipv6";
  constructor(address) {
    super(DirectPreferV6DnsServer.tag, address, Direct.tag, DirectPreferV6DnsServer.strategy);
  }
}
class FakeIpDnsServer extends DnsServer {
  static tag = "FakeIPDNS";
  static inet4_range = "198.18.0.0/15";
  static inet6_range = "fc00::/18";
  constructor() {
    super(FakeIpDnsServer.tag, "fakeip");
  }
}


function guessNodeSourcefromURL(url) {
  if (url.includes('ss=1')) {
    return new SIP008NodeSource(url);
  } else {
    return new SingBoxNodeSource(url);
  }
}
function convertRuleSetNameToURL(tag) {
  const [source, type, path] = tag.split("/");
  // Expand abbreviations
  const expandedType = type === "ni" ? "non_ip" :
    type === "ds" ? "domainset" :
      type; // "ip" remains unchanged
  switch (source) {
    case "S":
      return `https://github.com/100legit/singbox-set/raw/sing/${expandedType}/${path}.srs`;
    case "M":
      return `https://github.com/100legit/singbox-set/raw/sing/metacubex/${expandedType}/${path}.srs`;
    case "W":
      return `https://github.com/100legit/singbox-set/raw/sing/own/${expandedType}/${path}.srs`;
    default:
      return tag;
  }
}

const ENABLE_TUN_AUTO_ROUTE = true;
const ENABLE_TPROXY = false;
const ENABLE_TUN = true;
const LOG_LEVEL = "debug";
const CLASH_API_SECRET = "123";
const DEFAULT_MARK = 2;
const template = {
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
    "detour": Direct.tag
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "store_fakeip": true,
      "store_rdrc": true
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": CLASH_API_SECRET,
      "external_ui": "ui",
      "external_ui_download_url": "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip",
      "external_ui_download_detour": ProxySelector.tag,
      "default_mode": "Rule"
    }
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
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
      "strict_route": false,
      "route_exclude_address_set": [
        "S/ip/apple_services",
        "S/ip/china_ip",
        "S/ip/china_ip_ipv6"
      ],
      "platform": {
        "http_proxy": {
          "enabled": true,
          "server": "127.0.0.1",
          "server_port": 7080,
          "bypass_domain": [
            "push.apple.com"
          ],
        }
      },
    } : undefined,
  ].filter(Boolean),
};
const regionSelectorSpecs = [
  { "tag": "香港", "regex": /HK|香港/ },
  { "tag": "实验性", "regex": /实验性/ },
  { "tag": "台湾", "regex": /TW|台湾/ },
  { "tag": "新加坡", "regex": /SG|新加坡/ },
  { "tag": "美国", "regex": /US|美国/ },
  { "tag": "日本", "regex": /JP|日本/ },
  { "tag": "智利", "regex": /智利/ },
  { "tag": "Test", "regex": /Test/ }
];
const siteSpecs = [
  { tag: "telegram", rulesetTags: ["S/ni/telegram", "S/ip/telegram"], default: "香港" },
  { tag: "ai-services", rulesetTags: ["S/ni/ai"], default: "日本" },
  { tag: "youtube", rulesetTags: ["M/ds/youtube"], default: "香港" },
  { tag: "netflix", rulesetTags: ["M/ds/netflix"], default: "香港" },
  { tag: "cloudflare", rulesetTags: ["M/ds/cloudflare"], default: "香港" },
]

const dnsRules = [
  {
    outbound: "any",
    server: DirectDnsServer.tag
  },
  { rule_set: ["W/ds/pt"], server: DirectPreferV6DnsServer.tag },
  {
    rule_set: [
      "S/ni/my_proxy",
      "S/ds/reject"
    ], server: FakeIpDnsServer.tag
  },
  // Site-specific DNS use fakeip
  ...siteSpecs.map(site => ({
    rule_set: site.rulesetTags,
    server: FakeIpDnsServer.tag
  })),
  {
    rule_set: [
      "W/ds/direct_nofakeip",
      "S/ni/lan",
      "S/ni/apple_cn",
      "S/ni/apple_cdn",
      "S/ni/apple_services",
      "S/ni/microsoft",
      "S/ni/microsoft_cdn",
      "S/ni/domestic",
      "M/ds/cn",
      "S/ip/lan",
      "S/ip/domestic",
      "S/ip/china_ip",
      "S/ip/china_ip_ipv6"
    ], server: DirectDnsServer.tag
  },

  { rule_set: ["S/ni/global", "M/ds/notcn"], server: ProxyDnsServer.tag },
].map(rule => {
  if (!('action' in rule)) {
    rule.action = "route";
  }
  return rule;
});

const routeRules = [
  { "action": "sniff" },
  { "protocol": "dns", "action": "hijack-dns" },
  { "protocol": "quic", "action": "reject" },
  {
    "protocol": "bittorrent",
    "action": "route",
    "outbound": Direct.tag
  },

  { "clash_mode": "Direct", "action": "route", "outbound": Direct.tag },
  { "clash_mode": "Global", "action": "route", "outbound": ProxySelector.tag },

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
  ...siteSpecs.map(site => ({
    rule_set: site.rulesetTags,
    action: "route",
    outbound: site.tag
  })),
  {
    "rule_set": [
      "S/ds/apple_cdn",
      "S/ni/apple_cn",
      "S/ni/apple_services", // Apple 非国区服务域名, 直连
    ],
    "action": "route",
    "outbound": Direct.tag
  },
  {
    "rule_set": [
      "S/ni/microsoft_cdn",
      "S/ni/domestic",
      "S/ni/lan"
    ],
    "action": "route",
    "outbound": Direct.tag
  },
  {
    "rule_set": [
      "M/ds/notcn",
      "S/ni/my_proxy"
    ],
    action: "route",
    "outbound": ProxySelector.tag
  },
  { "action": "resolve" },
  {
    "rule_set": [
      "S/ip/apple_services",
      "S/ip/domestic", // 手工维护的腾讯云 AIA Anycast 业务的 IP 段和阿里云 Anycast 业务的 IP 段
      "S/ip/china_ip", // chnroutes2 with minor fix
      "S/ip/china_ip_ipv6",
    ],
    action: "route",
    "outbound": Direct.tag
  },
  {
    "ip_is_private": true,
    action: "route",
    "outbound": Direct.tag
  }
];

async function getAllOutbounds() {
  const u = Deno.env.get('SUB');
  if (typeof u !== 'string') {
    throw new Error('SUB is not set');
  }
  const urls = u.split(',');
  const nodeSources = urls.map(guessNodeSourcefromURL);
  const n = await Promise.all(nodeSources.map(nodeSource => nodeSource.get()));
  const nodes = n.flat();
  const regionSelectors = regionSelectorSpecs.map(spec => {
    return new RegionSelector(spec, nodes);
  }).filter(selector => selector.get() !== null);
  const siteSelectors = siteSpecs.map(siteSpec => new SiteSelector(siteSpec, regionSelectors.concat(Direct.tag, ProxySelector.tag)));
  return [
    Direct.get(),
    (new ProxySelector(regionSelectors.concat(Direct.tag))).get(),
    (new FinalSelector([ProxySelector.tag, Direct.tag])).get(),
    ...siteSelectors.map(siteSelector => siteSelector.get()),
    ...regionSelectors.map(regionSelector => regionSelector.get()),
    ...nodes,
  ]
}

async function main() {
  const outbounds = await getAllOutbounds();
  const dnsConfig = {
    "rules": dnsRules,
    "servers": [
      new DirectDnsServer("https://223.5.5.5/dns-query").getLegacy(),
      new ProxyDnsServer("tls://1.1.1.1").getLegacy(),
      new DirectPreferV6DnsServer("https://223.5.5.5/dns-query").getLegacy(),
      new FakeIpDnsServer().getLegacy(),
    ],
    "final": ProxyDnsServer.tag,
    "strategy": "ipv4_only",
    disable_cache: false,
    disable_expire: false,
    cache_capacity: 512,
    reverse_mapping: false,
    "fakeip": {
      "enabled": true,
      "inet4_range": FakeIpDnsServer.inet4_range,
      "inet6_range": FakeIpDnsServer.inet6_range
    }
  };
  // filter out rulesets that are not used
  const usedRulesetTags = new Set(getUsedRulesetTags(routeRules, dnsConfig.rules));
  const allRuleSets = Array.from(usedRulesetTags).map(tag => ({
    tag,
    type: "remote",
    url: convertRuleSetNameToURL(tag),
    format: "binary",
    download_detour: ProxySelector.tag,
    update_interval: "1d",
  }));
  const config = {
    "dns": dnsConfig,
    "route": {
      "rules": routeRules,
      "auto_detect_interface": true,
      "final": FinalSelector.tag,
      ...(DEFAULT_MARK ? { default_mark: DEFAULT_MARK } : {}),
      "rule_set": allRuleSets,
    },
    ...template,
    "outbounds": outbounds,
  }
  console.log(JSON.stringify(config, null, 2));
}
main();
function getUsedRulesetTags(routeRules, dnsRules) {
  // filter out rulesets that are not used
  const usedRulesetTags = routeRules.flatMap((rule) => rule.rule_set);
  const dnsUsedRulesetTags = dnsRules.flatMap((rule) => {
    if (rule.rule_set) {
      return rule.rule_set;
    }
    else if (rule.rules) {
      return rule.rules.flatMap((rule) => rule.rule_set);
    }
  });
  usedRulesetTags.push(...dnsUsedRulesetTags);
  return usedRulesetTags.filter(Boolean);
}

