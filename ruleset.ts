export interface RuleSet {
  type?: "inline" | "local" | "remote";
  tag: string;
  format?: "source" | "binary";
  url?: string;
  download_detour?: string;
  update_interval?: string;
}

const rulesetNames = [
  { tag: "S/ni/my_proxy" },
  { tag: "S/ds/reject" },
  { tag: "S/ni/reject-no-drop" }, // block quic
  { tag: "S/ni/reject-drop" }, // block Adobe tracking
  { tag: "S/ds/cdn" },
  { tag: "S/ni/cdn" },
  { tag: "S/ni/stream" },
  { tag: "S/ni/telegram" },
  { tag: "S/ds/apple_cdn" }, // Apple CN CDN
  { tag: "S/ni/microsoft_cdn" }, // Microsoft CN CDN
  { tag: "S/ds/download" },
  { tag: "S/ni/download" },
  { tag: "S/ni/apple_cn" }, // Apple CN services
  { tag: "S/ni/apple_services" }, // Apple non CN
  { tag: "S/ni/microsoft" }, // Microsoft non CN
  { tag: "S/ni/ai" },
  { tag: "S/ni/global" },
  { tag: "S/ni/domestic" },
  { tag: "S/ni/lan" }, // include .local and in-addr.arpa domains

  { tag: "S/ip/reject" }, // bogus-nxdomain.china.conf
  { tag: "S/ip/telegram" },
  { tag: "S/ip/stream" },
  { tag: "S/ip/lan" },
  { tag: "S/ip/domestic" },
  { tag: "S/ip/china_ip" },
  { tag: "S/ip/china_ip_ipv6" },

  { tag: "M/ds/netflix" },
  { tag: "M/ds/youtube" },
  { tag: "M/ds/cn" }, // geosite:cn
  { tag: "M/ds/notcn" }, // geosite:geolocation-!cn

  { tag: "W/ds/pt" }, // private tracker
  { tag: "W/ds/nofakeip" },
  { tag: "W/ds/reject_sideload" }
];

export const allRuleSets: RuleSet[] = rulesetNames.map(({ tag }) => ({
  tag,
  type: "remote",
  url: convertRuleSetNameToURL(tag),
  format: "binary",
  download_detour: "proxy",
  update_interval: "1d",
}));

function convertRuleSetNameToURL(tag: string) {
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