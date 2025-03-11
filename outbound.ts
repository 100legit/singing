import * as https from 'node:https';
import { SiteRouteSpec } from './main';

/**
 * All possible outbound types
 */
type OutboundType =
  | "direct"
  | "block"
  | "socks"
  | "http"
  | "shadowsocks"
  | "vmess"
  | "trojan"
  | "wireguard"
  | "hysteria"
  | "vless"
  | "shadowtls"
  | "tuic"
  | "hysteria2"
  | "anytls"
  | "tor"
  | "ssh"
  | "dns"
  | "selector"
  | "urltest";

/**
 * Node means an endpoint that can be connected to.
 */
type NodeType =
  | "socks"
  | "http"
  | "shadowsocks"
  | "vmess"
  | "trojan"
  | "wireguard"
  | "hysteria"
  | "vless"
  | "shadowtls"
  | "tuic"
  | "hysteria2"
  | "anytls"
  | "ssh";

/**
 * Function to check if the outbound type have a IP / domain
 * @param type - The outbound type to check
 * @returns True if the type is a node type, false otherwise
 */
function isNode(outbound: OutboundConfig): outbound is Node {
  return 'server' in outbound;
}

/**
 * Base outbound configuration
 */
export interface OutboundConfig {
  type: OutboundType;
  tag: string;
}

interface DirectOutbound extends OutboundConfig {
  type: "direct";
  routing_mark?: number;
}

interface Node extends OutboundConfig {
  type: NodeType;
  server: string;
  routing_mark?: number;
}

interface ShadowsocksNode extends Node {
  type: "shadowsocks"; // Must be "shadowsocks" for Shadowsocks outbound.
  server: string; // Server address for Shadowsocks.
  server_port: number; // Server port for Shadowsocks.
  method: ShadowsocksMethod; // Encryption method for Shadowsocks.
  password: string; // Password for Shadowsocks.
  plugin?: string; // Optional plugin for Shadowsocks, e.g., "obfs-local".
  plugin_opts?: string; // Options for the Shadowsocks plugin.
  network?: "tcp" | "udp"; // Network type, default is both.
  udp_over_tcp?: boolean; // Enable UDP over TCP.
  multiplex?: MultiplexOutboundConfig; // Optional multiplexing configuration.
}

/**
 * Supported encryption methods for Shadowsocks
 */
type ShadowsocksMethod =
  | "2022-blake3-aes-128-gcm"
  | "2022-blake3-aes-256-gcm"
  | "2022-blake3-chacha20-poly1305"
  | "none"
  | "aes-128-gcm"
  | "aes-192-gcm"
  | "aes-256-gcm"
  | "chacha20-ietf-poly1305"
  | "xchacha20-ietf-poly1305";

interface MultiplexOutboundConfig {
  enabled?: boolean; // If true, enables multiplexing.
  max_connections?: number; // Maximum connections allowed.
  min_streams?: number; // Minimum multiplexed streams before opening a new connection.
  max_streams?: number; // Maximum multiplexed streams before opening a new connection.
}

async function polyFetch(url: string, user_agent: string): Promise<string> {
  if (typeof window === 'undefined') {
    return new Promise((resolve, reject) => {
      https.get(url, { headers: { 'Accept': '*/*', 'User-Agent': user_agent } }, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve(data);
        });
      }).on('error', (err) => {
        reject(err);
      });
    });
  } else {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': '*/*',
        'User-Agent': user_agent
      }
    });
    return await response.text();
  }
}

export async function getSingBoxSub(url: string): Promise<Node[]> {
  const user_agent = 'sing-box';
  const res = await polyFetch(url, user_agent);
  const outbounds = JSON.parse(res)["outbounds"] as OutboundConfig[];
  return outbounds.filter((outbound) => isNode(outbound));
}

/**
 * SIP008 Online Configuration Delivery server object
 */
interface ShadowsocksSIP008Server {
  id?: string;
  remarks: string;
  server: string;
  server_port: string;
  password: string;
  method: ShadowsocksMethod;
  plugin?: string;
  plugin_opts?: string;
}

export async function getShadowsocksSIP008Sub(url: string): Promise<ShadowsocksNode[]> {
  const user_agent = 'Shadowsocks';
  const res = await polyFetch(url, user_agent);
  const servers = JSON.parse(res) as ShadowsocksSIP008Server[];
  const outbounds: ShadowsocksNode[] = servers.map((sip008Node) => {
    return {
      type: "shadowsocks",
      tag: sip008Node.remarks,
      server: sip008Node.server,
      server_port: parseInt(sip008Node.server_port),
      method: sip008Node.method,
      password: sip008Node.password,
      ...(sip008Node.plugin ? { "plugin": sip008Node.plugin, "plugin_opts": sip008Node.plugin_opts } : {}),
    };
  });
  return outbounds;
}

interface Selector extends OutboundConfig {
  type: "selector";
  outbounds: string[];
  default?: string;
  interrupt_exist_connections?: boolean;
}

export type OutboundSelectorSpec = {
  tag: string;
  regex: RegExp;
}

function getSelectorFromSpec(outbounds: OutboundConfig[], spec: OutboundSelectorSpec): Selector|null {
  const filteredOutbounds = outbounds.filter((outbound) => spec.regex.test(outbound.tag));
  if (filteredOutbounds.length === 0) {
    return null
  }
  return {
    "type": "selector",
    "tag": spec.tag,
    "outbounds": filteredOutbounds.map((outbound) => outbound.tag)
  };
}

function getOtherSelector(outbounds: OutboundConfig[], selectedTags: Set<string>): Selector|null {
  const otherOutbounds = outbounds.filter(outbound => !selectedTags.has(outbound.tag));
  if (otherOutbounds.length > 0) {
    return {
      "type": "selector",
      "tag": "其他节点",
      "outbounds": otherOutbounds.map(outbound => outbound.tag)
    };
  } else {
    return null;
  }
}

export interface Sub {
  url: string;
  user_agent: "sing-box" | "Shadowsocks";
}

export async function getNodesFromSubs(subs: Sub[]): Promise<Node[]> {
  const nodes = (await Promise.all(subs.map(async (sub) => {
    if (sub.user_agent === "sing-box") {
      return await getSingBoxSub(sub.url);
    } else if (sub.user_agent === "Shadowsocks") {
      return await getShadowsocksSIP008Sub(sub.url);
    }
  }))).flat().filter(node => node !== undefined);
  return nodes;
}

function getSiteSelector(siteRouteSpec: SiteRouteSpec, outbounds: OutboundConfig[]): Selector {
  return {
    "tag": siteRouteSpec.tag,
    "type": "selector",
    "outbounds": outbounds.map(selector => selector.tag),
    "default": siteRouteSpec.default
  }
}

export async function getAllOutbounds(subs: Sub[], regionSelectorSpecs: OutboundSelectorSpec[], siteRouteSpec: SiteRouteSpec[], routing_mark?: number): Promise<OutboundConfig[]> {
  const nodes = await getNodesFromSubs(subs);
  // add routing mark to each node
  if (routing_mark) {
    nodes.forEach((node, index) => {
      node.routing_mark = routing_mark;
    });
  }
  
  const regionSelectors: Selector[] = regionSelectorSpecs.map((spec) => {
    return getSelectorFromSpec(nodes, spec);
  }).filter(value => value !== null);
  // Generate a selector for nodes that are not in any selector
  const selectedTags = new Set(regionSelectors.flatMap(selector => selector.outbounds));
  const otherSelector = getOtherSelector(nodes, selectedTags);
  if (otherSelector !== null) {
    regionSelectors.push(otherSelector);
  }

  const siteSelectors = siteRouteSpec.map((spec) => {
    return getSiteSelector(spec, nodes);
  });

  const proxySelector: Selector = {
    "type": "selector" as const,
    "tag": "proxy",
    "outbounds": regionSelectors.map(selector => selector.tag),
    "default": regionSelectorSpecs[0].tag
  };
  const finalSelector: Selector = {
    "type": "selector" as const,
    "tag": "final",
    "outbounds": ["proxy", "direct"],
  }
  const directOutbound: DirectOutbound = {
    "tag": "direct",
    "type": "direct",
    ...(routing_mark ? { "routing_mark": routing_mark } : {})
  };

  return [
    directOutbound,
    proxySelector,
    finalSelector,
    ...siteSelectors,
    ...regionSelectors,
    ...nodes,
  ]
}