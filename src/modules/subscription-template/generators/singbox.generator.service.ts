import _ from 'lodash';

import { Injectable } from '@nestjs/common';

import { SubscriptionTemplateService } from '@modules/subscription-template/subscription-template.service';

import { ResolvedProxyConfig } from '../resolve-proxy/interfaces';

interface Remnawave {
    'include-proxies'?: boolean;
    'select-random-proxy'?: boolean;
    'shuffle-proxies-order'?: boolean;
}

interface OutboundConfig {
    flow?: string;
    method?: string;
    multiplex?: unknown;
    network?: string;
    outbounds?: string[];
    udp_over_tcp?: { enabled: boolean; version: number };
    password?: string;
    server: string;
    server_port: number;
    tag: string;
    tls?: TlsConfig;
    transport?: TransportConfig;
    type: string;
    uuid?: string;
    headers?: Record<string, unknown>;
    path?: string;
    max_early_data?: number;
    early_data_header_name?: string;
    remnawave?: Remnawave;
}

interface TlsConfig {
    alpn?: string[];
    enabled?: boolean;
    insecure?: boolean;
    reality?: {
        enabled: boolean;
        public_key?: string;
        short_id?: string;
    };
    server_name?: string;
    utls?: {
        enabled: boolean;
        fingerprint: string;
    };
}

interface TransportConfig {
    early_data_header_name?: string;
    headers?: Record<string, unknown>;
    max_early_data?: number;
    path?: string;
    service_name?: string;
    type: string;
}

const UNSUPPORTED_TRANSPORTS = new Set(['hysteria', 'kcp', 'xhttp']);
const PROXY_PROTOCOL_TYPES = new Set(['hysteria', 'shadowsocks', 'trojan', 'vless']);
const SELECTOR_TYPES = new Set(['shadowsocks', 'trojan', 'urltest', 'vless']);

@Injectable()
export class SingBoxGeneratorService {
    constructor(private readonly subscriptionTemplateService: SubscriptionTemplateService) {}

    public async generateConfig(
        hosts: ResolvedProxyConfig[],
        overrideTemplateName?: string,
    ): Promise<string> {
        try {
            const config = await this.subscriptionTemplateService.getCachedTemplateByType(
                'SINGBOX',
                overrideTemplateName,
            );

            for (const host of hosts) {
                if (host.metadata.excludeFromSubscriptionTypes.includes('SINGBOX')) continue;
                if (UNSUPPORTED_TRANSPORTS.has(host.transport)) continue;

                const outbound = this.buildOutbound(host);
                if (!outbound) continue;

                (config as Record<string, unknown[]>).outbounds.push(outbound);
            }

            return this.renderConfig(config as Record<string, unknown>);
        } catch {
            return '';
        }
    }

    private buildOutbound(host: ResolvedProxyConfig): OutboundConfig | null {
        try {
            const config: OutboundConfig = {
                type: host.protocol,
                tag: host.finalRemark,
                server: host.address,
                server_port: host.port,
            };

            if (!this.applyProtocolFields(config, host)) {
                return null;
            }

            this.applyTransport(config, host);
            this.applySecurity(config, host);

            return config;
        } catch {
            return null;
        }
    }

    /**
     * Extract include/exclude regex directives from outbounds array.
     * Removes directive strings and returns filtering config.
     */
    private extractRegexDirectives(outbounds: string[]): {
        includePatterns: string[];
        excludePatterns: string[];
        cleanedOutbounds: string[];
    } {
        const includePatterns: string[] = [];
        const excludePatterns: string[] = [];
        const cleanedOutbounds: string[] = [];

        for (const item of outbounds) {
            if (typeof item !== 'string') {
                cleanedOutbounds.push(item);
                continue;
            }

            const includeMatch = item.match(/^include:\s*(.+)$/i);
            const excludeMatch = item.match(/^exclude:\s*(.+)$/i);

            if (includeMatch) {
                includePatterns.push(includeMatch[1].trim());
            } else if (excludeMatch) {
                excludePatterns.push(excludeMatch[1].trim());
            } else {
                cleanedOutbounds.push(item);
            }
        }

        return { includePatterns, excludePatterns, cleanedOutbounds };
    }

    /**
     * Apply regex include/exclude filters to proxy tags.
     */
    private applyRegexFilters(
        tags: string[],
        includePatterns: string[],
        excludePatterns: string[],
    ): string[] {
        let filteredTags = [...tags];

        // Apply include filters (if any)
        if (includePatterns.length > 0) {
            filteredTags = filteredTags.filter((tag) => {
                return includePatterns.some((pattern) => {
                    try {
                        const regex = new RegExp(pattern, 'u');
                        return regex.test(tag);
                    } catch {
                        // Invalid regex, skip this pattern
                        return false;
                    }
                });
            });
        }

        // Apply exclude filters (if any)
        if (excludePatterns.length > 0) {
            filteredTags = filteredTags.filter((tag) => {
                return !excludePatterns.some((pattern) => {
                    try {
                        const regex = new RegExp(pattern, 'u');
                        return regex.test(tag);
                    } catch {
                        // Invalid regex, skip this pattern
                        return true; // Keep tag if exclude pattern is invalid
                    }
                });
            });
        }

        return filteredTags;
    }

    private renderConfig(config: Record<string, unknown>): string {
        const outbounds = config.outbounds as OutboundConfig[];

        const urltestTags = outbounds
            .filter((o) => PROXY_PROTOCOL_TYPES.has(o.type))
            .map((o) => o.tag);

        const selectorTags = outbounds.filter((o) => SELECTOR_TYPES.has(o.type)).map((o) => o.tag);

        /**
         * Process outbounds for proxy assignment with support for:
         * 1. Regex filtering (include/exclude directives)
         * 2. Remnawave custom keys
         * Priority: Regex filtering > Remnawave properties
         */
        for (const outbound of outbounds) {
            // Only process selector and urltest types
            if (outbound.type !== 'selector' && outbound.type !== 'urltest') {
                continue;
            }

            // Determine which tag set to use
            const availableTags = outbound.type === 'urltest' ? urltestTags : selectorTags;

            // Initialize outbounds array if needed
            if (!Array.isArray(outbound.outbounds)) {
                outbound.outbounds = [];
            }

            // Step 1: Extract and remove regex directives from outbounds
            const { includePatterns, excludePatterns, cleanedOutbounds } =
                this.extractRegexDirectives(outbound.outbounds);
            outbound.outbounds = cleanedOutbounds;

            // Step 2: Apply regex filtering to available tags
            let tagsToAdd = this.applyRegexFilters(
                availableTags,
                includePatterns,
                excludePatterns,
            );

            // Step 3: Extract and process remnawave property
            let remnawaveCustom: Remnawave | undefined = undefined;
            if (outbound?.remnawave) {
                remnawaveCustom = outbound.remnawave;
                delete outbound.remnawave; // Clean up before JSON output
            }

            // Step 4: Apply remnawave logic (if present)
            if (remnawaveCustom) {
                // Priority 1: include-proxies = false → skip adding proxies entirely
                if (remnawaveCustom['include-proxies'] === false) {
                    continue;
                }

                // Priority 2: select-random-proxy = true → add one random proxy
                if (remnawaveCustom['select-random-proxy'] === true) {
                    const randomTag = tagsToAdd[Math.floor(Math.random() * tagsToAdd.length)];
                    if (randomTag) {
                        outbound.outbounds.push(randomTag);
                    }
                    continue;
                }

                // Priority 3: shuffle-proxies-order = true → shuffle before adding
                if (remnawaveCustom['shuffle-proxies-order'] === true) {
                    tagsToAdd = _.shuffle(tagsToAdd);
                }
            }

            // Step 5: Append all tags to outbounds (preserves existing entries)
            for (const tag of tagsToAdd) {
                outbound.outbounds.push(tag);
            }
        }

        return JSON.stringify(config, null, 4);
    }

    private applyProtocolFields(config: OutboundConfig, host: ResolvedProxyConfig): boolean {
        switch (host.protocol) {
            case 'vless':
                config.uuid = host.protocolOptions.id;

                if (host.protocolOptions.flow === 'xtls-rprx-vision') {
                    config.flow = host.protocolOptions.flow;
                }
                return true;

            case 'trojan':
                config.password = host.protocolOptions.password;
                return true;

            case 'shadowsocks':
                config.password = host.protocolOptions.password;
                config.method = host.protocolOptions.method;
                config.udp_over_tcp = {
                    enabled: host.protocolOptions.uot,
                    version: host.protocolOptions.uotVersion,
                };
                return true;

            default:
                return false;
        }
    }

    private applyTransport(config: OutboundConfig, host: ResolvedProxyConfig): void {
        switch (host.transport) {
            case 'ws':
                config.transport = this.buildWsTransport(
                    host.transportOptions.path,
                    host.transportOptions.host,
                );
                break;

            case 'httpupgrade':
                config.transport = this.buildHttpUpgradeTransport(
                    host.transportOptions.path,
                    host.transportOptions.host,
                );
                break;

            case 'grpc':
                config.transport = this.buildGrpcTransport(host.transportOptions.serviceName);
                break;

            default:
                break;
        }
    }

    private buildWsTransport(rawPath: string | null, host: string | null): TransportConfig {
        const config: TransportConfig = {
            type: 'ws',
            headers: {},
        };

        let path = rawPath ?? '';

        if (path.includes('?ed=')) {
            const [pathPart, edPart] = path.split('?ed=');
            path = pathPart;
            const parsed = Number(edPart.split('/')[0]);
            if (!isNaN(parsed)) {
                config.max_early_data = parsed;
            }
            config.early_data_header_name = 'Sec-WebSocket-Protocol';
        }

        if (path) {
            config.path = path;
        }

        if (host) {
            config.headers = { Host: host };
        }

        return config;
    }

    private buildHttpUpgradeTransport(
        rawPath: string | null,
        host: string | null,
    ): TransportConfig {
        const config: TransportConfig = {
            type: 'httpupgrade',
            headers: {},
        };

        const path = rawPath ?? '';

        if (path) {
            config.path = path;
        }

        if (host) {
            config.headers = { Host: host };
        }

        return config;
    }

    private buildGrpcTransport(serviceName: string | null): TransportConfig {
        return {
            type: 'grpc',
            service_name: serviceName ?? '',
        };
    }

    private applySecurity(config: OutboundConfig, host: ResolvedProxyConfig): void {
        switch (host.security) {
            case 'tls':
                config.tls = this.buildTlsConfig(host);
                break;
            case 'reality':
                config.tls = this.buildRealityConfig(host);
                break;
            case 'none':
                break;
        }
    }

    private buildTlsConfig(host: Extract<ResolvedProxyConfig, { security: 'tls' }>): TlsConfig {
        const opts = host.securityOptions;
        const config: TlsConfig = {
            enabled: true,
        };

        if (opts.serverName) {
            config.server_name = opts.serverName;
        }

        if (opts.fingerprint) {
            config.utls = {
                enabled: true,
                fingerprint: opts.fingerprint,
            };
        }

        if (opts.allowInsecure) {
            config.insecure = true;
        }

        if (opts.alpn) {
            config.alpn = opts.alpn.split(',').map((a) => a.trim());
        }

        return config;
    }

    private buildRealityConfig(
        host: Extract<ResolvedProxyConfig, { security: 'reality' }>,
    ): TlsConfig {
        const opts = host.securityOptions;
        const config: TlsConfig = {
            enabled: true,
            reality: { enabled: true },
        };

        if (opts.serverName) {
            config.server_name = opts.serverName;
        }

        if (opts.publicKey) {
            config.reality!.public_key = opts.publicKey;
        }

        if (opts.shortId) {
            config.reality!.short_id = opts.shortId;
        }

        config.utls = {
            enabled: true,
            fingerprint: opts.fingerprint || 'chrome',
        };

        return config;
    }
}
