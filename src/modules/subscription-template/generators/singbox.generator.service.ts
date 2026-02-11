import _ from 'lodash';

import { Injectable } from '@nestjs/common';

import { SubscriptionTemplateService } from '@modules/subscription-template/subscription-template.service';

import { IFormattedHost } from './interfaces';

interface Remnawave {
    'include-proxies'?: boolean;
    'select-random-proxy'?: boolean;
    'shuffle-proxies-order'?: boolean;
}

interface OutboundConfig {
    flow?: string;
    method?: string;
    multiplex?: any;
    network?: string;
    outbounds?: string[];
    udp_over_tcp?: { enabled: boolean; version: number };
    password?: string;
    server: string;
    server_port: number;
    tag: string;
    tls?: any;
    transport?: any;
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
    headers?: Record<string, any>;
    host?: string | string[];
    max_early_data?: number;
    path?: string;
    service_name?: string;
    type: string;
}

@Injectable()
export class SingBoxGeneratorService {
    constructor(private readonly subscriptionTemplateService: SubscriptionTemplateService) {}

    public async generateConfig(
        hosts: IFormattedHost[],
        overrideTemplateName?: string,
    ): Promise<string> {
        try {
            const config = await this.subscriptionTemplateService.getCachedTemplateByType(
                'SINGBOX',
                overrideTemplateName,
            );

            const proxy_remarks: string[] = [];

            for (const host of hosts) {
                if (!host) {
                    continue;
                }

                this.addHost(host, config, proxy_remarks);
            }

            return this.renderConfig(config);
        } catch {
            return '';
        }
    }

    private addOutbound(config: Record<string, any>, outbound_data: OutboundConfig): void {
        config.outbounds.push(outbound_data);
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

    private renderConfig(config: Record<string, any>): string {
        const urltest_types = ['vless', 'trojan', 'shadowsocks'];
        const urltest_tags = config.outbounds
            .filter((outbound: OutboundConfig) => urltest_types.includes(outbound.type))
            .map((outbound: OutboundConfig) => outbound.tag);

        const selector_tags = config.outbounds
            .filter((outbound: OutboundConfig) => urltest_types.includes(outbound.type))
            .map((outbound: OutboundConfig) => outbound.tag);

        /**
         * Process outbounds for proxy assignment with support for:
         * 1. Regex filtering (include/exclude directives)
         * 2. Remnawave custom keys
         * Priority: Regex filtering > Remnawave properties
         */
        config.outbounds.forEach((outbound: OutboundConfig) => {
            // Only process selector and urltest types
            if (outbound.type !== 'selector' && outbound.type !== 'urltest') {
                return;
            }

            // Determine which tag set to use
            const availableTags = outbound.type === 'urltest' ? urltest_tags : selector_tags;

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
                    return;
                }

                // Priority 2: select-random-proxy = true → add one random proxy
                if (remnawaveCustom['select-random-proxy'] === true) {
                    const randomTag = tagsToAdd[Math.floor(Math.random() * tagsToAdd.length)];
                    if (randomTag) {
                        outbound.outbounds.push(randomTag);
                    }
                    return;
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
        });

        return JSON.stringify(config, null, 4);
    }

    private tlsConfig(
        sni?: string,
        fp?: string,
        tls?: string,
        pbk?: string,
        sid?: string,
        alpn?: string | string[],
        allowInsecure?: boolean,
    ): TlsConfig {
        const config: TlsConfig = {};

        if (tls === 'tls' || tls === 'reality') {
            config.enabled = true;
        }

        if (sni) {
            config.server_name = sni;
        }

        if (tls === 'reality') {
            config.reality = { enabled: true };
            if (pbk) {
                config.reality.public_key = pbk;
            }
            if (sid) {
                config.reality.short_id = sid;
            }
        }

        if (fp) {
            config.utls = {
                enabled: Boolean(fp),
                fingerprint: fp,
            };
        }

        if (allowInsecure) {
            config.insecure = allowInsecure;
        }

        if (!fp && tls === 'reality') {
            config.utls = {
                enabled: true,
                fingerprint: 'chrome',
            };
        }

        if (alpn) {
            if (typeof alpn === 'string' && alpn.includes(',')) {
                config.alpn = alpn.split(',').map((a) => a.trim());
            } else {
                config.alpn = Array.isArray(alpn) ? alpn : [alpn];
            }
        }

        return config;
    }

    private wsConfig(
        settings: Record<string, any> | undefined,
        host: string = '',
        path: string = '',
        max_early_data?: number,
        early_data_header_name?: string,
    ): TransportConfig {
        const config = structuredClone(settings?.wsSettings || { headers: {} });

        if (!config.headers) {
            config.headers = {};
        }

        if (path) {
            config.path = path;
        }
        if (host) {
            config.headers.Host = host;
        }

        if (max_early_data !== undefined) {
            config.max_early_data = max_early_data;
        }
        if (early_data_header_name) {
            config.early_data_header_name = early_data_header_name;
        }

        return config;
    }

    private httpUpgradeConfig(
        settings: Record<string, any> | undefined,
        host: string = '',
        path: string = '',
    ): TransportConfig {
        const config = structuredClone(settings?.httpupgradeSettings || { headers: {} });

        if (!config.headers) {
            config.headers = {};
        }

        if (path) {
            config.path = path;
        }
        if (host) {
            config.headers.Host = host;
        }

        return config;
    }

    private transportConfig(
        settings: Record<string, any> | undefined,
        transport_type: string = '',
        host: string = '',
        path: string = '',
        max_early_data?: number,
        early_data_header_name?: string,
    ): TransportConfig {
        let transport_config: TransportConfig = { type: transport_type };

        if (transport_type) {
            switch (transport_type) {
                case 'ws':
                    transport_config = this.wsConfig(
                        settings,
                        host,
                        path,
                        max_early_data,
                        early_data_header_name,
                    );
                    break;
                case 'httpupgrade':
                    transport_config = this.httpUpgradeConfig(settings, host, path);
                    break;
            }
        }

        transport_config.type = transport_type;
        return transport_config;
    }

    private makeOutbound(params: IFormattedHost, settings?: Record<string, any>): OutboundConfig {
        const config: OutboundConfig = {
            type: params.protocol,
            tag: params.remark,
            server: params.address,
            server_port: params.port,
        };

        if (params.flow === 'xtls-rprx-vision') {
            config.flow = params.flow;
        }

        if (params.protocol === 'shadowsocks') {
            config.udp_over_tcp = {
                enabled: true,
                version: 2,
            };
        }

        if (['httpupgrade', 'ws'].includes(params.network)) {
            let max_early_data: number | undefined;
            let early_data_header_name: string | undefined;

            if (params.path.includes('?ed=')) {
                const [pathPart, edPart] = params.path.split('?ed=');
                params.path = pathPart;
                [max_early_data] = edPart.split('/').map(Number);
                early_data_header_name = 'Sec-WebSocket-Protocol';
            }

            config.transport = this.transportConfig(
                settings,
                params.network,
                params.host,
                params.path,
                max_early_data,
                early_data_header_name,
            );
        }

        if (['reality', 'tls'].includes(params.tls)) {
            config.tls = this.tlsConfig(
                params.sni,
                params.fingerprint,
                params.tls,
                params.publicKey,
                params.shortId,
                params.alpn,
                params.allowInsecure,
            );
        }
        return config;
    }

    private addHost(
        host: IFormattedHost,
        config: Record<string, any>,
        proxy_remarks: string[],
    ): void {
        try {
            if (host.network === 'xhttp') {
                return;
            }

            const remark = host.remark;
            proxy_remarks.push(remark);

            const outbound = this.makeOutbound(host);

            switch (host.protocol) {
                case 'vless':
                    outbound.uuid = host.password.vlessPassword;
                    break;
                case 'trojan':
                    outbound.password = host.password.trojanPassword;
                    break;
                case 'shadowsocks':
                    outbound.password = host.password.ssPassword;
                    outbound.method = 'chacha20-ietf-poly1305';
                    break;
            }

            this.addOutbound(config, outbound);
        } catch {
            // silence error
        }
    }
}
