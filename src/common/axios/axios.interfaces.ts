export interface INodeConnectionOpts {
    address: string;
    port: number | null;
    proxyUrl: string | null;
}

export interface IMtlsOptions {
    ca: string;
    cert: string;
    key: string;
}
