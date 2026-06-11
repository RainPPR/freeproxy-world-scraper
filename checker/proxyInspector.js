import axios from "axios";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";
// import * as https from "https";

export async function inspectProxy(proxyUrl, timeoutMs = 5000) {
    let httpAgent;
    let httpsAgent;

    if (proxyUrl.startsWith("socks")) {
        const socksAgent =  new SocksProxyAgent(proxyUrl.replace(/^socks5:\/\//, 'socks5h://'))
        httpAgent = socksAgent;
        httpsAgent = socksAgent;
    } else {
        httpAgent = new HttpProxyAgent(proxyUrl);
        httpsAgent = new HttpsProxyAgent(proxyUrl);
    }

    const client = axios.create({
        httpAgent,
        httpsAgent,
        timeout: timeoutMs,
        proxy: false,
        headers: {
            'Referer': 'https://www.openssh.org/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36'
        }
    });

    const report = {
        proxy: proxyUrl,
        passAll: false,
        alive: false,
        latency: -1,
        tlsSecure: false,
        exitIpInfo: null,
        error: null,
    };

    try {
        const start = Date.now();
        await client.get("http://cp.cloudflare.com/generate_204", {
            validateStatus: (status) => status === 204,
        });
        report.latency = Date.now() - start;
        report.alive = true;
    } catch (error) {
        report.error = { step: "connectivity", message: error.message };
        return report;
    }

    try {
        await client.get("https://www.openssh.org/favicon.ico");
        report.tlsSecure = true;
    } catch (error) {
        report.error = { step: "tls", message: error.message };
        return report;
    }

    try {
        const ipRes = await client.get("https://api.ipapi.is/");
        report.exitIpInfo = ipRes.data;
    } catch (error) {
        report.error = { step: "ipinfo", message: error.message };
        return report;
    }

    report.passAll = true;
    return report;
}
