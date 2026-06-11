import axios from "axios";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";
// import * as https from "https";

delete process.env.HTTP_PROXY;
delete process.env.HTTPS_PROXY;
delete process.env.http_proxy;
delete process.env.https_proxy;

async function getWithRetry(client, url, options = {}, maxRetries = 2, retryDelayMs = 5000) {
    let lastError;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            return await client.get(url, options);
        } catch (error) {
            lastError = error;
            if (attempt < maxRetries) {
                await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
            }
        }
    }
    throw lastError;
}

export async function inspectProxy(proxyUrl, timeoutMs = 5000) {
    let httpAgent;
    let httpsAgent;

    if (proxyUrl.startsWith("socks")) {
        const socksAgent = new SocksProxyAgent(
            proxyUrl.replace(/^socks5:\/\//, "socks5h://"),
            {
                keepAlive: false,
            },
        );
        httpAgent = socksAgent;
        httpsAgent = socksAgent;
    } else {
        httpAgent = new HttpProxyAgent(proxyUrl, {
            keepAlive: false,
        });
        httpsAgent = new HttpsProxyAgent(proxyUrl, {
            keepAlive: false,
        });
    }

    const client = axios.create({
        httpAgent: httpAgent,
        httpsAgent: httpsAgent,
        timeout: timeoutMs,
        proxy: false,
        headers: {
            Referer: "https://www.openssh.org/",
            "User-Agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        },
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
        await getWithRetry(client, "http://cp.cloudflare.com/generate_204", {
            validateStatus: (status) => status === 204,
        });
        report.latency = Date.now() - start;
        report.alive = true;
    } catch (error) {
        report.error = { step: "connectivity", message: error.message };
        return report;
    }

    try {
        await getWithRetry(client, "https://www.openssh.org/favicon.ico");
        report.tlsSecure = true;
    } catch (error) {
        report.error = { step: "tls", message: error.message };
        return report;
    }

    try {
        const ipRes = await getWithRetry(client, "https://api.ipapi.is/");
        report.exitIpInfo = ipRes.data;
    } catch (error) {
        report.exitIpInfo = null;
        // report.error = { step: "ipinfo", message: error.message };
        // return report;
    }

    report.passAll = true;
    return report;
}
