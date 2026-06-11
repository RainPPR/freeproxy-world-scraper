import axios from "axios";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";

/**
 * 统一代理检测函数
 * @param {string} proxyUrl 代理地址，支持 http/https/socks4/socks5
 * @param {number} timeoutMs 超时时间，默认 15000ms
 * @returns {Promise<ProxyReport>}
 */
export async function inspectProxy(proxyUrl, timeoutMs = 15000) {
    let httpAgent;
    let httpsAgent;

    if (proxyUrl.startsWith("socks")) {
        // SOCKS 代理设置
        const socksAgent = new SocksProxyAgent(proxyUrl);
        httpAgent = socksAgent;
        httpsAgent = socksAgent;
    } else {
        // HTTP/HTTPS 代理设置
        httpAgent = new HttpProxyAgent(proxyUrl);
        httpsAgent = new HttpsProxyAgent(proxyUrl);
    }

    const client = axios.create({
        httpAgent,
        httpsAgent,
        timeout: timeoutMs,
        proxy: false
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

    console.log('代理组装完毕，开始检测...');

    // 步骤 1: 检测连通性和延迟
    try {
        const start = Date.now();
        await client.get("https://cp.cloudflare.com/generate_204", {
            validateStatus: (status) => status === 204,
        });
        report.latency = Date.now() - start;
        report.alive = true;
        console.log(`✓ 连通性检测通过，延迟: ${report.latency}ms`);
    } catch (error) {
        console.log('✗ 连通性检测失败:', error.message);
        report.error = { step: 'connectivity', message: error.message };
        return report;
    }

    // 步骤 2: 检测 TLS 安全性
    try {
        await client.get("https://openssh.org");
        report.tlsSecure = true;
        console.log('✓ TLS 安全性检测通过');
    } catch (error) {
        console.log('✗ TLS 安全性检测失败:', error.message);
        report.error = { step: 'tls', message: error.message };
        return report;
    }

    // 步骤 3: 获取出口 IP 信息
    try {
        const ipRes = await client.get("https://api.ipapi.is/");
        report.exitIpInfo = ipRes.data;
        console.log('✓ 出口 IP 信息获取成功');
    } catch (error) {
        console.log('✗ 出口 IP 信息获取失败:', error.message);
        report.error = { step: 'ipinfo', message: error.message };
        return report;
    }

    report.passAll = true;
    console.log('✓ 所有检测通过');

    return report;
}
