import axios from "axios";
import { HttpProxyAgent } from "http-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";
// import * as https from "https";

delete process.env.HTTP_PROXY;
delete process.env.HTTPS_PROXY;
delete process.env.http_proxy;
delete process.env.https_proxy;

// 全局本机IP，在模块加载时获取
let localIp = null;

/**
 * 获取本机IP（不用代理）
 * 先尝试 api.ipapi.is，失败再尝试 api-ipv4.ip.sb/ip
 * 都失败则 exit(1)
 */
async function initLocalIp() {
    const plainAxios = axios.create({
        timeout: 10000,
        headers: {
            "User-Agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        },
    });

    // 第一次尝试：api.ipapi.is
    try {
        const res = await plainAxios.get("https://api.ipapi.is/");
        if (res.data && res.data.ip) {
            localIp = res.data.ip;
            // console.log(`[INIT] 本机IP获取成功: ${localIp} (via api.ipapi.is)`);
            return;
        }
    } catch (error) {
        // console.warn(`[INIT] api.ipapi.is 获取失败: ${error.message}`);
    }

    // 第二次尝试：api-ipv4.ip.sb/ip（返回纯文本IP）
    try {
        const res = await plainAxios.get("https://api-ipv4.ip.sb/ip", {
            responseType: "text",
        });
        const ip = res.data.trim();
        if (ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
            localIp = ip;
            // console.log(
            //     `[INIT] 本机IP获取成功: ${localIp} (via api-ipv4.ip.sb/ip)`,
            // );
            return;
        }
    } catch (error) {
        // console.warn(`[INIT] api-ipv4.ip.sb/ip 获取失败: ${error.message}`);
    }

    // 都失败，退出
    // console.error("[INIT] 无法获取本机IP，程序退出");
    process.exit(1);
}

// 立即执行初始化
await initLocalIp();

async function getWithRetry(
    client,
    url,
    options = {},
    maxRetries = 1,
    retryDelayMs = 5000,
) {
    let lastError;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            return await client.get(url, options);
        } catch (error) {
            lastError = error;
            if (attempt < maxRetries) {
                await new Promise((resolve) =>
                    setTimeout(resolve, retryDelayMs),
                );
            }
        }
    }
    throw lastError;
}

/**
 * 将 api-ipv4.ip.sb/geoip 的返回格式转换为 ipapi.is 的 location 格式
 * geoip 格式：{ "organization": "...", "country": "...", "region": "...", "city": "...", "ip": "...", ... }
 * 转换为：{ location: { country: "...", state: "...", city: "...", ... } }
 */
function convertGeoipToLocationFormat(geoipData) {
    if (!geoipData || typeof geoipData !== "object") {
        return null;
    }

    // 构建 location 对象，将 region 重命名为 state
    const location = {
        country: geoipData.country || null,
        country_code: geoipData.country_code || null,
        state: geoipData.region || null, // region 重命名为 state
        region_code: geoipData.region_code || null,
        city: geoipData.city || null,
        timezone: geoipData.timezone || null,
        latitude: geoipData.latitude || null,
        longitude: geoipData.longitude || null,
        zip: geoipData.postal_code || null,
        continent: geoipData.continent_code || null,
    };

    // 构建 ipapi.is 风格的返回结构
    return {
        ip: geoipData.ip || null,
        location: location,
        company: {
            name: geoipData.organization || null,
            isp: geoipData.isp || null,
        },
        asn: {
            asn: geoipData.asn || null,
            org: geoipData.asn_organization || null,
        },
        // 标记这是从 geoip 转换来的数据
        _source: "api-ipv4.ip.sb/geoip",
    };
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
            "Cache-Control": "no-cache, no-store, must-revalidate",
            Pragma: "no-cache",
            Expires: "0",
            Connection: "close",
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

    // 获取出口IP信息
    try {
        // 第一次尝试：api.ipapi.is（不重试，由我们自己控制重试逻辑）
        let ipRes = null;
        let attemptCount = 0;
        const maxAttempts = 2; // 最多2次尝试

        while (attemptCount < maxAttempts) {
            try {
                ipRes = await client.get("https://api.ipapi.is/");
                const exitIp = ipRes.data?.ip;

                // 检查是否与本机IP相同（代理未生效）
                if (exitIp && exitIp === localIp) {
                    // console.warn(
                    //     `[WARN] 代理 ${proxyUrl} 返回IP与本机IP相同 (${exitIp})，重试中... (attempt ${attemptCount + 1})`,
                    // );
                    attemptCount++;
                    if (attemptCount < maxAttempts) {
                        await new Promise((resolve) =>
                            setTimeout(resolve, 2000),
                        );
                        continue;
                    } else {
                        // 两次都是本机IP，标记为需要切换到备份API
                        ipRes = null;
                        break;
                    }
                }

                // IP不同，代理生效，使用这个结果
                break;
            } catch (error) {
                attemptCount++;
                if (attemptCount < maxAttempts) {
                    await new Promise((resolve) => setTimeout(resolve, 2000));
                } else {
                    throw error;
                }
            }
        }

        // 如果 api.ipapi.is 返回的都是本机IP或失败了，使用备份API
        if (!ipRes) {
            // console.log(
            //     `[INFO] 切换到备份API api-ipv4.ip.sb/geoip for ${proxyUrl}`,
            // );
            let backupRes = null;
            let backupAttempts = 0;
            const maxBackupAttempts = 2;

            while (backupAttempts < maxBackupAttempts) {
                try {
                    backupRes = await client.get(
                        "https://api-ipv4.ip.sb/geoip",
                    );
                    // 转换格式到 ipapi.is 风格
                    const converted = convertGeoipToLocationFormat(
                        backupRes.data,
                    );
                    if (converted) {
                        report.exitIpInfo = converted;
                        // console.log(`[INFO] 备份API获取成功 for ${proxyUrl}`);
                        break;
                    } else {
                        throw new Error("备份API返回数据格式无效");
                    }
                } catch (error) {
                    backupAttempts++;
                    // console.warn(
                    //     `[WARN] 备份API尝试 ${backupAttempts} 失败: ${error.message}`,
                    // );
                    if (backupAttempts < maxBackupAttempts) {
                        await new Promise((resolve) =>
                            setTimeout(resolve, 2000),
                        );
                    } else {
                        report.exitIpInfo = null;
                        // console.error(
                        //     `[ERROR] 备份API也失败了 for ${proxyUrl}`,
                        // );
                    }
                }
            }
        } else {
            // 使用 api.ipapi.is 的结果
            report.exitIpInfo = ipRes.data;
        }
    } catch (error) {
        report.exitIpInfo = null;
        // console.error(
        //     `[ERROR] 获取出口IP信息失败 for ${proxyUrl}: ${error.message}`,
        // );
    }

    report.passAll = true;
    return report;
}
