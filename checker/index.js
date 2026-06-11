import { inspectProxy } from './proxyInspector';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const CONCURRENCY = 10000;
const TIMEOUT_MS = 30000;
const RAMP_UP_DURATION_MS = 20000;
const RAMP_UP_RATE = 500;
const RAW_JSON_PATH = join('.', 'data', 'raw.json');
const OUTPUT_JSON_PATH = join('.', 'data', 'checked.json');
const OUTPUT_TXT_PATH = join('.', 'data', 'checked.txt');

// IP 信息标志位对应的图标（为 true 时显示）
const IP_FLAG_ICONS = {
    is_bogon: '🚫',      // 无效地址
    is_mobile: '📱',     // 移动网络
    is_satellite: '🛰️',  // 卫星
    is_crawler: '🕷️',    // 爬虫
    is_datacenter: '🏢', // 数据中心
    is_tor: '🧅',        // Tor
    is_proxy: '🎭',      // 代理
    is_vpn: '🔒',        // VPN
    is_abuser: '⚠️'      // 滥用者
};

// 读取原始代理数据
function loadProxies() {
    try {
        const data = readFileSync(RAW_JSON_PATH, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        console.error('读取 raw.json 失败:', error.message);
        process.exit(1);
    }
}

// 将代理数据转换为代理 URL
function buildProxyUrl(proxy) {
    const type = proxy.type;
    const ip = proxy.ip;
    const port = proxy.port;
    return `${type}://${ip}:${port}`;
}

// 检测单个代理
async function checkSingleProxy(proxyData) {
    const proxyUrl = buildProxyUrl(proxyData);
    const report = await inspectProxy(proxyUrl, TIMEOUT_MS);
    return { proxyData, report };
}

// 并发控制检测 - 前60s均摊启动，之后填充空位
async function checkProxiesWithConcurrency(proxies, concurrency) {
    const results = [];
    const queue = [...proxies];
    const total = proxies.length;
    let processed = 0;
    let activeWorkers = 0;
    const startTime = Date.now();
    let rampUpComplete = false;

    async function worker() {
        while (queue.length > 0) {
            // 检查是否需要等待均摊期
            if (!rampUpComplete) {
                const elapsed = Date.now() - startTime;
                const expectedWorkers = Math.min(
                    concurrency,
                    Math.floor((elapsed / 1000) * RAMP_UP_RATE)
                );
                
                if (activeWorkers >= expectedWorkers && elapsed < RAMP_UP_DURATION_MS) {
                    // 等待下一个时间片
                    await new Promise(r => setTimeout(r, 100));
                    continue;
                }
                
                if (elapsed >= RAMP_UP_DURATION_MS) {
                    rampUpComplete = true;
                    console.log('均摊启动结束')
                }
            }

            const proxy = queue.shift();
            if (!proxy) break;
            
            activeWorkers++;
            processed++;
            
            if (processed % 100 === 0 || processed === total) {
                console.log(`进度: ${processed}/${total}`);
            }

            try {
                const result = await checkSingleProxy(proxy);
                results.push(result);
            } catch (error) {
                console.error(`检测失败 ${buildProxyUrl(proxy)}:`, error.message);
                results.push({
                    proxyData: proxy,
                    report: {
                        proxy: buildProxyUrl(proxy),
                        passAll: false,
                        alive: false,
                        latency: -1,
                        tlsSecure: false,
                        exitIpInfo: null,
                        error: { step: 'worker', message: error.message }
                    }
                });
            } finally {
                activeWorkers--;
            }
        }
    }

    // 启动所有 worker，但它们会自己控制启动节奏
    const workers = Array(concurrency).fill().map(() => worker());
    await Promise.all(workers);

    return results;
}

// 主函数
async function main() {
    console.log('开始读取代理数据...');
    const proxies = loadProxies();
    console.log(`共读取 ${proxies.length} 个代理`);
    console.log(`并发数: ${CONCURRENCY}, 超时: ${TIMEOUT_MS}ms\n`);

    console.log('开始检测代理...');
    const startTime = Date.now();
    const results = await checkProxiesWithConcurrency(proxies, CONCURRENCY);
    const duration = (Date.now() - startTime) / 1000;

    // 筛选通过检测的代理
    const passedProxies = results.filter(({ report }) => {
        return report.passAll === true && report.error === null;
    });

    console.log(`\n检测完成，耗时 ${duration.toFixed(2)} 秒`);
    console.log(`通过检测: ${passedProxies.length}/${results.length}`);

    // 构建所有结果的 JSON 输出（包含通过和未通过的）
    const allResultsOutput = results.map(({ proxyData, report }) => ({
        // 原始字段
        ...proxyData,
        // check 字段（包含 alive, latency, tlsSecure）
        check: {
            alive: report.alive,
            latency: report.latency,
            tlsSecure: report.tlsSecure
        },
        // exit_ip_info
        exit_ip_info: report.exitIpInfo
    }));

    // 写入 JSON 输出文件（所有节点）
    try {
        writeFileSync(OUTPUT_JSON_PATH, JSON.stringify(allResultsOutput, null, 4), 'utf-8');
        console.log(`\nJSON 结果已保存到: ${OUTPUT_JSON_PATH}`);
        console.log(`总代理数: ${allResultsOutput.length}`);
    } catch (error) {
        console.error('写入 JSON 结果失败:', error.message);
        process.exit(1);
    }

    // 构建通过的代理的 TXT 输出
    // 格式: type://ip:port#(urlencoded)exit_ip_info.location.country_code (country state city) ip【图标】
    try {
        const txtContent = passedProxies.map(({ proxyData, report }) => {
            const type = proxyData.type;
            const ip = proxyData.ip;
            const port = proxyData.port;

            // 获取 exit_ip_info 或 fallback 到 proxyData
            const exitIpInfo = report.exitIpInfo || {};
            const location = exitIpInfo.location || {};

            // 获取位置信息（优先使用 exit_ip_info，如果没有则 fallback 到 proxyData）
            const countryCode = location.country_code || proxyData.country_code || '';
            const country = location.country || proxyData.country || '';
            const state = location.state || '';  // state 如果不存在则留空
            const city = location.city || proxyData.city || '';
            const exitIp = exitIpInfo.ip || proxyData.ip || '';

            // 构建位置字符串: country state city（空格分隔，state 可能为空）
            const locationParts = [country, state, city].filter(p => p);
            const locationStr = locationParts.join(' ');

            // 构建需要 URL 编码的部分
            const urlencodedPart = encodeURIComponent(`${countryCode} (${locationStr}) ${exitIp}`);

            // 构建图标字符串（只显示为 true 的标志）
            let icons = '';
            if (exitIpInfo) {
                if (exitIpInfo.is_bogon) icons += IP_FLAG_ICONS.is_bogon;
                if (exitIpInfo.is_mobile) icons += IP_FLAG_ICONS.is_mobile;
                if (exitIpInfo.is_satellite) icons += IP_FLAG_ICONS.is_satellite;
                if (exitIpInfo.is_crawler) icons += IP_FLAG_ICONS.is_crawler;
                if (exitIpInfo.is_datacenter) icons += IP_FLAG_ICONS.is_datacenter;
                if (exitIpInfo.is_tor) icons += IP_FLAG_ICONS.is_tor;
                if (exitIpInfo.is_proxy) icons += IP_FLAG_ICONS.is_proxy;
                if (exitIpInfo.is_vpn) icons += IP_FLAG_ICONS.is_vpn;
                if (exitIpInfo.is_abuser) icons += IP_FLAG_ICONS.is_abuser;
            }

            if (icons && icons.trim() !== '') {
                icons = `【${icons}】`;
            }

            return `${type}://${ip}:${port}#${urlencodedPart}${icons}`;
        }).join('\n');

        writeFileSync(OUTPUT_TXT_PATH, txtContent, 'utf-8');
        console.log(`TXT 结果已保存到: ${OUTPUT_TXT_PATH}`);
        console.log(`TXT 有效代理数: ${passedProxies.length}`);
    } catch (error) {
        console.error('写入 TXT 结果失败:', error.message);
        process.exit(1);
    }
}

main().catch(error => {
    console.error('程序错误:', error);
    process.exit(1);
});
