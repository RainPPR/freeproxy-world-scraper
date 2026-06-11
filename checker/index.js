import { inspectProxy } from './proxyInspector';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const CONCURRENCY = 128;
const TIMEOUT_MS = 5000;
const RAW_JSON_PATH = join('.', 'data', 'raw.json');
const OUTPUT_JSON_PATH = join('.', 'data', 'checked.json');
const OUTPUT_TXT_PATH = join('.', 'data', 'checked.txt');

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

// 并发控制检测
async function checkProxiesWithConcurrency(proxies, concurrency) {
    const results = [];
    const queue = [...proxies];
    let processed = 0;
    const total = proxies.length;

    async function worker() {
        while (queue.length > 0) {
            const proxy = queue.shift();
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
            }
        }
    }

    // 启动多个 worker
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

    // 构建输出格式
    const output = passedProxies.map(({ proxyData, report }) => ({
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

    // 写入 JSON 输出文件
    try {
        writeFileSync(OUTPUT_JSON_PATH, JSON.stringify(output, null, 2), 'utf-8');
        console.log(`\nJSON 结果已保存到: ${OUTPUT_JSON_PATH}`);
        console.log(`有效代理数: ${output.length}`);
    } catch (error) {
        console.error('写入 JSON 结果失败:', error.message);
        process.exit(1);
    }

    // 写入 TXT 输出文件（每行一个 JSON 对象，与 raw.txt 格式一致）
    try {
        const txtContent = output.map(item => JSON.stringify(item)).join('\n');
        writeFileSync(OUTPUT_TXT_PATH, txtContent, 'utf-8');
        console.log(`TXT 结果已保存到: ${OUTPUT_TXT_PATH}`);
    } catch (error) {
        console.error('写入 TXT 结果失败:', error.message);
        process.exit(1);
    }
}

main().catch(error => {
    console.error('程序错误:', error);
    process.exit(1);
});
