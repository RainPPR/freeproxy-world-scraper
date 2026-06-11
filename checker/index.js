// index.js
import { inspectProxy } from './proxyInspector.js';

const testProxy = 'socks5://52.34.5.79:10808';

console.log('开始检测代理性能与安全性...\n');
const report = await inspectProxy(testProxy, 20000);
console.log('\n========== 检测报告 ==========');
console.log(JSON.stringify(report, null, 2));
