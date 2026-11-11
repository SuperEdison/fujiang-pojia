#!/usr/bin/env node
// 富江破甲 · 知识库指纹匹配 CLI（与插件同一内核）
// node bin/kb-match.mjs --port 443 --banner "Apache/2.4.49" [--product apache] [--limit 8] [--json]
import { match, loadEntries } from '../plugin/lib/core.mjs';

const argv = process.argv.slice(2);
const q = { port: null, banner: '', product: '', version: '', limit: 8, json: false };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--json') q.json = true;
  else if (a === '--port') q.port = Number(argv[++i]);
  else if (a === '--banner') q.banner = argv[++i] || '';
  else if (a === '--product') q.product = argv[++i] || '';
  else if (a === '--version') q.version = argv[++i] || '';
  else if (a === '--limit') q.limit = Number(argv[++i]);
  else if (!a.startsWith('--') && !q.banner) q.banner = a;
}

const hits = match(q);
if (q.json) {
  console.log(JSON.stringify({ query: q, total: loadEntries().length, hits }, null, 2));
  process.exit(0);
}
console.log(`知识库 ${loadEntries().length} 条；查询 port=${q.port ?? '-'} banner="${q.banner}"；命中 ${hits.length}`);
hits.forEach((h, i) => {
  console.log(`${String(i + 1).padStart(2)}. [${h.score}] ${h.cve || '无CVE'} · ${h.severity} · ${h.title}`);
  console.log(`    技能 ${h.category}｜文件 ${h.file}｜理由 ${h.reason.join('、')}`);
  if (h.versions) console.log(`    影响版本 ${h.versions}`);
  if (h.entry) console.log(`    入口 ${h.entry}`);
});
if (!hits.length) console.log('无命中：换端口 / 产品名，或用 skill_search 关键词检索。');
