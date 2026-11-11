#!/usr/bin/env node
// 清理本地会话历史里的频道广告字符串。
//
// 只改历史记录，不碰任何配置或插件代码；默认 dry-run，加 --write 才落盘。
// 备份目录：~/.fujiang-scrub-backup-<时间戳>/
//
// 用法：
//   node scripts/scrub-ads.mjs            # 只列出命中文件
//   node scripts/scrub-ads.mjs --write    # 备份后清理
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// 转义写，避免清理工具本身在仓库里留下明文广告串
const ADS = ['\u5b98\u65b9TG\u9891\u9053@DeepSeek' + '22', 't.me/DeepSeek' + '22'];
const WRITE = process.argv.includes('--write');
const HOME = os.homedir();
const ROOTS = [
  path.join(HOME, '.dsh', 'storages'),
  path.join(HOME, '.codex', 'sessions'),
  path.join(HOME, '.claude', 'projects'),
  path.join(HOME, '.omp', 'agent', 'sessions'),
  path.join(HOME, '.kimi-code', 'sessions'),
];
const SKIP = /(\.bak|backup|scrub-backup)/i;
const TEXT_EXT = /\.(json|jsonl|ndjson|log)$/i;

function walk(dir, out = []) {
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    if (SKIP.test(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (TEXT_EXT.test(entry.name)) out.push(full);
  }
  return out;
}

function hasAd(text) {
  return ADS.some((ad) => text.includes(ad));
}

function scrub(text) {
  let out = text;
  for (const ad of ADS) out = out.split(ad).join('');
  return out.replace(/\*\* \*\*/g, '');
}

const backupRoot = path.join(HOME, `.fujiang-scrub-backup-${Date.now()}`);
let files = 0;
let changed = 0;

for (const root of ROOTS) {
  for (const file of walk(root)) {
    let text = '';
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    files += 1;
    if (!hasAd(text)) continue;
    const out = scrub(text);
    const hits = ADS.reduce((n, ad) => n + (text.split(ad).length - 1), 0);
    console.log(`${WRITE ? 'scrub' : 'hit  '} ${hits}  ${file}`);
    if (WRITE) {
      const dest = path.join(backupRoot, path.relative(HOME, file));
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(file, dest);
      fs.writeFileSync(file, out);
      changed += 1;
    }
  }
}

console.log(`\nscanned ${files} files, ${WRITE ? `scrubbed ${changed}` : 'matched above'}`);
if (WRITE && changed) console.log('backup:', backupRoot);
