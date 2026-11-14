#!/usr/bin/env node
// 从 GitHub 直接更新本地 DSH 插件。
//
//   node scripts/update.mjs            # 下载最新 main、备份并替换插件目录
//   node scripts/update.mjs --check    # 只检查版本，不写盘
//
// 更新目标：${DSH_HOME:-~/.dsh}/local-plugins/dsh-prompt-custom
// 不会动 ~/.dsh/prompt-custom.json 和 ~/.dsh/vuln-report/。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const REPO = process.env.FUJIANG_REPO || 'SuperEdison/fujiang-pojia';
const HOME = os.homedir();
const DSH_HOME = process.env.DSH_HOME || path.join(HOME, '.dsh');
const TARGET = path.join(DSH_HOME, 'local-plugins', 'dsh-prompt-custom');
const CHECK_ONLY = process.argv.includes('--check');
const TS = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);

function readVersion(dir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version || null;
  } catch {
    return null;
  }
}

async function getJson(url) {
  const response = await fetch(url, {
    headers: { 'user-agent': 'fujiang-pojia-updater', accept: 'application/vnd.github+json' },
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error(`GitHub API ${response.status}：${url}`);
  return response.json();
}

async function download(url, destination) {
  const response = await fetch(url, { signal: AbortSignal.timeout(5 * 60 * 1000) });
  if (!response.ok || !response.body) throw new Error(`下载失败 HTTP ${response.status}`);
  const file = await fs.promises.open(destination, 'wx');
  try {
    for await (const chunk of response.body) await file.writeFile(Buffer.from(chunk));
    await file.sync();
  } finally {
    await file.close();
  }
}

function extract(zip, destination) {
  fs.mkdirSync(destination, { recursive: true });
  const result = spawnSync('tar', ['-xf', zip, '-C', destination], { encoding: 'utf8' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`解压失败：${(result.stderr || result.stdout || '').trim()}`);
  const top = fs.readdirSync(destination).find((name) => {
    try { return fs.statSync(path.join(destination, name)).isDirectory(); } catch { return false; }
  });
  if (!top) throw new Error('压缩包结构异常：找不到顶层目录。');
  return path.join(destination, top, 'plugin');
}

async function main() {
  const commit = await getJson(`https://api.github.com/repos/${REPO}/commits/main`);
  const sha = commit.sha;
  const remoteVersion = await getJson(`https://raw.githubusercontent.com/${REPO}/${sha}/plugin/package.json`);
  const localVersion = readVersion(TARGET);

  console.log(`repo:   ${REPO}`);
  console.log(`commit: ${sha.slice(0, 7)}  ${String(commit.commit?.message || '').split('\n')[0]}`);
  console.log(`remote: ${remoteVersion.version}`);
  console.log(`local:  ${localVersion || '未安装'}`);

  if (CHECK_ONLY) return;
  if (localVersion === remoteVersion.version) {
    console.log('版本一致，仍会同步代码（仓库可能有同版本改动）。');
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fujiang-update-'));
  try {
    const zip = path.join(tmp, 'repo.zip');
    await download(`https://codeload.github.com/${REPO}/zip/${sha}`, zip);
    const source = extract(zip, path.join(tmp, 'extract'));
    const staged = path.join(tmp, 'plugin');
    fs.cpSync(source, staged, { recursive: true });

    if (fs.existsSync(TARGET)) {
      const backup = `${TARGET}.bak-${TS}`;
      fs.renameSync(TARGET, backup);
      console.log(`backup: ${backup}`);
    }
    fs.mkdirSync(path.dirname(TARGET), { recursive: true });
    fs.cpSync(staged, TARGET, { recursive: true });
    console.log(`updated: ${remoteVersion.version} -> ${TARGET}`);
    console.log('完全退出并重启 Harness 后生效。prompt-custom.json 与台账未改动。');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(`[fujiang-update] ${error.message}`);
  process.exitCode = 1;
});
