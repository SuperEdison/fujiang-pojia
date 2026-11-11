// fujiang-core：知识库索引 / 版本区间匹配 / 漏洞台账 / 作业链（插件自带，唯一实现）
// fujiang-core：富江破甲 与宿主无关的内核（知识库索引 / 技能检索 / 漏洞台账 / 作业链）
// 与 dsh-prompt-custom 0.20.12 的匹配口径保持一致：端口 40 / 产品 30 / CVE 20 / 关键词 20 / severity 5
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export const CATEGORY_SKILL = {
  'cloud-container': 'kb-cloud-container',
  'edge-device': 'kb-edge-device',
  'exchange-ad': 'kb-exchange-ad',
  'gray-market': 'kb-gray-market',
  'java-deser': 'kb-java-deser',
  'java-web': 'kb-java-web',
  'linux-priv': 'kb-linux-priv',
  'triage': 'kb-triage',
  'web-cms': 'kb-web-cms',
};

export const STAGES = ['recon', 'fingerprint', 'match', 'verify', 'exploit', 'lateral', 'report'];

export function fujiangHome() {
  return process.env.FUJIANG_HOME || path.join(os.homedir(), '.fujiang');
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
  return p;
}

export function knowledgeRoots() {
  const env = process.env.FUJIANG_KB;
  const candidates = env
    ? [env]
    : [
        path.join(fujiangHome(), 'knowledge'),
        path.join(os.homedir(), '.dsh/local-plugins/dsh-prompt-custom/knowledge'),
        path.join(os.homedir(), '.omp/agent/skills'),
      ];
  const out = [];
  for (const c of candidates) {
    try {
      if (fs.statSync(c).isDirectory() && !out.includes(c)) out.push(c);
    } catch {}
  }
  return out;
}

function frontmatter(text) {
  const m = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!m) return {};
  const fm = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = line.match(/^([A-Za-z_]+):\s*(.*)$/);
    if (kv) fm[kv[1]] = kv[2].trim();
  }
  return fm;
}

const STOPWORDS = new Set(['gateway','server','service','client','web','http','https','httpd','api','admin','login','default','remote','manager','console','portal','access','open','source','code','test','main','index','config','system','vpn','ssl','tls','ipsec','cloud','security','edge','app','gate','proxy','auth']);
const escapeRe = (w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** 整词匹配：active 不能命中 activemq */
const hasWord = (hay, word) => new RegExp('(?:^|[^a-z0-9])' + escapeRe(String(word).toLowerCase()) + '(?:$|[^a-z0-9])').test(hay);
const tokens = (value) => String(value || '')
  .toLowerCase()
  .split(/[^a-z0-9.+_/-]+/)
  .filter((t) => t.length >= 2);

const VERSION_TEXT = /(\d+(?:\.\d+){0,3})/;

function parseVersion(value) {
  const m = String(value || '').match(VERSION_TEXT);
  return m ? m[1].split('.').map(Number) : null;
}

function cmpVersion(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const x = a[i] || 0;
    const y = b[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

const stripNotes = (s) => String(s).replace(/（[^）]*）|\([^)]*\)/g, ' ').trim();

/** 把 `10.2.x` / `10.2` 解析成闭区间；`x` 段表示该位上的全域。 */
function wildcardRange(text) {
  const parts = String(text).split('.');
  const nums = [];
  let wildcardAt = -1;
  for (let i = 0; i < parts.length; i += 1) {
    if (/^[xX*]$/.test(parts[i])) { wildcardAt = i; break; }
    const n = Number(parts[i]);
    if (!Number.isFinite(n)) return null;
    nums.push(n);
  }
  if (!nums.length) return null;
  if (wildcardAt < 0) {
    const v = nums.slice();
    return { min: v, max: v, minIncl: true, maxIncl: true };
  }
  const lo = nums.slice();
  const hi = nums.slice();
  hi[hi.length - 1] += 1;
  return { min: lo, max: hi, minIncl: true, maxIncl: false };
}

/** 单个区间描述 → {min,max,minIncl,maxIncl}；解析失败返回 null。 */
function parseRangePart(raw) {
  const text = stripNotes(raw).trim();
  if (!text) return null;

  let m = text.match(/^([\d.xX*]+(?:\.[\d.xX*]+)*)\s*(?:-|~|至|到)\s*([\d.xX*]+(?:\.[\d.xX*]+)*)/);
  if (m) {
    const lo = wildcardRange(m[1]);
    const hi = wildcardRange(m[2]);
    if (!lo || !hi) return null;
    return { min: lo.min, max: hi.max, minIncl: true, maxIncl: true };
  }

  // 复合：`10.2.x < 10.2.12` —— 通配区间再按比较符收紧
  m = text.match(/^([\d.xX*]+(?:\.[\d.xX*]+)*)\s*(<=?|>=?)\s*([\d.]+(?:\.[\d.]+)*)/);
  if (m) {
    const base = wildcardRange(m[1]);
    const v = parseVersion(m[3]);
    if (!base || !v) return null;
    let { min, max, minIncl, maxIncl } = base;
    if (m[2].startsWith('<')) {
      if (cmpVersion(v, max) < 0) { max = v; maxIncl = m[2] === '<='; }
    } else if (cmpVersion(v, min) > 0) {
      min = v;
      minIncl = m[2] === '>=';
    }
    return { min, max, minIncl, maxIncl };
  }

  m = text.match(/^(<=?|>=?)\s*([\d.]+(?:\.[\d.]+)*)/);
  if (m) {
    const v = parseVersion(m[2]);
    if (!v) return null;
    return m[1] === '<'
      ? { min: null, max: v, minIncl: true, maxIncl: false }
      : m[1] === '<='
        ? { min: null, max: v, minIncl: true, maxIncl: true }
        : m[1] === '>'
          ? { min: v, max: null, minIncl: false, maxIncl: true }
          : { min: v, max: null, minIncl: true, maxIncl: true };
  }

  m = text.match(/^([\d.]+(?:\.[\d.]+)*)\s*(之前|及更早|或更早|以下|及以下)/);
  if (m) {
    const v = parseVersion(m[1]);
    return v ? { min: null, max: v, minIncl: true, maxIncl: true } : null;
  }

  m = text.match(/^([\d.]+(?:\.[\d.]+)*)\s*(之后|及以后|以上|及以上)/);
  if (m) {
    const v = parseVersion(m[1]);
    return v ? { min: v, max: null, minIncl: true, maxIncl: true } : null;
  }

  // 含连接符但无法结构化成区间（如 `2008 R2 - 2019`、`2.0-beta9`）：保守返回 unknown
  if (/[-~至到]/.test(text)) return null;

  m = text.match(/^([\d.xX*]+(?:\.[\d.xX*]+)*)\s*$/);
  if (m) return wildcardRange(m[1]);

  return null;
}

function splitRangeParts(field) {
  return String(field || '')
    .split(/[、,，;；|]/)
    .map((s) => stripNotes(s))
    .filter(Boolean);
}

function inRange(target, range) {
  if (range.min && cmpVersion(target, range.min) < (range.minIncl ? 0 : 1)) return false;
  if (range.max && cmpVersion(target, range.max) > (range.maxIncl ? 0 : -1)) return false;
  return true;
}

/** 'hit' | 'miss' | 'unknown'；unknown 表示区间解析不全，不打负分。 */
export function versionVerdict(field, target) {
  const parts = splitRangeParts(field);
  if (!parts.length || !Array.isArray(target)) return 'unknown';
  let parsed = 0;
  let hit = false;
  for (const part of parts) {
    const range = parseRangePart(part);
    if (!range) continue;
    parsed += 1;
    if (inRange(target, range)) hit = true;
  }
  if (hit) return 'hit';
  if (!parsed) return 'unknown';
  return parsed === parts.length ? 'miss' : 'unknown';
}

/** 从 banner 里兜底提取版本：Apache/2.4.49、nginx 1.18.0、Redis v7.0.5 */
export function versionFromText(text) {
  const m = String(text || '').match(/[A-Za-z][\w.+-]*[\/ ]v?(\d+(?:\.\d+){0,3})/);
  return m ? parseVersion(m[1]) : null;
}

const caches = new Map();

export function loadEntries({ fresh = false, roots } = {}) {
  const useRoots = roots && roots.length ? roots : knowledgeRoots();
  const key = roots && roots.length ? useRoots.join('|') : '*';
  if (!fresh) {
    const cached = caches.get(key);
    if (cached && Date.now() - cached.at < 5000 && cached.items.length) return cached.items;
  }
  const items = [];
  const seen = new Set();
  for (const root of useRoots) {
    let cats = [];
    try {
      cats = fs.readdirSync(root);
    } catch {
      continue;
    }
    for (const cat of cats) {
      const dir = path.join(root, cat);
      let st;
      try {
        st = fs.statSync(dir);
      } catch {
        continue;
      }
      if (!st.isDirectory()) continue;
      let files = [];
      try {
        files = fs.readdirSync(dir);
      } catch {
        continue;
      }
      for (const f of files) {
        if (!f.endsWith('.md') || f === 'SKILL.md') continue;
        const abs = path.join(dir, f);
        let fm = {};
        try {
          fm = frontmatter(fs.readFileSync(abs, 'utf8'));
        } catch {
          continue;
        }
        const key2 = `${fm.cve || ''}|${fm.title || f}`;
        if (seen.has(key2)) continue;
        seen.add(key2);
        items.push({
          category: CATEGORY_SKILL[cat] || cat,
          cat,
          file: path.relative(root, abs),
          abs,
          root,
          cve: fm.cve || '',
          title: fm.title || f,
          severity: fm.severity || 'info',
          cvss: fm.cvss || '',
          product: fm.product || '',
          versions: fm.versions || '',
          ports: fm.ports || '',
          keywords: fm.keywords || '',
          entry: fm.entry || '',
          verified: /true/i.test(fm.verified || ''),
        });
      }
    }
  }
  caches.set(key, { at: Date.now(), items });
  return items;
}

/**
 * 指纹 → 候选条目。唯一评分口径：
 * 端口 40 / 产品 30 / CVE 20 / 关键词 20 / 标题 18 / severity 5；
 * 版本区间命中 +40，明确不在区间 -30（区间解析不全时不扣分）。
 */
export function match(input = {}, entries) {
  const list = Array.isArray(entries) ? entries : loadEntries();
  const ports = [...new Set([
    ...(Array.isArray(input.ports) ? input.ports : []),
    ...(input.port === undefined || input.port === null ? [] : [input.port]),
  ])].map(Number).filter(Number.isFinite);
  const hay = [input.banner, input.product, input.text, ...Object.values(input.headers || {})]
    .filter(Boolean).join(' ').toLowerCase();
  const hayTokens = new Set(tokens(hay));
  const targetVersion = parseVersion(input.version) || versionFromText(hay);
  const limit = Math.max(1, Math.min(20, Number(input.limit) || 8));

  const scored = [];
  for (const it of list) {
    let score = 0;
    const reason = [];
    const itemPorts = it.ports.split(/[,\s]+/).filter(Boolean).map(Number);
    if (ports.length && itemPorts.some((p) => ports.includes(p))) {
      score += 40;
      reason.push(`端口 ${itemPorts.filter((p) => ports.includes(p)).join(',')}`);
    }

    const productHit = tokens(it.product).some((t) => t.length >= 3 && !STOPWORDS.has(t) && hasWord(hay, t));
    if (productHit) {
      score += 30;
      reason.push(`产品 ${it.product}`);
    }

    const cves = it.cve.split(/[,\s]+/).filter(Boolean).map((c) => c.toLowerCase());
    if (hay && cves.some((c) => hasWord(hay, c))) {
      score += 20;
      reason.push('CVE 命中');
    }

    const keywords = it.keywords.split(/[,，、\s]+/).map((k) => k.trim()).filter((k) => k.length >= 2);
    const kwHits = keywords.filter((k) => /[\u4e00-\u9fa5]/.test(k)
      ? hay.includes(k.toLowerCase())
      : k.length >= 3 && !STOPWORDS.has(k.toLowerCase()) && hasWord(hay, k));
    if (kwHits.length) {
      score += Math.min(20, kwHits.length * 10);
      reason.push(`关键词 ${kwHits.slice(0, 4).join('/')}`);
    }

    if (!productHit) {
      const titleHits = tokens(it.title).filter((t) => t.length >= 4 && !STOPWORDS.has(t) && hayTokens.has(t));
      if (titleHits.length) {
        score += Math.min(18, titleHits.length * 6);
        reason.push(`标题 ${titleHits.slice(0, 3).join('/')}`);
      }
    }

    if (/critical|high/i.test(it.severity)) {
      score += 5;
      reason.push(`severity ${it.severity}`);
    }

    // 版本区间只在该产品已命中时才有意义：不同产品的版本号不可比
    if (productHit && targetVersion && it.versions) {
      const verdict = versionVerdict(it.versions, targetVersion);
      if (verdict === 'hit') {
        score += 40;
        reason.push(`版本 ${targetVersion.join('.')} 命中`);
      } else if (verdict === 'miss') {
        score -= 30;
        reason.push(`版本 ${targetVersion.join('.')} 不在区间`);
      }
    }

    if (score <= 0) continue;
    scored.push({ ...it, score, reason });
  }

  scored.sort((a, b) => b.score - a.score || a.file.localeCompare(b.file));
  return scored.slice(0, limit);
}

export function searchSkills(query = '', limit = 8) {
  const q = query.toLowerCase().trim();
  const skills = loadEntries()
    .filter((it) => it.file === undefined || true)
    .reduce((acc, it) => {
      if (!acc[it.category]) acc[it.category] = { name: it.category, cat: it.cat, count: 0, hits: 0, root: it.root };
      acc[it.category].count += 1;
      if (!q) acc[it.category].hits += 1;
      else if (`${it.cve} ${it.title} ${it.product} ${it.keywords} ${it.entry}`.toLowerCase().includes(q)) acc[it.category].hits += 1;
      return acc;
    }, {});
  return Object.values(skills)
    .filter((s) => s.hits > 0)
    .sort((a, b) => b.hits - a.hits)
    .slice(0, limit);
}

const CATEGORY_DIR = Object.fromEntries(Object.entries(CATEGORY_SKILL).map(([dir, skill]) => [skill, dir]));

export function readSkill(name) {
  if (!name) throw new Error('name 为空');
  const raw = String(name).trim();
  const bare = raw.replace(/^\.\//, '').replace(/\.md$/, '');
  if (!bare || bare.split('/').some((seg) => seg === '..')) throw new Error(`非法技能名：${name}`);
  const segs = bare.split('/').filter(Boolean);
  const head = segs[0] || '';
  const dirName = CATEGORY_DIR[head] || CATEGORY_SKILL[head] || head.replace(/^kb-/, '');
  const candidates = [];
  const push = (p) => { if (p && !candidates.includes(p)) candidates.push(p); };
  if (path.isAbsolute(raw)) push(raw);
  const roots = knowledgeRoots();
  for (const root of roots) {
    if (segs.length > 1) push(path.join(root, dirName, segs.slice(1).join('/') + '.md'));
    push(path.join(root, dirName, 'SKILL.md'));
    push(path.join(root, dirName));
    push(path.join(root, bare + '.md'));
  }
  for (const cand of candidates) {
    try {
      const st = fs.statSync(cand);
      if (!st.isFile() || !cand.endsWith('.md')) continue;
      const real = fs.realpathSync(cand);
      if (!roots.some((root) => real.startsWith(path.resolve(root) + path.sep))) continue;
      return { path: real, text: fs.readFileSync(real, 'utf8') };
    } catch {}
  }
  const entry = loadEntries().find((it) => {
    const file = it.file.replace(/\\/g, '/');
    return file === bare + '.md' || file === bare ||
      file.endsWith('/' + bare + '.md') || file.endsWith('/' + bare) ||
      path.basename(file) === bare + '.md';
  });
  if (entry) return { path: entry.abs, text: fs.readFileSync(entry.abs, 'utf8') };
  throw new Error(`找不到技能或条目：${name}（可用：kb-<分类> / <分类> / <分类>/<文件>.md / <文件>.md）`);
}

// ── 台账：findings / campaigns ────────────────────────────────────────────
function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}
function writeJson(file, data) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
}

export function storeDir() {
  const explicit = process.env.FUJIANG_STORE?.trim();
  if (explicit) return ensureDir(explicit);
  const dsh = process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh');
  return ensureDir(path.join(dsh, 'vuln-report'));
}

export function findingsFile() {
  return path.join(storeDir(), 'findings.json');
}
export function campaignsFile() {
  return path.join(storeDir(), 'campaigns.json');
}

/** 兼容插件格式 {schema,updatedAt,items} 与旧格式 {findings|campaigns}。 */
export function readStore(file, legacyKey) {
  const raw = readJson(file, null);
  if (!raw || typeof raw !== 'object') return { schema: 1, updatedAt: 0, items: [] };
  const items = Array.isArray(raw.items)
    ? raw.items
    : Array.isArray(raw[legacyKey])
      ? raw[legacyKey]
      : [];
  return { schema: 1, updatedAt: Number(raw.updatedAt) || 0, items: items.filter((x) => x && typeof x === 'object') };
}

export function writeStore(file, store) {
  store.schema = 1;
  store.updatedAt = Date.now();
  writeJson(file, store);
}

export function addFinding({
  title,
  severity = 'medium',
  target = '',
  evidence = '',
  remediation = '',
  verified = false,
  url = '',
  category = '',
  cve = '',
  cvss = null,
  description = '',
  references = '',
}) {
  const file = findingsFile();
  const db = readStore(file, 'findings');
  const now = new Date().toISOString();
  const item = {
    id: `v${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`,
    title: String(title || '未命名漏洞').slice(0, 200),
    severity: ['critical', 'high', 'medium', 'low', 'info'].includes(severity) ? severity : 'medium',
    status: 'open',
    target: String(target || '').slice(0, 300),
    url: String(url || ''),
    category: String(category || ''),
    cve: String(cve || ''),
    source: 'ai',
    cvss: Number.isFinite(Number(cvss)) ? Math.max(0, Math.min(10, Number(cvss))) : null,
    evidence: String(evidence || ''),
    description: String(description || ''),
    remediation: String(remediation || ''),
    references: String(references || ''),
    verified: verified === true && !!(target && String(evidence).trim()),
    foundAt: now,
    updatedAt: now,
  };
  db.items.unshift(item);
  writeStore(file, db);
  return item;
}

export function listFindings() {
  return readStore(findingsFile(), 'findings').items;
}

export function upsertCampaign({ id, campaignId, objective, name, stage, host, port, fingerprint, command, result, status, advance, done, sessionId, autopilot }) {
  const file = campaignsFile();
  const db = readStore(file, 'campaigns');
  const now = new Date().toISOString();
  const key = id || campaignId;
  let c = key ? db.items.find((x) => x.id === key) : null;
  if (!c) {
    c = {
      id: key || `c${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`,
      name: String(name || objective || '未命名任务').slice(0, 120),
      stage: STAGES.includes(stage) ? stage : 'recon',
      scope: { domains: [], cidrs: [], exclude: [] },
      assets: [],
      steps: [],
      attempts: [],
      note: '',
      objective: String(objective || ''),
      done: false,
      doneNote: '',
      autopilot: true,
      rounds: 0,
      maxRounds: 8,
      lastProgress: -1,
      sessionId: sessionId ? String(sessionId).slice(0, 120) : null,
      createdBy: 'cli',
      createdAt: now,
      updatedAt: now,
    };
    db.items.unshift(c);
  }
  if (objective !== undefined) {
    c.objective = String(objective);
    if (!c.name || c.name === '未命名任务') c.name = String(name || objective).slice(0, 120);
  }
  if (name !== undefined) c.name = String(name).slice(0, 120);
  if (stage) c.stage = stage;
  if (sessionId !== undefined) c.sessionId = sessionId ? String(sessionId).slice(0, 120) : null;
  if (typeof autopilot === 'boolean') c.autopilot = autopilot;
  c.assets = Array.isArray(c.assets) ? c.assets : [];
  c.steps = Array.isArray(c.steps) ? c.steps : [];
  if (host || port || fingerprint || status) {
    const asset = c.assets.find((a) => a.host === host && (a.port ?? null) === (port ?? null)) || (c.assets.push({ host, port: port ?? null, fingerprint: '', status: 'new' }), c.assets[c.assets.length - 1]);
    if (fingerprint) asset.fingerprint = fingerprint;
    if (status) asset.status = status;
  }
  if (command || result) c.steps.push({ at: now, stage: c.stage, command: command || '', result: result || '' });
  if (advance) {
    const i = STAGES.indexOf(c.stage);
    if (i >= 0 && i < STAGES.length - 1) {
      c.advanceFrom = c.stage;
      c.stage = STAGES[i + 1];
    }
  }
  if (typeof done === 'boolean') {
    if (done && (!Array.isArray(c.assets) || c.assets.length === 0 || !Array.isArray(c.steps) || c.steps.length === 0)) {
      throw new Error('结单前至少需要 1 个资产和 1 步验证记录（command/result）。');
    }
    c.done = done;
    if (done) c.doneNote = String(result || c.doneNote || '');
  }
  c.updatedAt = now;
  writeStore(file, db);
  return c;
}

export function pipelineNext(id) {
  const db = readStore(campaignsFile(), 'campaigns');
  const c = id ? db.items.find((x) => x.id === id) : db.items[0];
  if (!c) return { error: '没有任务；先用 campaign_upsert 建一个（objective 或 name 必填）' };
  const assets = Array.isArray(c.assets) ? c.assets : [];
  const steps = Array.isArray(c.steps) ? c.steps : [];
  const idx = Math.max(0, STAGES.indexOf(c.stage));
  const pending = assets.filter((a) => a.status !== 'verified' && a.status !== 'exploited');
  return {
    campaign: c.id,
    objective: c.objective || c.name || '',
    stage: c.stage || 'recon',
    nextStage: STAGES[Math.min(idx + 1, STAGES.length - 1)],
    done: c.done === true,
    pendingAssets: pending,
    stall: steps.length >= 2 && assets.length > 0 && pending.length === assets.length,
    suggestion:
      c.stage === 'recon'
        ? '先补资产与端口：nmap -sV -p- TARGET，结果用 campaign_upsert 落账'
        : c.stage === 'fingerprint'
          ? '指纹入账后立刻 kb_match 匹配候选条目'
          : c.stage === 'match'
            ? '按命中条目的「前置条件」筛掉版本不符的候选，选 1 条做最小验证'
            : c.stage === 'verify'
              ? '只读验证（version/info/配置读取）先做，写入型放到 exploit 阶段'
              : c.stage === 'exploit'
                ? '拿证据（命令 + 原始响应文本），然后 finding_upsert 写报告'
                : c.stage === 'lateral'
                  ? '横向只做已授权资产，凭据与跳板记录进 steps'
                  : '输出报告并 campaign_upsert(done=true)',
  };
}
