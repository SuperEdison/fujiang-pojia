# 富江破甲 · DSH 插件版

本地 CVE/PoC 知识库（167 条 / 9 分类）+ DeepSeek Harness 面板插件：漏洞报告、技能库、作业链。内核自带版本区间匹配，插件与 CLI 共用同一份实现。

宿主侧只装插件；不写其他客户端的提示词或技能目录。

## 结构

```
plugin/lib/core.mjs      唯一内核：知识库索引、版本区间匹配、台账、阶段机
plugin/lib/index.js      插件入口：面板、HTTP 路由、系统提示词节、原生工具
plugin/lib/client.js     设置页 UI
plugin/knowledge/        167 条知识（9 分类，Markdown + frontmatter）
bin/kb-match.mjs         同内核的 CLI
prompt-custom.json          默认去广告破甲配置（enabled:true）
prompt-custom.example.json  关闭态空模板
```

## 安装插件

先完全退出 Harness（包括托盘里的退出）。

```bash
mkdir -p ~/.dsh/local-plugins
rm -rf ~/.dsh/local-plugins/dsh-prompt-custom
cp -R plugin ~/.dsh/local-plugins/dsh-prompt-custom

# 默认使用仓库自带的去广告配置；已有配置先备份，不覆盖
if [ -f ~/.dsh/prompt-custom.json ]; then
  cp ~/.dsh/prompt-custom.json ~/.dsh/prompt-custom.json.bak-$(date +%Y%m%d-%H%M%S)
else
  cp prompt-custom.json ~/.dsh/prompt-custom.json
fi

# 注册到 desktop profile
dsh plugin --profile desktop add ~/.dsh/local-plugins/dsh-prompt-custom
```

Windows 用 `%USERPROFILE%\.dsh\local-plugins\...`，`dsh` 换成 `dsh.cmd`。

启动 Harness 后，输入框旁会出现「富江破甲」状态与设置入口。

### 更新插件

```bash
node scripts/update.mjs --check   # 只看远端/本地版本
node scripts/update.mjs           # 拉最新 main，备份并替换
```

直接从 `SuperEdison/fujiang-pojia` 的 `main` 下载 zip，替换 `~/.dsh/local-plugins/dsh-prompt-custom`，旧目录备份为 `.bak-<时间>`。不会动 `~/.dsh/prompt-custom.json` 和 `~/.dsh/vuln-report/`；完全退出并重启 Harness 后生效。换仓库用 `FUJIANG_REPO=owner/repo`。

### 默认提示词与关闭方式

仓库自带 `prompt-custom.json`：`enabled:true`，内容是去广告后的破甲提示词（无频道推广、无二维码）。安装时默认复制到 `~/.dsh/prompt-custom.json`，新装即生效。

已有配置不会被覆盖：安装步骤会先备份。想恢复默认文本，删掉 `~/.dsh/prompt-custom.json` 后重新复制仓库版本，或在面板里粘贴。

想关闭注入：把 `prompt-custom.example.json` 复制为 `~/.dsh/prompt-custom.json`（`enabled:false`、空文本），或在面板里关开关。`enabled:false` 时插件不注册任何 `systemPrompt` 节（`desiredShape()` 返回 `off`），官方人设与提示词原样保留；面板、知识库、台账照常工作。

作业链绑定任务后会注入 `campaign:rules` / `campaign:context`（阶段、授权范围、下一步），这是功能上下文，不绑定任务时不出现。

## 不装插件，只用知识库

CLI 与插件同一内核，零依赖：

```bash
node bin/kb-match.mjs --port 443 --banner "Apache/2.4.49" --version 2.4.49
node bin/kb-match.mjs --port 6379 --banner redis --json
```

把 9 个分类技能复制到宿主目录（可选）：

| 宿主 | 目录 |
|---|---|
| Claude Code | `~/.claude/skills/` |
| Codex CLI | `~/.codex/skills/` |
| oh-my-pi | `~/.omp/agent/skills/` |
| Kimi CLI | `~/.kimi-code/skills/` |

每个技能一个目录，名字取 `SKILL.md` 的 `name`（如 `kb-triage`），目录内放 `SKILL.md` 和条目。Kimi 也可以用 `--skills-dir` 指过来，不必复制：

```bash
kimi --skills-dir ~/.kimi-code/skills
```

AboutSecurity 技能库由插件面板下载到 `$DSH_HOME/fujiang-skills/aboutsecurity/skills`（固定 commit + SHA256 校验）。

REA 逆向工具由面板下载到 `$DSH_HOME/fujiang-skills/rea`，默认 `rea-agents@6.9.0`：

- 6.9 把 `^[^\uD800-\uDFFF]*$` 写进了 183 处 JSON Schema 的 `pattern`；宿主的 Rust regex 解析器不接受代理区转义，会拒绝 `binary_session` 等工具。安装时插件会把这些 pattern 统一清洗成 `^[\s\S]*$`，NUL 与绝对路径约束保留。
- `FUJIANG_REA_VERSION` 可覆盖安装版本。
- Node 要求 `^22.23.4 || ^24.22.1 || >=26.12.1`；插件会扫描 mise 安装目录，也认 `FUJIANG_NODE`。

## 匹配口径

| 信号 | 分值 |
|---|---|
| 端口命中 | +40 |
| 产品命中（整词） | +30 |
| CVE 命中 | +20 |
| 关键词（英文整词 / 中文子串） | 每个 +10，上限 +20 |
| 标题命中（无产品命中时） | 每词 +6，上限 +18 |
| severity critical/high | +5 |
| 版本命中 `versions` 区间 | +40 |
| 版本明确不在区间 | −30（区间解析不全时不扣分） |

`version` 可显式传，也可从 banner 兜底提取。区间支持 `1.4.1 之前`、`10.2.x < 10.2.12`、`1.3.0 - 7.4.17`、`10.5、11.1`、`2.4.49（41773）`；无法结构化的描述按 `unknown` 处理。

## 台账

```
$DSH_HOME/vuln-report/findings.json    { schema, updatedAt, items: [...] }
$DSH_HOME/vuln-report/campaigns.json   { schema, updatedAt, items: [...] }
```

面板与 CLI 共用；写入走 `tmp + rename` 原子替换。旧格式 `{findings:[...]}` / `{campaigns:[...]}` 自动识别，写回时升级为 `items`。

## 卸载

```bash
dsh plugin --profile desktop remove @deepseek-ai/dsh-prompt-custom
rm -rf ~/.dsh/local-plugins/dsh-prompt-custom
rm -f ~/.dsh/prompt-custom.json
```

插件不影响 Harness 其他功能；删掉 `local-plugins` 目录即完全移除。技能目录里复制过去的 `kb-*` 按需删除。

## 与上游的关系

知识库与台账逻辑来自 `FJNB5/fujiang-pojia 0.20.12`（MIT）。本仓库保留可搬走的部分：知识库、匹配、台账、CLI，以及 DSH 面板插件。面板插件默认不注入提示词。

使用与责任边界见 [DISCLAIMER.md](./DISCLAIMER.md)。
