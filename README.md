# recover-matlab-pcode

用于 Codex 的 MATLAB P-code 源码还原 skill，支持单个 `.p` 文件和目录批量处理，并保留 `+package`、`@class` 目录结构。还原后可通过 MATLAB 重新编码，比较完整解压载荷；需要时再做源码对比和逻辑审查。

当前只支持精确文件头 `v01.00v00.00` 的旧格式。其他格式、损坏数据和未知 token 会逐文件报告，不会被标为还原成功。不支持 `.slxp`、MEX 或 MATLAB Compiler 归档。

## 环境要求

- Python 3.10+，Python 脚本仅依赖标准库。
- 完整验证需要支持 `pcode -R2007b` 的 MATLAB，并启用 JVM。
- 没有 MATLAB 时可以解码，但结果只属于未验证的候选源码。

## 安装为 Codex skill

仓库根目录就是 skill 根目录，`SKILL.md` 应直接位于 `skills/recover-matlab-pcode/`，不要再套一层同名目录。

Windows PowerShell：

```powershell
if ([string]::IsNullOrWhiteSpace($env:CODEX_HOME)) {
    $codexSkillHome = Join-Path $env:USERPROFILE '.codex'
} else {
    $codexSkillHome = $env:CODEX_HOME
}
$skillsRoot = Join-Path $codexSkillHome 'skills'
$skillInstallPath = Join-Path $skillsRoot 'recover-matlab-pcode'
if (Test-Path -LiteralPath $skillInstallPath) {
    throw "目标已存在，请保留已有文件并选择其他安装位置：$skillInstallPath"
}
New-Item -ItemType Directory -Path $skillsRoot -Force | Out-Null
git clone https://github.com/SanwenYu007/recover-matlab-pcode.git $skillInstallPath
if ($LASTEXITCODE -ne 0) { throw 'git clone 失败，安装未完成。' }
```

在 Codex 中调用：

```text
使用 $recover-matlab-pcode 还原 Tools 下的 .p，验证结果并比较逻辑差异。
```

## 手动运行

下面的 `<skill>` 表示本仓库根目录；输入可为单个 `.p` 文件或包含 `.p` 的目录。输出目录必须不存在或为空，脚本不会覆盖已有源码。

1. 解码到独立目录：

   ```powershell
   python "<skill>/scripts/recover_pcode.py" --input "D:/project/Tools" --output "D:/project/PcodeRecovered"
   ```

2. 在 MATLAB 中检查语法并重新生成 P-code：

   ```matlab
   addpath('<skill>/scripts');
   validate_recovery('D:/project/PcodeRecovered/recovery_manifest.json');
   ```

3. 比较原始与重生成 P-code 的完整载荷：

   ```powershell
   python "<skill>/scripts/verify_roundtrip.py" --manifest "D:/project/PcodeRecovered/recovery_manifest.json" --matlab-report "D:/project/PcodeRecovered/matlab_validation.json"
   ```

MATLAB 步骤只运行 Code Analyzer 和临时副本的 `pcode`，不会执行还原程序、启动其 GUI 或加载/构建目标模型。输入文件保持只读。

完整流程生成 `sources/`、`evidence/`、`recovery_manifest.json`、`matlab_validation.json` 和 `roundtrip_validation.json`。最后的 Python 比对步骤不可省略；语法检查和重新编码成功尚不能证明载荷一致。验证会更新清单，再次验证时须重新运行 MATLAB 步骤以生成对应的新报告。

非零退出码表示需要查看逐文件结果。部分成功、未知格式和验证失败会分别保留状态。整个 `.p` 二进制一致和解压后载荷一致是两个指标；载荷一致证明编码保真，不能据此保证原始排版、普通注释或运行行为。

## 测试

在仓库根目录执行：

```powershell
python -B -m unittest discover -s tests -v
```

Python 测试不替代实际 MATLAB 重新编码验证。详细流程见 [SKILL.md](SKILL.md)，格式结构、解析边界和技术来源见 [references/format.md](references/format.md)，按需审查方法见 [references/review.md](references/review.md)。

## 来源与许可说明

格式、扰乱表和 token 表参考 [Cognet-74/ptom_py](https://github.com/Cognet-74/ptom_py)。上游 README 声明 MIT，但制作此 skill 时未获取到其 LICENSE 正文；这里保留来源事实，不补写或推定许可证。完整来源记录见 [references/format.md](references/format.md)。

仓库只包含 skill 文档、工具和测试，不包含用户的受保护 `.p` 文件或其还原源码。
