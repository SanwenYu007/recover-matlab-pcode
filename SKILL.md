---
name: recover-matlab-pcode
description: "Use when a user requests recovery or decompilation of local MATLAB P-code (.p) into readable .m files, singly or in a directory, including lost-source recovery and source comparisons. 用于 MATLAB .p 反编译和批量源码还原。Not for .slxp, MEX binaries, or MATLAB Compiler archives."
---

# MATLAB P-code 源码还原

将用户指定的 P-code 还原成可读源码，保留目录结构，并用 MATLAB 重新编码后的完整载荷证明保真。只支持已识别的 `v01.00v00.00` 格式；其他格式或未知语句编码须逐文件报告，不能推断为通用解密能力。

## 环境要求

Python 3.10+，脚本只依赖标准库。完整保真验证需要支持 `pcode -R2007b` 的 MATLAB 和 JVM；没有 MATLAB 时只交付候选源码与未验证状态。

## 工作流程

1. 确定用户指定的文件或目录和输出位置，读取适用的 AGENTS.md。输入保持只读，输出使用独立的新目录。已经找到的同名 `.m` 可作为候选，但文件名相同不能证明版本对应。
2. 用本 skill 的脚本处理单文件或批量目录。先查看 `--help`；脚本会保留 `+包` 和 `@类` 结构，拒绝覆盖非空输出目录，并记录不支持、损坏或未知 token 的文件。
3. 检查清单的每文件状态。`decoded_unverified` 只代表解码完成。未知格式不交给旧格式解析器，未知 token 不作猜测替换。
4. 有 MATLAB 时执行 `validate_recovery`：只做 Code Analyzer 和临时副本的 `pcode(...,'-R2007b','-inplace')`，不运行还原程序、不启动 GUI、不加载/构建目标模型。MATLAB MCP 的 `evaluate_matlab_code` 可将 `project_path` 设为 skill 的 `scripts` 目录，再调用该函数。
5. 执行 `verify_roundtrip.py`，核对同次报告、输入/源码/重生成文件哈希和完整解压载荷，然后更新恢复清单。分别报告载荷一致与整个 `.p` 文件一致；扰乱字段变化不能当成语句差异。没有 MATLAB 或验证失败时保留明确的未验证/失败状态。
6. 交付源码目录、恢复清单、验证结果和实际计数。保留已编码的文字及指令；原版排版和未编码的普通注释无法保证恢复。

## 运行示例

将 `<skill>` 替换为本 SKILL.md 所在目录，选择新的输出目录。

```powershell
python "<skill>/scripts/recover_pcode.py" --input "D:/project/Tools" --output "D:/project/PcodeRecovered"
```

MATLAB 中调用，或通过 MCP 在 skill 的 scripts 目录执行：

```matlab
validate_recovery('D:/project/PcodeRecovered/recovery_manifest.json');
```

最后完成载荷比对，不能省略这一步：

```powershell
python "<skill>/scripts/verify_roundtrip.py" --manifest "D:/project/PcodeRecovered/recovery_manifest.json" --matlab-report "D:/project/PcodeRecovered/matlab_validation.json"
```

完整运行后会生成 `sources/`、`evidence/`、`recovery_manifest.json`、`matlab_validation.json` 和 `roundtrip_validation.json`。验证会更新清单；再次验证时须先重新运行 MATLAB 步骤，旧报告的清单哈希将不再对应。非零退出码须检查逐文件结果，不能当作全部成功。

这些操作不需要下载或上传源文件。若调用路径含单引号，应按 MATLAB 字符串语法转义；在 PowerShell 中写含中文的脚本或报告时使用 UTF-8 文件，避免默认管道编码损坏文字。

## 对比和审查

只有用户要求比较或漏洞分析时，读取 [references/review.md](references/review.md)，沿实际调用链审查通过保真验证的源码。恢复问题和原程序缺陷分别记录；运行行为需要另行验证。读取 [references/format.md](references/format.md) 可查格式、已知解析陷阱及来源。

## 完成状态

| 状态 | 可以报告的结果 |
|---|---|
| 解码成功，未做 MATLAB 验证 | 已生成候选源码，验证待完成 |
| MATLAB 语法/重新生成通过 | 源码可重新生成 P-code，载荷比对待完成 |
| 完整载荷一致且哈希未变 | 已验证代码编码保真；运行行为未由此证明 |
| 部分文件失败/不支持 | 给出成功数、失败数和逐文件原因，保留成功产物 |
