//! Windows 防火墙规则管理。
//!
//! 为什么必须做这件事：iroh 用 **UDP** 通信。Windows 防火墙默认拦截未放行的入站 UDP，
//! 表现就是「一直走中继、打洞永远不成功」，或者干脆连不上。
//! 本机实测 `node.exe` 等程序都没有入站放行规则 —— 远控程序必须自己放行。
//!
//! 实现用 `netsh`，因为它在所有 Windows 版本上都在，且不依赖 PowerShell 的执行策略。

use std::{
    path::Path,
    process::Command,
};

use anyhow::{Context, Result};

/// 默认规则名。
pub const RULE_NAME: &str = "iroh-rdp-tunnel (irt UDP inbound)";

/// 生成 `netsh advfirewall firewall add rule` 的参数。
pub fn add_rule_args(exe: &Path, rule_name: &str) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name={rule_name}"),
        "dir=in".into(),
        "action=allow".into(),
        format!("program={}", exe.display()),
        "protocol=UDP".into(),
        "enable=yes".into(),
    ]
}

/// 判断 `netsh advfirewall firewall show rule` 的输出里是否有一条指向该 exe 的规则。
///
/// Windows 路径不区分大小写，netsh 也可能改写路径分隔符，所以两边都做归一化再比较。
pub fn output_has_rule(output: &str, exe: &Path) -> bool {
    let want = normalize_path(&exe.display().to_string());
    if want.is_empty() {
        return false;
    }
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let lower = line.to_ascii_lowercase();
            if !lower.starts_with("program") {
                return None;
            }
            // 形如：Program: C:\path\to\irt.exe
            let (_, value) = line.split_once(':')?;
            Some(normalize_path(value.trim()))
        })
        .any(|got| got == want)
}

/// 归一化路径用于比较：统一分隔符、转小写、去掉尾部反斜杠。
fn normalize_path(s: &str) -> String {
    let s = s.trim().trim_matches('"');
    let s = s.replace('/', "\\");
    let s = s.trim_end_matches('\\').to_ascii_lowercase();
    s
}

/// 防火墙放行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallStatus {
    /// 已放行入站 UDP。
    Allowed,
    /// 未检测到放行规则。
    Missing,
    /// 检测失败（例如没有权限读防火墙配置）。
    Unknown,
}

/// 检测当前 exe 的防火墙放行状态。
pub fn status(exe: &Path) -> FirewallStatus {
    if has_allow_rule(exe, RULE_NAME) {
        FirewallStatus::Allowed
    } else {
        FirewallStatus::Missing
    }
}

/// 生成防火墙状态提示文案。
pub fn status_hint(status: FirewallStatus) -> String {
    match status {
        FirewallStatus::Allowed => "✅ 已放行入站 UDP".to_string(),
        FirewallStatus::Missing => format!(
            "⚠ 未检测到入站 UDP 放行规则\n                → 请以管理员执行:  irt server --install-firewall-rule"
        ),
        FirewallStatus::Unknown => {
            "？无法检测防火墙规则状态（可能没有读取权限）".to_string()
        }
    }
}

/// 当前可执行文件的绝对路径。
pub fn current_exe() -> Result<std::path::PathBuf> {
    std::env::current_exe().context("无法获取当前可执行文件路径")
}

/// 检测是否已存在指向该 exe 的放行规则。
#[cfg(windows)]
pub fn has_allow_rule(exe: &Path, rule_name: &str) -> bool {
    let output = Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", &format!("name={rule_name}")])
        .output();
    match output {
        Ok(out) => output_has_rule(&String::from_utf8_lossy(&out.stdout), exe),
        Err(_) => false,
    }
}

/// 非 Windows 平台：恒为 false。
#[cfg(not(windows))]
pub fn has_allow_rule(_exe: &Path, _rule_name: &str) -> bool {
    false
}

/// 为指定可执行文件添加入站 UDP 放行规则（需要管理员权限）。
#[cfg(windows)]
pub fn install_udp_allow_rule(exe: &Path, rule_name: &str) -> Result<()> {
    // 同名规则先删掉，避免重复添加。
    let _ = remove_rule(rule_name);
    let args = add_rule_args(exe, rule_name);
    let output = Command::new("netsh")
        .args(&args)
        .output()
        .context("调用 netsh 失败")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let msg = format!("{}{}", stdout.trim(), stderr.trim());
        if needs_elevation(&msg) {
            anyhow::bail!("netsh 添加规则失败: {msg}\n\n{}", admin_hint());
        }
        anyhow::bail!("netsh 添加规则失败: {msg}");
    }
    Ok(())
}

/// 非 Windows 平台：返回「不适用」错误，不 panic。
#[cfg(not(windows))]
pub fn install_udp_allow_rule(_exe: &Path, _rule_name: &str) -> Result<()> {
    anyhow::bail!("防火墙规则管理仅支持 Windows")
}

/// 删除规则。
#[cfg(windows)]
pub fn remove_rule(rule_name: &str) -> Result<()> {
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={rule_name}"),
        ])
        .output()
        .context("调用 netsh 失败")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("netsh 删除规则失败: {}", stderr.trim());
    }
    Ok(())
}

/// 非 Windows 平台：返回「不适用」错误，不 panic。
#[cfg(not(windows))]
pub fn remove_rule(_rule_name: &str) -> Result<()> {
    anyhow::bail!("防火墙规则管理仅支持 Windows")
}

/// 判断错误信息是否表示「需要管理员权限」。
pub fn needs_elevation(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("提升")
        || m.contains("elevat")
        || m.contains("administrator")
        || m.contains("access is denied")
        || m.contains("拒绝访问")
        || m.contains("需要管理员")
}

/// 管理员权限提示。
pub fn admin_hint() -> String {
    format!(
        "请以**管理员身份**运行 PowerShell/CMD 后重试，例如：\n    \
         netsh advfirewall firewall add rule name=\"{RULE_NAME}\" dir=in action=allow program=\"<irt.exe 路径>\" protocol=UDP enable=yes"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_rule_args_contain_everything_netsh_needs() {
        let exe = Path::new(r"C:\Program Files\irt\irt.exe");
        let args = add_rule_args(exe, RULE_NAME);
        let joined = args.join(" ");

        assert!(joined.contains("advfirewall"));
        assert!(joined.contains("add rule"));
        assert!(joined.contains(&format!("name={RULE_NAME}")));
        assert!(joined.contains("dir=in"), "必须限制为入站: {joined}");
        assert!(joined.contains("action=allow"), "必须是放行: {joined}");
        assert!(joined.contains("protocol=UDP"), "必须是 UDP: {joined}");
        assert!(
            joined.contains("program=C:\\Program Files\\irt\\irt.exe"),
            "必须指向可执行文件: {joined}"
        );
    }

    #[test]
    fn output_has_rule_matches_the_program_line() {
        let exe = Path::new(r"C:\Program Files\irt\irt.exe");
        let output = "Rule Name:                            irt UDP inbound\n\
                      ----------------------------------------------------------------------\n\
                      Program:                              C:\\Program Files\\irt\\irt.exe\n\
                      Enabled:                              Yes\n";
        assert!(output_has_rule(output, exe));
    }

    #[test]
    fn output_has_rule_is_case_insensitive() {
        let exe = Path::new(r"C:\Program Files\irt\irt.exe");
        let output = "Program:                              c:\\program files\\irt\\irt.exe\n";
        assert!(output_has_rule(output, exe));
    }

    #[test]
    fn output_has_rule_ignores_other_programs() {
        let exe = Path::new(r"C:\Program Files\irt\irt.exe");
        let output = "Program:                              C:\\Windows\\System32\\svchost.exe\n";
        assert!(!output_has_rule(output, exe));
    }

    #[test]
    fn output_has_rule_handles_empty_output() {
        let exe = Path::new(r"C:\Program Files\irt\irt.exe");
        assert!(!output_has_rule("", exe));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_returns_not_applicable_error() {
        let exe = Path::new("/usr/bin/irt");
        let err = install_udp_allow_rule(exe, RULE_NAME).unwrap_err().to_string();
        assert!(err.contains("Windows"), "错误信息应说明仅支持 Windows: {err}");
        let err = remove_rule(RULE_NAME).unwrap_err().to_string();
        assert!(err.contains("Windows"), "错误信息应说明仅支持 Windows: {err}");
    }

    #[test]
    fn elevation_errors_are_recognised() {
        assert!(needs_elevation("请求的操作需要提升(作为管理员运行)。"));
        assert!(needs_elevation("The requested operation requires elevation."));
        assert!(needs_elevation("Access is denied."));
        assert!(!needs_elevation("没有找到与参数匹配的规则。"));
    }

    #[test]
    fn admin_hint_mentions_the_rule_name() {
        let hint = admin_hint();
        assert!(hint.contains(RULE_NAME), "提示里应包含规则名，实际: {hint}");
        assert!(hint.contains("管理员"), "提示里应说明需要管理员，实际: {hint}");
    }

    #[test]
    fn status_hint_covers_all_states() {
        let allowed = status_hint(FirewallStatus::Allowed);
        assert!(allowed.contains("已放行"), "实际: {allowed}");

        let missing = status_hint(FirewallStatus::Missing);
        assert!(missing.contains("未检测到"), "实际: {missing}");
        assert!(
            missing.contains("--install-firewall-rule"),
            "缺失时应给出可执行的命令，实际: {missing}"
        );

        let unknown = status_hint(FirewallStatus::Unknown);
        assert!(unknown.contains("无法检测"), "实际: {unknown}");
    }
}
