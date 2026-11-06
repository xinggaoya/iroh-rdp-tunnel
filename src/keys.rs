//! endpoint 私钥的持久化。
//!
//! 为什么要持久化：旧版每次启动都 `SecretKey::generate()`，endpoint id 每次都变，
//! 用户得每次重新复制 64 位十六进制；防火墙规则、端口转发、脚本也都没法固定引用。
//! 落盘之后 id 永久不变。

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Context;
use iroh::{EndpointId, SecretKey};

/// 密钥文件里的字节长度。
pub const KEY_LEN: usize = 32;

/// 读取密钥文件；不存在则原子创建。
///
/// 文件内容是 32 字节原始私钥。创建时先写同目录下的临时文件再 `rename`，
/// 避免写到一半崩溃留下半截文件。
pub fn load_or_create_secret_key(path: &Path) -> anyhow::Result<SecretKey> {
    if path.exists() {
        return read_secret_key(path);
    }
    let key = SecretKey::generate();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("创建目录失败: {}", parent.display()))?;
        }
    }
    // 先写同目录临时文件，再 rename —— 保证不会留下半截密钥。
    let tmp = tmp_sibling(path);
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("创建临时密钥文件失败: {}", tmp.display()))?;
        f.write_all(&key.to_bytes())
            .with_context(|| format!("写入密钥失败: {}", tmp.display()))?;
        f.sync_all().ok();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).ok();
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(key),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            // 可能是另一个进程抢先创建了 → 重新读一次。
            if path.exists() {
                return read_secret_key(path);
            }
            Err(e).with_context(|| format!("保存密钥失败: {}", path.display()))
        }
    }
}

/// 从已有密钥文件读取私钥。
fn read_secret_key(path: &Path) -> anyhow::Result<SecretKey> {
    let bytes =
        std::fs::read(path).with_context(|| format!("读取密钥文件失败: {}", path.display()))?;
    if bytes.len() != KEY_LEN {
        anyhow::bail!(
            "密钥文件 {} 的长度应为 {KEY_LEN} 字节，实际 {} 字节",
            path.display(),
            bytes.len()
        );
    }
    let mut arr = [0u8; KEY_LEN];
    arr.copy_from_slice(&bytes);
    Ok(SecretKey::from_bytes(&arr))
}

/// 把 endpoint id 以小写十六进制写到 `<path>.txt`，方便复制粘贴。
///
/// best-effort：写不进去也不影响主流程。
pub fn write_endpoint_id_hint(path: &Path, id: EndpointId) -> anyhow::Result<()> {
    let hp = hint_path(path);
    if let Some(parent) = hp.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("创建目录失败: {}", parent.display()))?;
        }
    }
    std::fs::write(&hp, format!("{id}\n"))
        .with_context(|| format!("写入 endpoint id 提示文件失败: {}", hp.display()))?;
    Ok(())
}

/// 与目标文件同目录的临时文件名。
fn tmp_sibling(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "server.key".to_string());
    let tmp_name = format!(".{name}.tmp{}", std::process::id());
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(tmp_name),
        _ => PathBuf::from(tmp_name),
    }
}

/// `<path>.txt` 的路径。
fn hint_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".txt");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_dir(tag: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("irt-keys-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn first_use_creates_a_32_byte_key_file() {
        let dir = temp_dir("create");
        let path = dir.join("server.key");
        assert!(!path.exists());

        let key = load_or_create_secret_key(&path).unwrap();

        assert_eq!(std::fs::metadata(&path).unwrap().len(), KEY_LEN as u64);
        assert_eq!(key.to_bytes().len(), KEY_LEN);
    }

    #[test]
    fn second_use_returns_the_same_key() {
        let dir = temp_dir("stable");
        let path = dir.join("server.key");

        let first = load_or_create_secret_key(&path).unwrap();
        let second = load_or_create_secret_key(&path).unwrap();

        assert_eq!(first.public(), second.public(), "两次读取必须得到同一个 endpoint id");
        assert_eq!(first.to_bytes(), second.to_bytes());
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = temp_dir("nested");
        let path = dir.join("a").join("b").join("server.key");
        load_or_create_secret_key(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn rejects_a_key_file_with_wrong_length() {
        let dir = temp_dir("badlen");
        let path = dir.join("server.key");
        std::fs::write(&path, b"too short").unwrap();

        let err = load_or_create_secret_key(&path).unwrap_err().to_string();
        assert!(
            err.contains("32"),
            "错误信息应说明期望 32 字节，实际: {err}"
        );
    }

    #[test]
    fn writes_endpoint_id_hint_as_lowercase_hex() {
        let dir = temp_dir("hint");
        let path = dir.join("server.key");
        let key = load_or_create_secret_key(&path).unwrap();

        write_endpoint_id_hint(&path, key.public()).unwrap();

        let hint = std::fs::read_to_string(dir.join("server.key.txt")).unwrap();
        assert_eq!(hint.trim(), key.public().to_string());
        assert_eq!(hint.trim().len(), 64);
        assert_eq!(hint.trim(), hint.trim().to_lowercase());
    }
}
