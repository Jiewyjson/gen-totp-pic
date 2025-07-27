use serde::Deserialize;
use totp_rs::{Algorithm, Secret, TOTP};
use anyhow::{Context, Result};
use std::{env, fs, path::Path};

/// JSON 根对象结构
#[derive(Debug, Deserialize)]
struct TotpExport {
    export_time: String,
    total_entries: u32,
    entries: Vec<TotpEntry>,
}

/// TOTP 条目结构
#[derive(Debug, Deserialize)]
struct TotpEntry {
    username: String,
    label_name: String,
    secret: String,      // Base32 字符串
    algorithm: String,   // "SHA1" / "SHA256" / ...
    digits: u32,
    period_time: u64,    // 秒
}

fn main() -> Result<()> {
    // 1. 获取输入文件名（命令行参数或默认值）
    let args: Vec<String> = env::args().collect();
    let input_file = if args.len() > 1 {
        &args[1]
    } else {
        println!("💡 使用方法: {} <JSON文件路径>", args[0]);
        println!("💡 或者直接运行使用默认文件: totp.json");
        "totp.json"
    };
    
    println!("📂 读取文件: {}", input_file);
    
    // 2. 读取 JSON 文件
    let data = fs::read_to_string(input_file)
        .with_context(|| format!("无法读取文件: {}", input_file))?;
    
    // 3. 解析 JSON 根对象
    let export: TotpExport = serde_json::from_str(&data)
        .context("JSON 解析失败，请检查文件格式是否正确")?;
    
    println!("📊 导出时间: {}", export.export_time);
    println!("📊 总条目数: {}", export.total_entries);
    println!("📊 实际条目数: {}", export.entries.len());
    
    if export.entries.is_empty() {
        println!("⚠️  没有找到任何 TOTP 条目");
        return Ok(());
    }

    // 4. 创建输出目录
    fs::create_dir_all("qr")
        .context("无法创建 qr 目录")?;
    
    // 5. 为每一项生成二维码 PNG
    for (index, entry) in export.entries.iter().enumerate() {
        println!("🔄 处理第 {}/{} 项: {} ({})", 
                 index + 1, export.entries.len(), 
                 entry.label_name, entry.username);
        
        let totp = build_totp(entry)
            .with_context(|| format!("构建 TOTP 失败: {} ({})", entry.label_name, entry.username))?;
        
        let png = totp.get_qr_png()
            .map_err(|e| anyhow::anyhow!("生成二维码失败: {} ({}): {}", entry.label_name, entry.username, e))?;

        // 文件名: <label>-<username>.png ，去掉可能的斜杠/空格
        let filename = format!(
            "{}-{}.png",
            sanitize(&entry.label_name),
            sanitize(&entry.username)
        );
        let path = Path::new("qr").join(filename);
        
        fs::write(&path, png)
            .with_context(|| format!("写入文件失败: {:?}", path))?;
        
        println!("✅ 已生成: {:?}", path);
    }
    
    println!("🎉 所有二维码生成完成！");
    Ok(())
}

/// 将 JSON 里的算法、secret 等转换为 TOTP
fn build_totp(entry: &TotpEntry) -> Result<TOTP> {
    // 解析算法
    let algorithm = match entry.algorithm.to_uppercase().as_str() {
        "SHA1" => Algorithm::SHA1,
        "SHA256" => Algorithm::SHA256,
        "SHA512" => Algorithm::SHA512,
        _ => {
            return Err(anyhow::anyhow!(
                "不支持的算法: {}，仅支持 SHA1/SHA256/SHA512", 
                entry.algorithm
            ));
        }
    };
    
    // 验证参数
    if entry.digits < 6 || entry.digits > 8 {
        return Err(anyhow::anyhow!(
            "digits 必须在 6-8 之间，当前值: {}", 
            entry.digits
        ));
    }
    
    if entry.period_time == 0 {
        return Err(anyhow::anyhow!("period_time 不能为 0"));
    }
    
    // 解码 Base32 secret
    let secret_bytes = Secret::Encoded(entry.secret.clone())
        .to_bytes()
        .with_context(|| format!(
            "Base32 解码失败，请检查 secret 格式: {}", 
            entry.secret
        ))?;
    
    println!("🔑 Secret 长度: {} 字节 ({} 位)", secret_bytes.len(), secret_bytes.len() * 8);
    
    // 创建 TOTP - 使用 new_unchecked 绕过 128 位限制，保持原始 secret 不变
    let totp = TOTP::new_unchecked(
        algorithm,
        entry.digits as usize,
        1,  // clock skew
        entry.period_time,
        secret_bytes,
        Some(entry.label_name.clone()),
        entry.username.clone(),
    );
    
    Ok(totp)
}

/// 简单清洗文件名
fn sanitize(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}