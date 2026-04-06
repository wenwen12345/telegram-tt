#!/usr/bin/env node
/**
 * encrypt-dist.js
 *
 * 将 dist/ 目录下所有文件用 AES-256-GCM 就地加密。
 * 已加密文件（以 "ENC" 魔数开头）会跳过，避免重复加密。
 *
 * 加密格式（二进制拼接）：
 *   [0..2]   "ENC"      魔数（3 bytes）
 *   [3..14]  IV         随机 12 bytes
 *   [15..30] AuthTag    GCM 认证标签 16 bytes
 *   [31..]   ciphertext 密文
 *
 * 环境变量：
 *   AES_KEY  必填，64 个十六进制字符（256-bit 密钥）
 *
 * 用法：
 *   AES_KEY=<64-hex> node encrypt-dist.js [dist目录路径，默认 ./dist]
 */

import { createCipheriv, randomBytes } from 'crypto';
import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

// ─── 密钥 ─────────────────────────────────────────────────────────────────────

const hexKey = process.env.AES_KEY;
if (!hexKey || hexKey.length !== 64) {
  console.error('Error: AES_KEY env var must be a 64-character hex string (256-bit key).');
  process.exit(1);
}
const KEY = Buffer.from(hexKey, 'hex');

// ─── 魔数 ─────────────────────────────────────────────────────────────────────

const MAGIC = Buffer.from('ENC');

// ─── 加密单个文件 ──────────────────────────────────────────────────────────────

function encryptFile(filePath) {
  const plain = readFileSync(filePath);

  // 已加密则跳过
  if (plain.length >= 3 && plain.slice(0, 3).equals(MAGIC)) {
    console.log(`  skip (already encrypted): ${filePath}`);
    return;
  }

  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', KEY, iv);

  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16 bytes

  // 拼接：MAGIC + IV + AuthTag + ciphertext
  const out = Buffer.concat([MAGIC, iv, authTag, ciphertext]);
  writeFileSync(filePath, out);
  console.log(`  encrypted: ${filePath} (${plain.length} → ${out.length} bytes)`);
}

// ─── 递归遍历目录 ──────────────────────────────────────────────────────────────

function walkAndEncrypt(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walkAndEncrypt(full);
    } else if (stat.isFile()) {
      encryptFile(full);
    }
  }
}

// ─── 入口 ─────────────────────────────────────────────────────────────────────

const distDir = process.argv[2] || './dist';
console.log(`Encrypting all files in: ${distDir}`);
walkAndEncrypt(distDir);
console.log('Done.');
