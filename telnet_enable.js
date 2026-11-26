"use strict";

const fs = require("fs");
const crypto = require("crypto");
const zlib = require("zlib");

const MAGIC = 0x01020304;
const OUTER_TYPE = 4;
const INNER_TYPE = 0;
const HEADER_SIZE = 0x3c;
const XML_CHUNK_SIZE = 0x10000;

// Firmware-family profiles. No serial number, MAC address or local path is used.
// A candidate is accepted only after all structural and CRC checks pass.
const PROFILES = [
  {
    name: "E2637-0238002E",
    keySeed: "E2637Key0238002E",
    ivSeed: "E2637Iv0238002E",
    marker: /(?:ZXHN[^<>\r\n]{0,96}E2637|E2637Key|2637@)/i,
  },
  {
    name: "E2633-0238002E",
    keySeed: "E2633Key0238002E",
    ivSeed: "E2633Iv0238002E",
    marker: /ZXHN[^<>\r\n]{0,96}E2633/i,
  },
  {
    name: "E2638-0238002E",
    keySeed: "E2638Key0238002E",
    ivSeed: "E2638Iv0238002E",
    marker: /ZXHN[^<>\r\n]{0,96}E2638/i,
  },
  {
    name: "E2631-0238002E",
    keySeed: "E2631Key0238002E",
    ivSeed: "E2631Iv0238002E",
    marker: /ZXHN[^<>\r\n]{0,96}E2631/i,
  },
  {
    name: "E1630-0238002E",
    keySeed: "E1630Key0238002E",
    ivSeed: "E1630Iv0238002E",
    marker: /ZXHN[^<>\r\n]{0,96}E1630/i,
  },
  {
    name: "E2631-E1630-legacy-13515211",
    keySeed: "E2631Key13515211",
    ivSeed: "E2631Iv13515211",
    marker: /ZXHN[^<>\r\n]{0,96}(?:E2631|E1630)/i,
  },
];

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function uint32be(value) {
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value >>> 0, 0);
  return result;
}

function sha256Ascii(value) {
  return crypto.createHash("sha256").update(Buffer.from(value, "ascii")).digest();
}

function aesDecrypt(payload, profile) {
  if (payload.length % 16 !== 0) throw new Error("encrypted chunk is not AES aligned");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    sha256Ascii(profile.keySeed),
    sha256Ascii(profile.ivSeed).subarray(0, 16),
  );
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(payload), decipher.final()]);
}

function aesEncrypt(payload, profile) {
  const paddedSize = (payload.length + 15) & ~15;
  const padded = paddedSize === payload.length
    ? payload
    : Buffer.concat([payload, Buffer.alloc(paddedSize - payload.length)]);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    sha256Ascii(profile.keySeed),
    sha256Ascii(profile.ivSeed).subarray(0, 16),
  );
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(padded), cipher.final()]);
}

function parseChunks(buffer, startOffset = HEADER_SIZE) {
  const chunks = [];
  let offset = startOffset;
  while (offset + 12 <= buffer.length) {
    const unpackedSize = buffer.readUInt32BE(offset);
    const packedSize = buffer.readUInt32BE(offset + 4);
    const nextOffset = buffer.readUInt32BE(offset + 8);
    const payloadStart = offset + 12;
    const payloadEnd = payloadStart + packedSize;
    if (!packedSize || payloadEnd > buffer.length) throw new Error(`invalid chunk at 0x${offset.toString(16)}`);
    chunks.push({ offset, unpackedSize, packedSize, nextOffset, payload: buffer.subarray(payloadStart, payloadEnd) });
    offset = payloadEnd;
    if (nextOffset === 0) return chunks;
  }
  throw new Error("unterminated chunk list");
}

function checkHeader(buffer, expectedType, label) {
  if (buffer.length < HEADER_SIZE) throw new Error(`${label}: file is too small`);
  if (buffer.readUInt32BE(0) !== MAGIC || buffer.readUInt32BE(4) !== expectedType) {
    throw new Error(`${label}: unexpected magic/type`);
  }
}

function decryptConfig(input, profile) {
  checkHeader(input, OUTER_TYPE, "outer config");
  const outerChunks = parseChunks(input);
  const inner = Buffer.concat(outerChunks.map((chunk) => aesDecrypt(chunk.payload, profile)));
  checkHeader(inner, INNER_TYPE, "inner config");

  if (inner.readUInt32BE(24) !== crc32(inner.subarray(0, 24))) throw new Error("inner header CRC32 mismatch");
  const innerChunks = parseChunks(inner);
  const storedDataCrc = inner.readUInt32BE(20);
  const actualDataCrc = crc32(Buffer.concat(innerChunks.map((chunk) => chunk.payload)));
  if (storedDataCrc !== actualDataCrc) throw new Error("compressed data CRC32 mismatch");

  const xmlParts = innerChunks.map((chunk) => {
    const inflated = zlib.inflateSync(chunk.payload);
    if (inflated.length !== chunk.unpackedSize) throw new Error("inflated chunk size mismatch");
    return inflated;
  });
  const xml = Buffer.concat(xmlParts);
  if (xml.length !== inner.readUInt32BE(8)) throw new Error("decrypted XML size mismatch");
  const text = xml.toString("utf8");
  if (!text.includes("<") || !/DM|Tbl|Cfg/i.test(text)) throw new Error("not a config XML");
  return { xml, text };
}

function buildInner(xml) {
  if (!xml.length) throw new Error("input XML is empty");
  const chunks = [];
  for (let offset = 0; offset < xml.length; offset += XML_CHUNK_SIZE) {
    const source = xml.subarray(offset, Math.min(xml.length, offset + XML_CHUNK_SIZE));
    chunks.push({ unpackedSize: source.length, payload: zlib.deflateSync(source) });
  }

  const offsets = [];
  let currentOffset = HEADER_SIZE;
  for (const chunk of chunks) {
    offsets.push(currentOffset);
    currentOffset += 12 + chunk.payload.length;
  }
  const encoded = chunks.map((chunk, index) => Buffer.concat([
    uint32be(chunk.unpackedSize),
    uint32be(chunk.payload.length),
    uint32be(index + 1 < chunks.length ? offsets[index + 1] : 0),
    chunk.payload,
  ]));

  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt32BE(MAGIC, 0);
  header.writeUInt32BE(INNER_TYPE, 4);
  header.writeUInt32BE(xml.length, 8);
  header.writeUInt32BE(offsets[offsets.length - 1], 12);
  header.writeUInt32BE(XML_CHUNK_SIZE, 16);
  header.writeUInt32BE(crc32(Buffer.concat(chunks.map((chunk) => chunk.payload))), 20);
  header.writeUInt32BE(crc32(header.subarray(0, 24)), 24);
  return Buffer.concat([header, ...encoded]);
}

function encryptConfig(xml, profile) {
  const inner = buildInner(xml);
  const encrypted = aesEncrypt(inner, profile);
  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt32BE(MAGIC, 0);
  header.writeUInt32BE(OUTER_TYPE, 4);
  return Buffer.concat([header, uint32be(inner.length), uint32be(encrypted.length), uint32be(0), encrypted]);
}

function setDm(row, name, value) {
  // 全量导出（db_backup_cfg 风格）的 DM 会带 defval 属性，必须一并兼容，
  // 否则正则失配会走 fallback 插入一行同名 DM，形成重复键。
  const expression = new RegExp(`<DM name="${name}" val="[^"]*"(\\s+defval="[^"]*")?\\s*/>`);
  const replacement = `<DM name="${name}" val="${value}"$1/>`;
  if (expression.test(row)) return row.replace(expression, replacement);
  return row.replace(/<\/Row>/, `${replacement}\r\n</Row>`);
}

function modifyTelnet(xmlText, credentials) {
  const adminName = (credentials && credentials.user) || "admin";
  const adminPass = (credentials && credentials.pass) || "admin";
  const keepCreds = Boolean(credentials && credentials.keep);
  let portRuleCount = 0;
  let telnetTableCount = 0;
  let modified = xmlText.replace(/<Row No="\d+">[\s\S]*?<\/Row>/g, (row) => {
    // 同理不能写成 val="TELNET"/>——带 defval 的行会漏匹配。
    if (!/<DM name="ServName" val="TELNET"/.test(row)) return row;
    portRuleCount += 1;
    return setDm(row, "PortEnable", "1");
  });
  modified = modified.replace(/<Tbl name="TelnetCfg"\s+RowCount="1">[\s\S]*?<\/Tbl>/g, (table) => {
    telnetTableCount += 1;
    return table.replace(/<Row No="0">[\s\S]*?<\/Row>/, (row) => {
      let result = setDm(row, "TS_Enable", "1");
      result = setDm(result, "Wan_Enable", "0");
      result = setDm(result, "Lan_Enable", "1");
      result = setDm(result, "TS_Port", "23");
      if (!keepCreds) {
        result = setDm(result, "TS_UName", adminName);
        result = setDm(result, "TS_UPwd", adminPass);
      }
      return result;
    });
  });
  if (portRuleCount < 1 || telnetTableCount !== 1) {
    throw new Error(`required Telnet structures not found: PortControl=${portRuleCount}, TelnetCfg=${telnetTableCount}`);
  }
  return modified;
}

function chooseProfile(results) {
  if (results.length === 0) throw new Error("unsupported config or unknown key");
  const modelMatch = results.find((result) => result.profile.marker.test(result.text));
  if (modelMatch) return modelMatch;
  if (results.length === 1) return results[0];
  throw new Error("multiple profiles matched without a model marker");
}

function processFile(inputPath, outputPath, credentials) {
  const input = fs.readFileSync(inputPath);
  const valid = [];
  for (const profile of PROFILES) {
    try {
      valid.push({ profile, ...decryptConfig(input, profile) });
    } catch (_) {
      // Failed candidates are expected during automatic profile detection.
    }
  }
  const selected = chooseProfile(valid);
  const modifiedText = modifyTelnet(selected.text, credentials);
  const modifiedXml = Buffer.from(modifiedText, "utf8");
  const output = encryptConfig(modifiedXml, selected.profile);
  const verified = decryptConfig(output, selected.profile);
  if (!verified.xml.equals(modifiedXml)) throw new Error("round-trip verification failed");
  fs.writeFileSync(outputPath, output);
  return {
    profile: selected.profile.name,
    changes: modifiedText === selected.text ? 0 : 1,
    size: output.length,
    keepCreds: Boolean(credentials && credentials.keep),
    user: (credentials && credentials.user) || "admin",
    pass: (credentials && credentials.pass) || "admin",
  };
}

function parseCredentials(argv) {
  return {
    keep: argv.includes("--keep-creds"),
    user: process.env.TELNET_USER || "admin",
    pass: process.env.TELNET_PASS || "admin",
  };
}

function main() {
  const args = process.argv.slice(2);
  const positional = args.filter((arg) => !arg.startsWith("--"));
  const [inputPath, outputPath] = positional;
  if (!inputPath || !outputPath) throw new Error("usage: node zte_config_telnet_enable.js input output [--keep-creds]");
  const credentials = parseCredentials(args);
  if (args.includes("--keep-creds")) credentials.keep = true;
  process.stdout.write("正在处理 config.bin ...\n");
  const result = processFile(inputPath, outputPath, credentials);
  process.stdout.write("处理完成。\n");
  process.stdout.write(`参数族：${result.profile}\n`);
  process.stdout.write(`输出文件：${outputPath}\n`);
  process.stdout.write("Telnet：端口 23\n");
  if (result.keepCreds) {
    process.stdout.write("用户名/密码：沿用原配置中的 TS_UName / TS_UPwd\n");
  } else {
    process.stdout.write(`用户名： ${result.user}\n密码： ${result.pass}\n`);
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write("config 文件暂不适配。\n");
    process.exitCode = 1;
  }
}

module.exports = { PROFILES, crc32, decryptConfig, encryptConfig, modifyTelnet, processFile };
