#!/usr/bin/env node
/**
 * 로컬 .env 의 OPERATOR_PASSWORD_HASH 와 평문 비밀번호가 맞는지 확인합니다.
 * Railway에 넣은 값을 검증하려면 일시적으로 .env에 같은 해시를 넣고 실행하세요.
 *
 * Usage: node scripts/verify-operator-hash.js <평문비밀번호>
 */
require("dotenv").config();
const bcrypt = require("bcryptjs");

function normalizeOperatorPasswordHash(raw) {
  let s = String(raw ?? "").trim();
  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    s = s.slice(1, -1).trim();
  }
  return s;
}

const hash = normalizeOperatorPasswordHash(process.env.OPERATOR_PASSWORD_HASH || "");
const password = process.argv[2];

if (!password) {
  console.error("Usage: node scripts/verify-operator-hash.js <평문비밀번호>");
  process.exit(1);
}
if (!hash) {
  console.error(".env 에 OPERATOR_PASSWORD_HASH 가 없습니다.");
  process.exit(1);
}
if (!/^\$2[aby]\$\d{2}\$/.test(hash)) {
  console.warn("경고: 해시가 $2a$ / $2b$ 형식이 아닙니다. Railway에 잘못 붙였을 수 있습니다.\n");
}

bcrypt.compare(String(password).trim(), hash).then((ok) => {
  console.log(
    ok
      ? "일치: 이 비밀번호는 현재 .env의 해시와 짝이 맞습니다."
      : "불일치: 해시를 만든 비밀번호가 아니거나, .env 해시가 Railway와 다릅니다."
  );
  process.exit(ok ? 0 : 1);
});
