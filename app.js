const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const csurf = require("csurf");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = 3000;
const OPERATOR_PASSWORD = process.env.OPERATOR_PASSWORD || "change-operator-password";
const OPERATOR_COOKIE = "operator_auth";
const OPERATOR_TOKEN = crypto.createHash("sha256").update(OPERATOR_PASSWORD).digest("hex");
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS || 90);
const dataDir = path.join(__dirname, "data");
const consultFilePath = path.join(dataDir, "consult-requests.json");
const isProduction = process.env.NODE_ENV === "production";
const encryptionKeySource = process.env.PII_ENCRYPTION_KEY || "";
const PII_ENCRYPTION_KEY =
  /^[a-fA-F0-9]{64}$/.test(encryptionKeySource)
    ? Buffer.from(encryptionKeySource, "hex")
    : crypto.createHash("sha256").update(`${OPERATOR_PASSWORD}-fallback-pii-key`).digest();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.set("trust proxy", 1);
app.use(
  helmet({
    contentSecurityPolicy: false
  })
);
app.use((req, res, next) => {
  if (isProduction && req.headers["x-forwarded-proto"] !== "https") {
    return res.redirect(`https://${req.headers.host}${req.originalUrl}`);
  }
  return next();
});
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  csurf({
    cookie: {
      httpOnly: true,
      sameSite: "strict",
      secure: isProduction
    }
  })
);

const operatorLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: "로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요."
});

function purgeExpiredRequests(requests) {
  const retentionMs = RETENTION_DAYS * 24 * 60 * 60 * 1000;
  const now = Date.now();
  return requests.filter((item) => {
    const createdAt = new Date(item.createdAt).getTime();
    return Number.isFinite(createdAt) && now - createdAt <= retentionMs;
  });
}

function encryptPII(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", PII_ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted.toString("hex")}`;
}

function decryptPII(payload) {
  if (!payload || typeof payload !== "string" || !payload.includes(":")) {
    return "";
  }
  const [ivHex, tagHex, dataHex] = payload.split(":");
  if (!ivHex || !tagHex || !dataHex) return "";
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    PII_ENCRYPTION_KEY,
    Buffer.from(ivHex, "hex")
  );
  decipher.setAuthTag(Buffer.from(tagHex, "hex"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(dataHex, "hex")),
    decipher.final()
  ]);
  return decrypted.toString("utf8");
}

const LAST_INSURANCE_CHECK_LABELS = {
  within3m: "3개월 이내",
  within6m: "6개월 이내",
  within1y: "1년 이내",
  over1y: "1년 이상",
  unknown: "기억 안 남"
};

function sanitizeLastInsuranceCheck(value) {
  const v = String(value || "");
  return Object.prototype.hasOwnProperty.call(LAST_INSURANCE_CHECK_LABELS, v) ? v : "";
}

function toDisplayRequest(item) {
  return {
    ...item,
    name: item.nameEnc ? decryptPII(item.nameEnc) : item.name || "",
    phone: item.phoneEnc ? decryptPII(item.phoneEnc) : item.phone || "",
    ageLabel: formatAgeLabel(item),
    lastInsuranceCheckLabel:
      item.lastInsuranceCheck && LAST_INSURANCE_CHECK_LABELS[item.lastInsuranceCheck]
        ? LAST_INSURANCE_CHECK_LABELS[item.lastInsuranceCheck]
        : "-"
  };
}

function sanitizeName(name) {
  const clean = String(name || "").trim();
  return clean.length >= 2 && clean.length <= 30 ? clean : "";
}

function sanitizePhone(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  return /^01\d{8,9}$/.test(digits) ? digits : "";
}

const AGE_BAND_LABELS = {
  "20": "20대",
  "30": "30대",
  "40": "40대",
  "50": "50대",
  "60": "60대 이상"
};

function sanitizeAgeBand(ageBand) {
  const b = String(ageBand || "");
  return Object.prototype.hasOwnProperty.call(AGE_BAND_LABELS, b) ? b : "";
}

function formatAgeLabel(item) {
  if (item.ageBand === "10") return "10대";
  if (item.ageBand && AGE_BAND_LABELS[item.ageBand]) {
    return AGE_BAND_LABELS[item.ageBand];
  }
  if (item.age !== undefined && item.age !== null) {
    const n = Number(item.age);
    if (Number.isFinite(n)) return `${n}세`;
  }
  return "-";
}

function sanitizeGender(gender) {
  const g = String(gender || "").toLowerCase();
  if (g === "male" || g === "female") return g;
  return "";
}

function sanitizeInsuredStatus(status) {
  const s = String(status || "").toLowerCase();
  if (s === "yes" || s === "no" || s === "unknown") return s;
  return "unknown";
}

function ensureConsultStorage() {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  if (!fs.existsSync(consultFilePath)) {
    fs.writeFileSync(consultFilePath, JSON.stringify([], null, 2), "utf-8");
  }
}

function readConsultRequests() {
  ensureConsultStorage();
  let requests = JSON.parse(fs.readFileSync(consultFilePath, "utf-8"));
  const beforeCount = requests.length;
  let migrated = false;

  requests = requests.map((item) => {
    const next = { ...item };
    if (!next.nameEnc && next.name) {
      next.nameEnc = encryptPII(next.name);
      delete next.name;
      migrated = true;
    }
    if (!next.phoneEnc && next.phone) {
      next.phoneEnc = encryptPII(next.phone);
      delete next.phone;
      migrated = true;
    }
    return next;
  });

  requests = purgeExpiredRequests(requests);
  if (beforeCount !== requests.length || migrated) {
    saveConsultRequests(requests);
  }
  return requests;
}

function saveConsultRequests(requests) {
  ensureConsultStorage();
  const safeRequests = purgeExpiredRequests(requests);
  fs.writeFileSync(consultFilePath, JSON.stringify(safeRequests, null, 2), "utf-8");
}

function parseCookies(cookieHeader = "") {
  return cookieHeader
    .split(";")
    .map((v) => v.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const eqIdx = part.indexOf("=");
      if (eqIdx > -1) {
        const key = part.slice(0, eqIdx);
        const value = part.slice(eqIdx + 1);
        acc[key] = decodeURIComponent(value);
      }
      return acc;
    }, {});
}

function isOperatorAuthenticated(req) {
  const cookies = parseCookies(req.headers.cookie);
  return cookies[OPERATOR_COOKIE] === OPERATOR_TOKEN;
}

function requireOperatorAuth(req, res, next) {
  if (!isOperatorAuthenticated(req)) {
    return res.redirect("/operator/login");
  }
  return next();
}

app.get("/", (req, res) => {
  res.render("index", {
    success: req.query.sent === "1",
    fail: req.query.fail || "",
    csrfToken: req.csrfToken()
  });
});

app.post("/consult", (req, res) => {
  const {
    name,
    phone,
    ageBand,
    gender,
    consultHope,
    insuredStatus,
    lastInsuranceCheck,
    agreePrivacy,
    agreeThirdParty,
    agreeContact
  } = req.body;

  const safeName = sanitizeName(name);
  const safePhone = sanitizePhone(phone);
  const safeAgeBand = sanitizeAgeBand(ageBand);
  const safeGender = sanitizeGender(gender);
  const safeLastInsuranceCheck = sanitizeLastInsuranceCheck(lastInsuranceCheck);

  if (!safeName || !safePhone || !safeAgeBand || !safeGender || !safeLastInsuranceCheck) {
    return res.redirect("/?fail=validation#consult");
  }

  const requiredAgreements = agreePrivacy && agreeThirdParty && agreeContact;
  if (!requiredAgreements) {
    return res.redirect("/?fail=agreement#consult");
  }

  const requests = readConsultRequests();
  requests.push({
    id: Date.now(),
    nameEnc: encryptPII(safeName),
    phoneEnc: encryptPII(safePhone),
    ageBand: safeAgeBand,
    gender: safeGender,
    consultHope: consultHope || "yes",
    insuredStatus: sanitizeInsuredStatus(insuredStatus),
    lastInsuranceCheck: safeLastInsuranceCheck,
    agreements: {
      privacy: Boolean(agreePrivacy),
      thirdParty: Boolean(agreeThirdParty),
      contact: Boolean(agreeContact)
    },
    createdAt: new Date().toISOString()
  });
  saveConsultRequests(requests);
  return res.redirect("/?sent=1#consult");
});

app.get("/operator/login", (req, res) => {
  res.render("operator-login", { error: "", csrfToken: req.csrfToken() });
});

app.post("/operator/login", operatorLoginLimiter, (req, res) => {
  const { password } = req.body;
  if (password !== OPERATOR_PASSWORD) {
    return res.status(401).render("operator-login", {
      error: "비밀번호가 올바르지 않습니다.",
      csrfToken: req.csrfToken()
    });
  }

  res.cookie(OPERATOR_COOKIE, OPERATOR_TOKEN, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "strict",
    path: "/",
    maxAge: 8 * 60 * 60 * 1000
  });
  return res.redirect("/operator");
});

app.post("/operator/logout", (req, res) => {
  res.clearCookie(OPERATOR_COOKIE, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "strict",
    path: "/"
  });
  res.redirect("/operator/login");
});

app.get("/operator", requireOperatorAuth, (req, res) => {
  const requests = readConsultRequests()
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map(toDisplayRequest);
  res.render("operator", { requests, csrfToken: req.csrfToken() });
});

app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    if (req.path.startsWith("/operator")) {
      return res.redirect("/operator/login");
    }
    return res.redirect("/?fail=csrf#consult");
  }
  return next(err);
});

app.listen(PORT, () => {
  console.log(`보험 DB 사이트 실행: http://localhost:${PORT}`);
  if (OPERATOR_PASSWORD === "change-operator-password") {
    console.log("운용자 보호를 위해 OPERATOR_PASSWORD 환경변수를 설정하세요.");
  }
  if (!/^[a-fA-F0-9]{64}$/.test(encryptionKeySource)) {
    console.log("PII_ENCRYPTION_KEY 미설정: 안전한 64자리 hex 키를 .env에 설정하세요.");
  }
});
