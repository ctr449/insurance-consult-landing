const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { z } = require("zod");
const cookieParser = require("cookie-parser");
const csurf = require("csurf");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const OPERATOR_USERNAME = process.env.OPERATOR_USERNAME || "operator";
const OPERATOR_PASSWORD = process.env.OPERATOR_PASSWORD || "change-operator-password";
const OPERATOR_PASSWORD_HASH = process.env.OPERATOR_PASSWORD_HASH || "";
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.createHash("sha256").update(`${OPERATOR_PASSWORD}-default-session-secret`).digest("hex");
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS || 90);
const DATABASE_URL = process.env.DATABASE_URL || "";
const isProduction = process.env.NODE_ENV === "production";
const encryptionKeySource = process.env.PII_ENCRYPTION_KEY || "";
const PII_ENCRYPTION_KEY =
  /^[a-fA-F0-9]{64}$/.test(encryptionKeySource)
    ? Buffer.from(encryptionKeySource, "hex")
    : crypto.createHash("sha256").update(`${OPERATOR_PASSWORD}-fallback-pii-key`).digest();
if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is required. 3단계에서는 JSON fallback을 지원하지 않습니다.");
}
const dbPool = new Pool({
  connectionString: DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false
});

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
  session({
    name: "operator_session",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProduction,
      sameSite: "strict",
      maxAge: 8 * 60 * 60 * 1000
    }
  })
);
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
  message: "로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.",
  handler: (req, res) => {
    res.status(429).send("로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.");
  }
});

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

const REGION_LABELS = {
  chungbuk: "충청북도",
  chungnam: "충청남도"
};

function toDisplayRequest(item) {
  return {
    ...item,
    name: item.nameEnc ? decryptPII(item.nameEnc) : item.name || "",
    phone: item.phoneEnc ? decryptPII(item.phoneEnc) : item.phone || "",
    ageLabel: formatAgeLabel(item),
    regionLabel:
      item.region && REGION_LABELS[item.region] ? REGION_LABELS[item.region] : item.regionLabel || "-",
    lastInsuranceCheckLabel:
      item.lastInsuranceCheck && LAST_INSURANCE_CHECK_LABELS[item.lastInsuranceCheck]
        ? LAST_INSURANCE_CHECK_LABELS[item.lastInsuranceCheck]
        : "-"
  };
}

function normalizePhone(phone) {
  const raw = String(phone || "");
  const digitsRaw = raw.replace(/\D/g, "");
  return digitsRaw.startsWith("82") && digitsRaw.length >= 11 && digitsRaw.length <= 12
    ? `0${digitsRaw.slice(2)}`
    : digitsRaw;
}

const consultPayloadSchema = z.object({
  name: z.string().trim().min(2).max(30),
  phone: z
    .string()
    .transform((value) => normalizePhone(value))
    .refine((value) => /^01\d{8,9}$/.test(value), "invalid phone"),
  region: z.enum(["chungbuk", "chungnam"]),
  ageBand: z.enum(["20", "30", "40", "50", "60"]),
  gender: z.enum(["male", "female"]),
  consultHope: z.enum(["yes", "no"]).default("yes"),
  insuredStatus: z.enum(["yes", "no", "unknown"]).default("unknown"),
  lastInsuranceCheck: z.enum(["within3m", "within6m", "within1y", "over1y", "unknown"]),
  agreePrivacy: z.boolean(),
  agreeThirdParty: z.boolean(),
  agreeContact: z.boolean()
});

function parseConsultPayload(body) {
  return consultPayloadSchema.safeParse({
    name: String(body.name || ""),
    phone: String(body.phone || ""),
    region: String(body.region || ""),
    ageBand: String(body.ageBand || ""),
    gender: String(body.gender || "").toLowerCase(),
    consultHope: body.consultHope ? String(body.consultHope || "").toLowerCase() : "yes",
    insuredStatus: body.insuredStatus ? String(body.insuredStatus || "").toLowerCase() : "unknown",
    lastInsuranceCheck: String(body.lastInsuranceCheck || ""),
    agreePrivacy: Boolean(body.agreePrivacy),
    agreeThirdParty: Boolean(body.agreeThirdParty),
    agreeContact: Boolean(body.agreeContact)
  });
}

function formatAgeLabel(item) {
  if (item.ageBand && AGE_BAND_LABELS[item.ageBand]) {
    return AGE_BAND_LABELS[item.ageBand];
  }
  return "-";
}

function getClientIp(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  if (typeof forwardedFor === "string" && forwardedFor.length > 0) {
    return forwardedFor.split(",")[0].trim().slice(0, 100);
  }
  return (req.ip || req.socket?.remoteAddress || "").slice(0, 100);
}

async function writeAuditLog(req, action, result, resourceType, resourceId) {
  const actorId = req.session?.operatorUsername || null;
  const userAgent = String(req.headers["user-agent"] || "").slice(0, 255);
  await dbPool.query(
    `
      INSERT INTO audit_logs (actor_id, action, resource_type, resource_id, result, ip, user_agent, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
    `,
    [actorId, action, resourceType, resourceId, result, getClientIp(req), userAgent]
  );
}

const AGE_BAND_LABELS = {
  "20": "20대",
  "30": "30대",
  "40": "40대",
  "50": "50대",
  "60": "60대 이상"
};

function sanitizeInsuredStatus(status) {
  const s = String(status || "").toLowerCase();
  if (s === "yes" || s === "no" || s === "unknown") return s;
  return "unknown";
}

function sanitizeLastInsuranceCheck(value) {
  const v = String(value || "");
  return Object.prototype.hasOwnProperty.call(LAST_INSURANCE_CHECK_LABELS, v) ? v : "unknown";
}

function sanitizeAgeBand(ageBand) {
  const b = String(ageBand || "");
  return Object.prototype.hasOwnProperty.call(AGE_BAND_LABELS, b) ? b : "";
}

function sanitizeGender(gender) {
  const g = String(gender || "").toLowerCase();
  if (g === "male" || g === "female") return g;
  return "";
}

function sanitizeRegion(region) {
  const r = String(region || "");
  return Object.prototype.hasOwnProperty.call(REGION_LABELS, r) ? r : "";
}

function sanitizeName(name) {
  const clean = String(name || "").trim();
  return clean.length >= 2 && clean.length <= 30 ? clean : "";
}

function sanitizePhone(phone) {
  const digits = normalizePhone(phone);
  return /^01\d{8,9}$/.test(digits) ? digits : "";
}

async function initDb() {
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS consult_requests (
      id BIGSERIAL PRIMARY KEY,
      name_enc TEXT NOT NULL,
      phone_enc TEXT NOT NULL,
      region TEXT NOT NULL,
      age_band TEXT NOT NULL,
      gender TEXT NOT NULL,
      consult_hope TEXT NOT NULL,
      insured_status TEXT NOT NULL,
      last_insurance_check TEXT NOT NULL,
      agreements JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor_id TEXT,
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT NOT NULL,
      result TEXT NOT NULL,
      ip TEXT NOT NULL,
      user_agent TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function purgeExpiredRequestsDb() {
  await dbPool.query(
    "DELETE FROM consult_requests WHERE created_at < (NOW() - ($1::int * INTERVAL '1 day'))",
    [RETENTION_DAYS]
  );
}

async function readConsultRequests() {
  await purgeExpiredRequestsDb();
  const result = await dbPool.query(
    `
      SELECT
        id,
        name_enc AS "nameEnc",
        phone_enc AS "phoneEnc",
        region,
        age_band AS "ageBand",
        gender,
        consult_hope AS "consultHope",
        insured_status AS "insuredStatus",
        last_insurance_check AS "lastInsuranceCheck",
        agreements,
        created_at AS "createdAt"
      FROM consult_requests
      ORDER BY created_at DESC
    `
  );
  return result.rows.map((row) => ({
    ...row,
    createdAt: new Date(row.createdAt).toISOString()
  }));
}

async function appendConsultRequest(request) {
  await purgeExpiredRequestsDb();
  await dbPool.query(
    `
      INSERT INTO consult_requests (
        name_enc,
        phone_enc,
        region,
        age_band,
        gender,
        consult_hope,
        insured_status,
        last_insurance_check,
        agreements,
        created_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::timestamptz)
    `,
    [
      request.nameEnc,
      request.phoneEnc,
      request.region,
      request.ageBand,
      request.gender,
      request.consultHope,
      request.insuredStatus,
      request.lastInsuranceCheck,
      JSON.stringify(request.agreements),
      request.createdAt
    ]
  );
}

async function verifyOperatorCredentials(username, password) {
  if (username !== OPERATOR_USERNAME) return false;
  if (OPERATOR_PASSWORD_HASH) {
    return bcrypt.compare(password, OPERATOR_PASSWORD_HASH);
  }
  return password === OPERATOR_PASSWORD;
}

function isOperatorAuthenticated(req) {
  return Boolean(
    req.session &&
      req.session.operatorAuthenticated === true &&
      req.session.operatorUsername === OPERATOR_USERNAME
  );
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

app.post("/consult", async (req, res) => {
  const parsed = parseConsultPayload(req.body);
  if (!parsed.success) {
    await writeAuditLog(req, "consult_create", "validation_fail", "consult_request", "new");
    return res.redirect("/?fail=validation#consult");
  }

  const payload = parsed.data;
  const requiredAgreements = payload.agreePrivacy && payload.agreeThirdParty && payload.agreeContact;
  if (!requiredAgreements) {
    await writeAuditLog(req, "consult_create", "agreement_fail", "consult_request", "new");
    return res.redirect("/?fail=agreement#consult");
  }

  const requestId = String(Date.now());
  await appendConsultRequest({
    id: requestId,
    nameEnc: encryptPII(payload.name),
    phoneEnc: encryptPII(payload.phone),
    region: sanitizeRegion(payload.region),
    ageBand: sanitizeAgeBand(payload.ageBand),
    gender: sanitizeGender(payload.gender),
    consultHope: payload.consultHope,
    insuredStatus: sanitizeInsuredStatus(payload.insuredStatus),
    lastInsuranceCheck: sanitizeLastInsuranceCheck(payload.lastInsuranceCheck),
    agreements: {
      privacy: payload.agreePrivacy,
      thirdParty: payload.agreeThirdParty,
      contact: payload.agreeContact
    },
    createdAt: new Date().toISOString()
  });
  await writeAuditLog(req, "consult_create", "success", "consult_request", requestId);
  return res.redirect("/?sent=1#consult");
});

app.get("/operator/login", (req, res) => {
  res.render("operator-login", { error: "", csrfToken: req.csrfToken() });
});

app.post("/operator/login", operatorLoginLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const isValid = await verifyOperatorCredentials(username, password);
  if (!isValid) {
    await writeAuditLog(req, "operator_login", "fail", "operator_auth", username || "unknown");
    return res.status(401).render("operator-login", {
      error: "아이디 또는 비밀번호가 올바르지 않습니다.",
      csrfToken: req.csrfToken()
    });
  }

  req.session.operatorAuthenticated = true;
  req.session.operatorUsername = OPERATOR_USERNAME;
  await writeAuditLog(req, "operator_login", "success", "operator_auth", OPERATOR_USERNAME);
  return res.redirect("/operator");
});

app.post("/operator/logout", (req, res) => {
  const actor = req.session?.operatorUsername || "unknown";
  req.session.destroy(() => {
    res.clearCookie("operator_session", {
      httpOnly: true,
      secure: isProduction,
      sameSite: "strict",
      path: "/"
    });
    writeAuditLog(req, "operator_logout", "success", "operator_auth", actor)
      .catch(() => null)
      .finally(() => res.redirect("/operator/login"));
  });
});

app.get("/operator", requireOperatorAuth, async (req, res) => {
  const requests = (await readConsultRequests())
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map(toDisplayRequest);
  await writeAuditLog(req, "operator_view", "success", "consult_request", "list");
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

initDb()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`보험 DB 사이트 실행 (포트 ${PORT})`);
      console.log("상담 저장소: PostgreSQL");
      if (!OPERATOR_PASSWORD_HASH && OPERATOR_PASSWORD === "change-operator-password") {
        console.log("운용자 보호를 위해 OPERATOR_PASSWORD 환경변수를 설정하세요.");
      }
      if (!OPERATOR_PASSWORD_HASH) {
        console.log("권장: OPERATOR_PASSWORD_HASH(bcrypt)와 SESSION_SECRET을 .env에 설정하세요.");
      }
      if (!/^[a-fA-F0-9]{64}$/.test(encryptionKeySource)) {
        console.log("PII_ENCRYPTION_KEY 미설정: 안전한 64자리 hex 키를 .env에 설정하세요.");
      }
    });
  })
  .catch((err) => {
    console.error("DB 초기화 실패:", err);
    process.exit(1);
  });
