const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");
const session = require("express-session");
const PgStore = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const { authenticator } = require("otplib");
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
const OPERATOR_TOTP_SECRET = String(process.env.OPERATOR_TOTP_SECRET || "").trim();
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.createHash("sha256").update(`${OPERATOR_PASSWORD}-default-session-secret`).digest("hex");
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS || 90);
const OPERATOR_PAGE_SIZE = 50;
const DUPLICATE_LEAD_WINDOW_HOURS = Number(process.env.DUPLICATE_LEAD_WINDOW_HOURS || 24);
const AGREEMENT_VERSION = process.env.AGREEMENT_VERSION || "v1.0";
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
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"]
      }
    }
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
    store: new PgStore({
      pool: dbPool,
      tableName: "user_sessions",
      createTableIfMissing: true
    }),
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

const MONTHLY_BUDGET_LABELS = {
  "200": "200만원",
  "300": "300만원",
  "400": "400만원",
  "500": "500만원",
  "600": "600만원",
  "700": "700만원",
  "800": "800만원",
  "900": "900만원",
  "1000plus": "1000만원+"
};

const AVAILABLE_TIME_LABELS = {
  morning: "오전 (09:00~12:00)",
  afternoon: "오후 (12:00~18:00)",
  evening: "저녁 (18:00~21:00)",
  anytime: "상관없음"
};

const DESIRED_COVERAGE_LABELS = {
  life: "생명보험",
  nonlife: "손해보험",
  third: "제3보험"
};

const EXISTING_INSURANCE_LABELS = {
  life: "생명보험",
  nonlife: "손해보험",
  third: "제3보험",
  unknown: "잘 모르겠다"
};

function toDisplayRequest(item) {
  const existingInsurance = Array.isArray(item.existingInsurance) ? item.existingInsurance : [];
  return {
    ...item,
    name: item.nameEnc ? decryptPII(item.nameEnc) : item.name || "",
    phone: item.phoneEnc ? decryptPII(item.phoneEnc) : item.phone || "",
    ageLabel: formatAgeLabel(item),
    regionLabel:
      item.region && REGION_LABELS[item.region] ? REGION_LABELS[item.region] : item.regionLabel || "-",
    monthlyBudgetLabel:
      item.monthlyBudget && MONTHLY_BUDGET_LABELS[item.monthlyBudget]
        ? MONTHLY_BUDGET_LABELS[item.monthlyBudget]
        : "-",
    availableTimeLabel:
      item.availableTime && AVAILABLE_TIME_LABELS[item.availableTime]
        ? AVAILABLE_TIME_LABELS[item.availableTime]
        : "-",
    desiredCoverageLabel:
      item.desiredCoverage && DESIRED_COVERAGE_LABELS[item.desiredCoverage]
        ? DESIRED_COVERAGE_LABELS[item.desiredCoverage]
        : "-",
    existingInsuranceLabels:
      existingInsurance.length > 0
        ? existingInsurance
            .map((code) => EXISTING_INSURANCE_LABELS[code])
            .filter(Boolean)
            .join(", ")
        : "-",
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
  monthlyBudget: z.enum(["200", "300", "400", "500", "600", "700", "800", "900", "1000plus"]),
  availableTime: z.enum(["morning", "afternoon", "evening", "anytime"]),
  desiredCoverage: z.enum(["life", "nonlife", "third"]),
  consultHope: z.enum(["yes", "no"]).default("yes"),
  insuredStatus: z.enum(["yes", "no", "unknown"]).default("unknown"),
  existingInsurance: z.array(z.enum(["life", "nonlife", "third", "unknown"])).default([]),
  lastInsuranceCheck: z.enum(["within3m", "within6m", "within1y", "over1y", "unknown"]),
  agreePrivacy: z.boolean(),
  agreeThirdParty: z.boolean(),
  agreeContact: z.boolean()
})
  .superRefine((data, ctx) => {
    if (data.insuredStatus === "yes" && data.existingInsurance.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["existingInsurance"],
        message: "기존 보험 선택 필요"
      });
    }
  });

function normalizeExistingInsurance(value) {
  const rawList = Array.isArray(value) ? value : [value];
  const normalized = rawList
    .map((item) => String(item || "").toLowerCase())
    .filter((item) => ["life", "nonlife", "third", "unknown"].includes(item));
  const unique = [...new Set(normalized)];
  return unique.includes("unknown") ? ["unknown"] : unique;
}

function parseConsultPayload(body) {
  return consultPayloadSchema.safeParse({
    name: String(body.name || ""),
    phone: String(body.phone || ""),
    region: String(body.region || ""),
    ageBand: String(body.ageBand || ""),
    gender: String(body.gender || "").toLowerCase(),
    monthlyBudget: String(body.monthlyBudget || ""),
    availableTime: String(body.availableTime || ""),
    desiredCoverage: String(body.desiredCoverage || ""),
    consultHope: body.consultHope ? String(body.consultHope || "").toLowerCase() : "yes",
    insuredStatus: body.insuredStatus ? String(body.insuredStatus || "").toLowerCase() : "unknown",
    existingInsurance: normalizeExistingInsurance(body.existingInsurance),
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

function hashPhone(phone) {
  return crypto.createHash("sha256").update(phone).digest("hex");
}

async function initDb() {
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS consult_requests (
      id BIGSERIAL PRIMARY KEY,
      name_enc TEXT NOT NULL,
      phone_enc TEXT NOT NULL,
      phone_hash TEXT NOT NULL DEFAULT '',
      region TEXT NOT NULL,
      age_band TEXT NOT NULL,
      gender TEXT NOT NULL,
      monthly_budget TEXT NOT NULL DEFAULT '200',
      available_time TEXT NOT NULL DEFAULT 'anytime',
      desired_coverage TEXT NOT NULL DEFAULT 'life',
      existing_insurance JSONB NOT NULL DEFAULT '[]'::jsonb,
      agreement_version TEXT NOT NULL DEFAULT 'v1.0',
      consult_hope TEXT NOT NULL,
      insured_status TEXT NOT NULL,
      last_insurance_check TEXT NOT NULL,
      agreements JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await dbPool.query(`
    ALTER TABLE consult_requests
    ADD COLUMN IF NOT EXISTS phone_hash TEXT NOT NULL DEFAULT ''
  `);
  await dbPool.query(`
    ALTER TABLE consult_requests
    ADD COLUMN IF NOT EXISTS monthly_budget TEXT NOT NULL DEFAULT '200'
  `);
  await dbPool.query(`
    ALTER TABLE consult_requests
    ADD COLUMN IF NOT EXISTS available_time TEXT NOT NULL DEFAULT 'anytime'
  `);
  await dbPool.query(`
    ALTER TABLE consult_requests
    ADD COLUMN IF NOT EXISTS desired_coverage TEXT NOT NULL DEFAULT 'life'
  `);
  await dbPool.query(`
    ALTER TABLE consult_requests
    ADD COLUMN IF NOT EXISTS existing_insurance JSONB NOT NULL DEFAULT '[]'::jsonb
  `);
  await dbPool.query(`
    ALTER TABLE consult_requests
    ADD COLUMN IF NOT EXISTS agreement_version TEXT NOT NULL DEFAULT 'v1.0'
  `);
  await dbPool.query(`
    CREATE INDEX IF NOT EXISTS idx_consult_requests_created_at_desc
    ON consult_requests (created_at DESC)
  `);
  await dbPool.query(`
    CREATE INDEX IF NOT EXISTS idx_consult_requests_phone_hash_created_at
    ON consult_requests (phone_hash, created_at DESC)
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

async function readConsultRequests({ limit = OPERATOR_PAGE_SIZE, offset = 0 } = {}) {
  await purgeExpiredRequestsDb();
  const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.min(200, Number(limit))) : OPERATOR_PAGE_SIZE;
  const safeOffset = Number.isFinite(offset) ? Math.max(0, Number(offset)) : 0;
  const result = await dbPool.query(
    `
      SELECT
        id,
        name_enc AS "nameEnc",
        phone_enc AS "phoneEnc",
        region,
        age_band AS "ageBand",
        gender,
        monthly_budget AS "monthlyBudget",
        available_time AS "availableTime",
        desired_coverage AS "desiredCoverage",
        existing_insurance AS "existingInsurance",
        agreement_version AS "agreementVersion",
        consult_hope AS "consultHope",
        insured_status AS "insuredStatus",
        last_insurance_check AS "lastInsuranceCheck",
        agreements,
        created_at AS "createdAt"
      FROM consult_requests
      ORDER BY created_at DESC
      LIMIT $1
      OFFSET $2
    `
    ,
    [safeLimit, safeOffset]
  );
  // #region agent log
  fetch("http://127.0.0.1:7561/ingest/5c01f500-4c66-473d-982d-543e2111d81d", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "bdbd90" },
    body: JSON.stringify({
      sessionId: "bdbd90",
      runId: "run-consult-list",
      hypothesisId: "H3",
      location: "app.js:readConsultRequests result",
      message: "latest row selected fields",
      data: {
        rowCount: result.rows.length,
        latestHasMonthlyBudget:
          result.rows.length > 0 ? Boolean(result.rows[0].monthlyBudget) : false,
        latestHasAvailableTime:
          result.rows.length > 0 ? Boolean(result.rows[0].availableTime) : false,
        latestHasDesiredCoverage:
          result.rows.length > 0 ? Boolean(result.rows[0].desiredCoverage) : false,
        latestExistingInsuranceType:
          result.rows.length > 0
            ? Array.isArray(result.rows[0].existingInsurance)
              ? "array"
              : typeof result.rows[0].existingInsurance
            : "none"
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
  return result.rows.map((row) => ({
    ...row,
    createdAt: new Date(row.createdAt).toISOString()
  }));
}

async function readConsultRequestCount() {
  const result = await dbPool.query("SELECT COUNT(*)::int AS total FROM consult_requests");
  return result.rows[0]?.total || 0;
}

async function hasRecentDuplicateLead(phoneHash, windowHours = DUPLICATE_LEAD_WINDOW_HOURS) {
  const safeWindowHours = Number.isFinite(windowHours) ? Math.max(1, Math.min(72, Number(windowHours))) : 24;
  const result = await dbPool.query(
    `
      SELECT 1
      FROM consult_requests
      WHERE phone_hash = $1
        AND created_at >= NOW() - ($2::int * INTERVAL '1 hour')
      LIMIT 1
    `,
    [phoneHash, safeWindowHours]
  );
  return result.rows.length > 0;
}

async function appendConsultRequest(request) {
  await purgeExpiredRequestsDb();
  // #region agent log
  fetch("http://127.0.0.1:7561/ingest/5c01f500-4c66-473d-982d-543e2111d81d", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "bdbd90" },
    body: JSON.stringify({
      sessionId: "bdbd90",
      runId: "run-consult-list",
      hypothesisId: "H2",
      location: "app.js:appendConsultRequest before insert",
      message: "insert payload field presence",
      data: {
        hasMonthlyBudget: Boolean(request.monthlyBudget),
        hasAvailableTime: Boolean(request.availableTime),
        hasDesiredCoverage: Boolean(request.desiredCoverage),
        existingInsuranceCount: Array.isArray(request.existingInsurance)
          ? request.existingInsurance.length
          : -1
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
  try {
    await dbPool.query(
      `
      INSERT INTO consult_requests (
        name_enc,
        phone_enc,
        phone_hash,
        region,
        age_band,
        gender,
        monthly_budget,
        available_time,
        desired_coverage,
        existing_insurance,
        agreement_version,
        consult_hope,
        insured_status,
        last_insurance_check,
        agreements,
        created_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15::jsonb,$16::timestamptz)
    `,
    [
      request.nameEnc,
      request.phoneEnc,
      request.phoneHash,
      request.region,
      request.ageBand,
      request.gender,
      request.monthlyBudget,
      request.availableTime,
      request.desiredCoverage,
      JSON.stringify(request.existingInsurance || []),
      request.agreementVersion,
      request.consultHope,
      request.insuredStatus,
      request.lastInsuranceCheck,
      JSON.stringify(request.agreements),
      request.createdAt
      ]
    );
    // #region agent log
    fetch("http://127.0.0.1:7561/ingest/5c01f500-4c66-473d-982d-543e2111d81d", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "bdbd90" },
      body: JSON.stringify({
        sessionId: "bdbd90",
        runId: "run-consult-list",
        hypothesisId: "H2",
        location: "app.js:appendConsultRequest after insert",
        message: "insert query success",
        data: { inserted: true },
        timestamp: Date.now()
      })
    }).catch(() => {});
    // #endregion
  } catch (error) {
    // #region agent log
    fetch("http://127.0.0.1:7561/ingest/5c01f500-4c66-473d-982d-543e2111d81d", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "bdbd90" },
      body: JSON.stringify({
        sessionId: "bdbd90",
        runId: "run-consult-list",
        hypothesisId: "H4",
        location: "app.js:appendConsultRequest insert error",
        message: "insert query failed",
        data: { code: error && error.code ? String(error.code) : "unknown" },
        timestamp: Date.now()
      })
    }).catch(() => {});
    // #endregion
    throw error;
  }
}

async function verifyOperatorCredentials(username, password) {
  if (username !== OPERATOR_USERNAME) return false;
  if (OPERATOR_PASSWORD_HASH) {
    return bcrypt.compare(password, OPERATOR_PASSWORD_HASH);
  }
  return password === OPERATOR_PASSWORD;
}

function verifyOperatorOtp(otp) {
  if (!OPERATOR_TOTP_SECRET) return true;
  const token = String(otp || "").trim();
  if (!/^\d{6}$/.test(token)) return false;
  return authenticator.check(token, OPERATOR_TOTP_SECRET);
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
  // #region agent log
  fetch("http://127.0.0.1:7561/ingest/5c01f500-4c66-473d-982d-543e2111d81d", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "bdbd90" },
    body: JSON.stringify({
      sessionId: "bdbd90",
      runId: "run-consult-list",
      hypothesisId: "H1",
      location: "app.js:/consult parsed",
      message: "consult payload parse result",
      data: {
        success: parsed.success,
        hasMonthlyBudget: parsed.success ? Boolean(parsed.data.monthlyBudget) : false,
        hasAvailableTime: parsed.success ? Boolean(parsed.data.availableTime) : false,
        hasDesiredCoverage: parsed.success ? Boolean(parsed.data.desiredCoverage) : false,
        existingInsuranceCount: parsed.success ? parsed.data.existingInsurance.length : -1
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
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

  const safePhone = sanitizePhone(payload.phone);
  const phoneHash = hashPhone(safePhone);
  if (await hasRecentDuplicateLead(phoneHash)) {
    await writeAuditLog(req, "consult_create", "duplicate_blocked", "consult_request", phoneHash.slice(0, 12));
    return res.redirect("/?fail=duplicate#consult");
  }

  const requestId = String(Date.now());
  await appendConsultRequest({
    id: requestId,
    nameEnc: encryptPII(payload.name),
    phoneEnc: encryptPII(safePhone),
    phoneHash,
    region: sanitizeRegion(payload.region),
    ageBand: sanitizeAgeBand(payload.ageBand),
    gender: sanitizeGender(payload.gender),
    monthlyBudget: payload.monthlyBudget,
    availableTime: payload.availableTime,
    desiredCoverage: payload.desiredCoverage,
    existingInsurance: payload.existingInsurance,
    agreementVersion: AGREEMENT_VERSION,
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
  const otp = String(req.body.otp || "");
  const isValid = await verifyOperatorCredentials(username, password);
  const otpValid = verifyOperatorOtp(otp);
  if (!isValid || !otpValid) {
    await writeAuditLog(req, "operator_login", "fail", "operator_auth", username || "unknown");
    return res.status(401).render("operator-login", {
      error: OPERATOR_TOTP_SECRET
        ? "아이디, 비밀번호 또는 인증코드를 확인해주세요."
        : "아이디 또는 비밀번호가 올바르지 않습니다.",
      csrfToken: req.csrfToken()
    });
  }

  return req.session.regenerate((err) => {
    if (err) {
      return res.status(500).render("operator-login", {
        error: "로그인 처리 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
        csrfToken: req.csrfToken()
      });
    }
    req.session.operatorAuthenticated = true;
    req.session.operatorUsername = OPERATOR_USERNAME;
    writeAuditLog(req, "operator_login", "success", "operator_auth", OPERATOR_USERNAME)
      .catch(() => null)
      .finally(() => res.redirect("/operator"));
  });
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
  const pageRaw = Number.parseInt(String(req.query.page || "1"), 10);
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1;
  const offset = (page - 1) * OPERATOR_PAGE_SIZE;
  const [totalCount, rows] = await Promise.all([
    readConsultRequestCount(),
    readConsultRequests({ limit: OPERATOR_PAGE_SIZE, offset })
  ]);
  const requests = rows.map(toDisplayRequest);
  const totalPages = Math.max(1, Math.ceil(totalCount / OPERATOR_PAGE_SIZE));
  const hasPrev = page > 1;
  const hasNext = page < totalPages;
  await writeAuditLog(req, "operator_view", "success", "consult_request", "list");
  res.render("operator", {
    requests,
    csrfToken: req.csrfToken(),
    pagination: {
      page,
      pageSize: OPERATOR_PAGE_SIZE,
      totalCount,
      totalPages,
      hasPrev,
      hasNext
    }
  });
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
