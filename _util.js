const crypto = require("crypto");

function getSecret() {
  const s = process.env.APP_SECRET;
  if (!s) {
    throw new Error(
      "Walang APP_SECRET na naka-set sa Vercel Environment Variables. Kailangan ito para gumana ang login."
    );
  }
  return s;
}

function sign(value) {
  const h = crypto.createHmac("sha256", getSecret()).update(value).digest("hex");
  return `${value}.${h}`;
}

function verify(token) {
  if (!token || !token.includes(".")) return false;
  const idx = token.lastIndexOf(".");
  const value = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expected = crypto.createHmac("sha256", getSecret()).update(value).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

// Ibinabalik: true kung pumasa sa auth check (o kung walang APP_PASSWORD
// na naka-set, ibig sabihin walang gate). false kung bawal.
function checkAuth(req) {
  const appPassword = process.env.APP_PASSWORD;
  if (!appPassword) return true; // walang gate kung walang APP_PASSWORD
  const cookies = parseCookies(req);
  const token = cookies["session"];
  if (!token) return false;
  if (!verify(token)) return false;
  const value = token.slice(0, token.lastIndexOf("."));
  const [, tsStr] = value.split(":");
  const ts = Number(tsStr);
  if (!ts || Date.now() - ts > 7 * 24 * 60 * 60 * 1000) return false; // 7 days
  return true;
}

async function readJsonBody(req) {
  if (req.body && typeof req.body === "object") return req.body; // Vercel auto-parses kung JSON content-type
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(data || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

module.exports = { sign, verify, parseCookies, checkAuth, readJsonBody };
