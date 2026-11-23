const { sign, readJsonBody } = require("./_util");

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ ok: false });

  const appPassword = process.env.APP_PASSWORD;
  if (!appPassword) {
    // Walang gate na naka-set — ituring na palaging "authed".
    res.setHeader("Set-Cookie", `session=; Max-Age=0; Path=/`);
    return res.status(200).json({ ok: true, note: "Walang APP_PASSWORD na naka-set, walang gate." });
  }

  const body = await readJsonBody(req);
  if (body.password !== appPassword) {
    return res.status(401).json({ ok: false });
  }

  let token;
  try {
    token = sign(`authed:${Date.now()}`);
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }

  const maxAge = 7 * 24 * 60 * 60; // 7 days
  res.setHeader(
    "Set-Cookie",
    `session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`
  );
  return res.status(200).json({ ok: true });
};
