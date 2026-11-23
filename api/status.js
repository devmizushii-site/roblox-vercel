const { checkAuth, readJsonBody } = require("./_util");

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ connected: false, error: "Method not allowed" });
  if (!checkAuth(req)) return res.status(401).json({ connected: false, error: "Not logged in." });

  const body = await readJsonBody(req);
  const cookie = (body.cookie || "").trim();
  if (!cookie) {
    return res.status(200).json({ connected: false, error: "Walang ibinigay na cookie." });
  }

  const cookieHeader = `.ROBLOSECURITY=${cookie}`;

  try {
    const meResp = await fetch("https://users.roblox.com/v1/users/authenticated", {
      headers: { Cookie: cookieHeader, "User-Agent": "Mozilla/5.0" },
    });
    if (meResp.status !== 200) {
      return res.status(200).json({
        connected: false,
        error: `Hindi ma-verify ang cookie (status ${meResp.status}). Baka expired na.`,
      });
    }
    const me = await meResp.json();

    // Kumuha ng CSRF token (sinasadyang 403 sa logout endpoint).
    const csrfResp = await fetch("https://auth.roblox.com/v1/logout", {
      method: "POST",
      headers: { Cookie: cookieHeader, "User-Agent": "Mozilla/5.0" },
    });
    const csrfToken = csrfResp.headers.get("x-csrf-token");
    if (!csrfToken) {
      return res.status(200).json({
        connected: false,
        error: "Hindi makuha ang CSRF token. Posibleng mali/expired na ang cookie.",
      });
    }

    return res.status(200).json({
      connected: true,
      username: me.name,
      userId: me.id,
      csrfToken,
    });
  } catch (e) {
    return res.status(200).json({ connected: false, error: String(e.message || e) });
  }
};
