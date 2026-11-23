const { checkAuth, readJsonBody } = require("./_util");

const CREATE_UNIVERSE_URL = "https://apis.roblox.com/universes/v1/universes/create";
const USER_URL = "https://users.roblox.com/v1/users/authenticated";

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method not allowed" });
  if (!checkAuth(req)) return res.status(401).json({ ok: false, error: "Not logged in." });

  const body = await readJsonBody(req);
  const cookie = (body.cookie || "").trim();
  let csrfToken = body.csrfToken || "";
  const templatePlaceId = Number(body.templatePlaceId) || 95206881;

  if (!cookie) return res.status(200).json({ ok: false, error: "Walang cookie." });

  const cookieHeader = `.ROBLOSECURITY=${cookie}`;

  async function callCreate(token) {
    return fetch(CREATE_UNIVERSE_URL, {
      method: "POST",
      headers: {
        Cookie: cookieHeader,
        "Content-Type": "application/json",
        "x-csrf-token": token,
        "User-Agent": "Mozilla/5.0",
      },
      body: JSON.stringify({ templatePlaceId }),
    });
  }

  let resp;
  try {
    resp = await callCreate(csrfToken);
    if (resp.status === 403) {
      const freshToken = resp.headers.get("x-csrf-token");
      if (freshToken) {
        csrfToken = freshToken;
        resp = await callCreate(csrfToken);
      }
    }
  } catch (e) {
    return res.status(200).json({ ok: false, error: `Request error: ${e.message || e}` });
  }

  if (resp.status !== 200) {
    const text = await resp.text();
    const err = `${resp.status}: ${text.slice(0, 300)}`;
    return res.status(200).json({ ok: false, error: err, csrfToken });
  }

  let data = {};
  try {
    data = await resp.json();
  } catch {
    /* ignore */
  }
  const universeId = data.universeId || data.UniverseId || data.id;
  const placeId = data.placeId || data.PlaceId || data.rootPlaceId;

  return res.status(200).json({ ok: true, placeId, universeId, csrfToken, raw: data });
};
