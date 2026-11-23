const { checkAuth } = require("./_util");

module.exports = async (req, res) => {
  const required = Boolean(process.env.APP_PASSWORD);
  const authed = checkAuth(req);
  return res.status(200).json({ required, authed });
};
