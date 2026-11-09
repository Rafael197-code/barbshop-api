const jwt = require("jsonwebtoken")

function auth(req, res, next) {
    const authHeader = req.headers.authorization

    if (!authHeader) {
        return res.status(401).json({ mensagem: "Token não informado" })
    }

    const token = authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ mensagem: "Token não informado" })
    }

    try {
        req.usuario = jwt.verify(token, process.env.JWT_SECRET)
        next()
    } catch (error) {
        return res.status(401).json({ mensagem: "Token inválido" })
    }
}

module.exports = auth
