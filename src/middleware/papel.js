function papel(tipoPermitido) {
    return (req, res, next) => {
        if (!req.usuario || req.usuario.tipo !== tipoPermitido) {
            return res.status(403).json({ mensagem: "Você não tem permissão para isso" })
        }

        next()
    }
}

module.exports = papel
