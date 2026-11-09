if (process.env.NODE_ENV === "production") {
    require("dotenv").config({ path: ".env.production" })
} else {
    require("dotenv").config({ path: ".env" })
}

const crypto = require("crypto")
const express = require("express")
const cors = require("cors")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")

const db = require("./config/database")
const auth = require("./middleware/auth")
const papel = require("./middleware/papel")

if (!process.env.JWT_SECRET) {
    console.error("Defina JWT_SECRET no arquivo .env")
    process.exit(1)
}

if (!process.env.CODIGO_BARBEIRO) {
    console.warn("CODIGO_BARBEIRO não definido: os barbeiros não conseguirão entrar.")
}

const app = express()
const PORT = process.env.PORT || 3001

app.use(express.json())
app.use(cors())

function pad(n) {
    return String(n).padStart(2, "0")
}

function toISO(d) {
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

const HORARIOS = Array.from({ length: 20 }, (_, i) => {
    const minutos = 9 * 60 + i * 30
    return `${pad(Math.floor(minutos / 60))}:${pad(minutos % 60)}`
})

function dataValida(texto) {
    if (typeof texto !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(texto)) return false
    const d = new Date(`${texto}T12:00:00`)
    return !Number.isNaN(d.getTime()) && toISO(d) === texto
}

function limparNome(nome) {
    return String(nome || "").trim().replace(/\s+/g, " ")
}

function senhaDaBarbeariaCorreta(informada) {
    const esperada = process.env.CODIGO_BARBEIRO

    if (!esperada || typeof informada !== "string") return false

    const a = Buffer.from(informada)
    const b = Buffer.from(esperada)

    return a.length === b.length && crypto.timingSafeEqual(a, b)
}

function criarToken(payload) {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" })
}

function formatarAgendamento(linha) {
    return {
        id: linha.id,
        data: String(linha.data).slice(0, 10),
        horario: String(linha.horario).slice(0, 5),
        cliente: linha.cliente,
        barbeiro: linha.barbeiro
    }
}

function lerDadosBarbeiro(body) {
    const nome = limparNome(body.nome)
    const dataNascimento = body.data_nascimento

    if (nome.split(" ").length < 2) {
        return { erro: "Informe o nome completo" }
    }

    if (!dataValida(dataNascimento) || dataNascimento > toISO(new Date()) || dataNascimento < "1920-01-01") {
        return { erro: "Informe uma data de nascimento válida" }
    }

    return { nome, dataNascimento }
}

app.get("/", (req, res) => {
    res.json({ mensagem: "API funcionando" })
})

app.post("/register", async (req, res) => {
    try {
        const { nome, email, senha } = req.body

        if (!nome || !email || !senha) {
            return res.status(400).json({ mensagem: "Preencha todos os campos" })
        }

        if (String(senha).length < 6) {
            return res.status(400).json({ mensagem: "A senha precisa ter pelo menos 6 caracteres" })
        }

        const emailLimpo = String(email).trim().toLowerCase()

        const [existente] = await db.query(
            "SELECT id FROM usuario WHERE email = ?",
            [emailLimpo]
        )

        if (existente.length > 0) {
            return res.status(400).json({ mensagem: "E-mail já cadastrado" })
        }

        const senhaHash = await bcrypt.hash(String(senha), 10)

        await db.query(
            "INSERT INTO usuario (nome, email, senha) VALUES (?, ?, ?)",
            [limparNome(nome), emailLimpo, senhaHash]
        )

        res.status(201).json({ mensagem: "Usuário cadastrado com sucesso" })
    } catch (error) {
        console.log(error)
        res.status(500).json({ mensagem: "Erro interno" })
    }
})

app.post("/login", async (req, res) => {
    try {
        const { email, senha } = req.body

        if (!email || !senha) {
            return res.status(400).json({ mensagem: "Informe e-mail e senha" })
        }

        const [usuarios] = await db.query(
            "SELECT * FROM usuario WHERE email = ?",
            [String(email).trim().toLowerCase()]
        )

        if (usuarios.length === 0) {
            return res.status(401).json({ mensagem: "E-mail ou senha inválidos" })
        }

        const usuario = usuarios[0]

        const senhaValida = await bcrypt.compare(String(senha), usuario.senha)

        if (!senhaValida) {
            return res.status(401).json({ mensagem: "E-mail ou senha inválidos" })
        }

        const token = criarToken({
            id: usuario.id,
            nome: usuario.nome,
            email: usuario.email,
            tipo: "cliente"
        })

        res.json({ mensagem: "Login realizado", token })
    } catch (error) {
        console.log(error)
        res.status(500).json({ mensagem: "Erro no login" })
    }
})

app.post("/barbeiros/login", async (req, res) => {
    try {
        if (!process.env.CODIGO_BARBEIRO) {
            return res.status(500).json({ mensagem: "A senha da barbearia não está configurada no servidor" })
        }

        if (!senhaDaBarbeariaCorreta(req.body.senha)) {
            return res.status(401).json({ mensagem: "Senha da barbearia incorreta" })
        }

        const dados = lerDadosBarbeiro(req.body)

        if (dados.erro) {
            return res.status(400).json({ mensagem: dados.erro })
        }

        const [barbeiros] = await db.query(
            "SELECT id, nome FROM barbeiro WHERE nome = ? AND data_nascimento = ?",
            [dados.nome, dados.dataNascimento]
        )

        if (barbeiros.length === 0) {
            return res.status(401).json({
                mensagem: "Não encontramos um barbeiro com esse nome e data de nascimento. Confira os dados ou faça o cadastro."
            })
        }

        const barbeiro = barbeiros[0]

        const token = criarToken({
            id: barbeiro.id,
            nome: barbeiro.nome,
            tipo: "barbeiro"
        })

        res.json({ mensagem: "Login realizado", token })
    } catch (error) {
        console.log(error)
        res.status(500).json({ mensagem: "Erro no login" })
    }
})

app.post("/barbeiros/register", async (req, res) => {
    try {
        if (!process.env.CODIGO_BARBEIRO) {
            return res.status(500).json({ mensagem: "A senha da barbearia não está configurada no servidor" })
        }

        if (!senhaDaBarbeariaCorreta(req.body.senha)) {
            return res.status(401).json({ mensagem: "Senha da barbearia incorreta" })
        }

        const dados = lerDadosBarbeiro(req.body)

        if (dados.erro) {
            return res.status(400).json({ mensagem: dados.erro })
        }

        await db.query(
            "INSERT INTO barbeiro (nome, data_nascimento) VALUES (?, ?)",
            [dados.nome, dados.dataNascimento]
        )

        res.status(201).json({ mensagem: "Barbeiro cadastrado com sucesso" })
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(400).json({
                mensagem: "Esse barbeiro já está cadastrado. Use a opção de entrar."
            })
        }

        console.log(error)
        res.status(500).json({ mensagem: "Erro ao cadastrar o barbeiro" })
    }
})

app.get("/barbeiros", auth, async (req, res) => {
    try {
        const [barbeiros] = await db.query(
            "SELECT id, nome FROM barbeiro ORDER BY nome"
        )

        res.json(barbeiros)
    } catch (error) {
        console.log(error)
        res.status(500).json({ mensagem: "Erro ao buscar barbeiros" })
    }
})

app.get("/agendamentos", auth, async (req, res) => {
    try {
        const coluna = req.usuario.tipo === "barbeiro" ? "a.barbeiro_id" : "a.usuario_id"

        const [linhas] = await db.query(
            `
            SELECT a.id, a.data, a.horario, u.nome AS cliente, b.nome AS barbeiro
            FROM agendamento a
            JOIN usuario u ON u.id = a.usuario_id
            JOIN barbeiro b ON b.id = a.barbeiro_id
            WHERE ${coluna} = ?
              AND a.data >= CURDATE() - INTERVAL 1 DAY
            ORDER BY a.data, a.horario
            `,
            [req.usuario.id]
        )

        res.json(linhas.map(formatarAgendamento))
    } catch (error) {
        console.log(error)
        res.status(500).json({ mensagem: "Erro ao buscar agendamentos" })
    }
})

app.get("/agendamentos/ocupados", auth, async (req, res) => {
    try {
        const barbeiroId = Number(req.query.barbeiro_id)
        const { data } = req.query

        if (!Number.isInteger(barbeiroId)) {
            return res.status(400).json({ mensagem: "Informe o barbeiro" })
        }

        if (!dataValida(data)) {
            return res.status(400).json({ mensagem: "Informe a data no formato AAAA-MM-DD" })
        }

        const [linhas] = await db.query(
            "SELECT horario FROM agendamento WHERE barbeiro_id = ? AND data = ?",
            [barbeiroId, data]
        )

        res.json(linhas.map((l) => String(l.horario).slice(0, 5)))
    } catch (error) {
        console.log(error)
        res.status(500).json({ mensagem: "Erro ao buscar horários" })
    }
})

app.post("/agendamentos", auth, papel("cliente"), async (req, res) => {
    try {
        const { data, horario } = req.body
        const barbeiroId = Number(req.body.barbeiro_id)

        if (!Number.isInteger(barbeiroId)) {
            return res.status(400).json({ mensagem: "Escolha um barbeiro" })
        }

        if (!dataValida(data)) {
            return res.status(400).json({ mensagem: "Informe uma data válida" })
        }

        if (!HORARIOS.includes(horario)) {
            return res.status(400).json({ mensagem: "Horário fora do atendimento" })
        }

        const agora = new Date()

        if (data < toISO(agora)) {
            return res.status(400).json({ mensagem: "Escolha uma data a partir de hoje" })
        }

        if (data === toISO(agora) && horario <= `${pad(agora.getHours())}:${pad(agora.getMinutes())}`) {
            return res.status(400).json({ mensagem: "Esse horário já passou" })
        }

        const [barbeiros] = await db.query(
            "SELECT id, nome FROM barbeiro WHERE id = ?",
            [barbeiroId]
        )

        if (barbeiros.length === 0) {
            return res.status(400).json({ mensagem: "Barbeiro não encontrado" })
        }

        const [resultado] = await db.query(
            "INSERT INTO agendamento (usuario_id, barbeiro_id, data, horario) VALUES (?, ?, ?, ?)",
            [req.usuario.id, barbeiroId, data, horario]
        )

        res.status(201).json({
            mensagem: "Horário agendado com sucesso",
            agendamento: {
                id: resultado.insertId,
                data,
                horario,
                cliente: req.usuario.nome,
                barbeiro: barbeiros[0].nome
            }
        })
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({
                mensagem: "Esse horário acabou de ser ocupado. Escolha outro."
            })
        }

        console.log(error)
        res.status(500).json({ mensagem: "Erro ao agendar" })
    }
})

app.delete("/agendamentos/:id", auth, async (req, res) => {
    try {
        const id = Number(req.params.id)

        if (!Number.isInteger(id)) {
            return res.status(400).json({ mensagem: "Agendamento inválido" })
        }

        const [linhas] = await db.query(
            "SELECT id, usuario_id, barbeiro_id FROM agendamento WHERE id = ?",
            [id]
        )

        if (linhas.length === 0) {
            return res.status(404).json({ mensagem: "Agendamento não encontrado" })
        }

        const dono = req.usuario.tipo === "barbeiro"
            ? linhas[0].barbeiro_id === req.usuario.id
            : linhas[0].usuario_id === req.usuario.id

        if (!dono) {
            return res.status(403).json({ mensagem: "Você não pode alterar o horário de outra pessoa" })
        }

        await db.query("DELETE FROM agendamento WHERE id = ?", [id])

        res.json({ mensagem: "Horário cancelado com sucesso" })
    } catch (error) {
        console.log(error)
        res.status(500).json({ mensagem: "Erro ao cancelar o horário" })
    }
})

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`)
})
