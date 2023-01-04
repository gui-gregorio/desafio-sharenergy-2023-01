require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const app = express()


app.get('/', (req, res) => {
    res.status(200).json({msg: "Hello World"})

})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({msg: "Acesso negado!" })
    }
    
    try{
        const secret = process.env.SECRET
        jwt.verify(token, secret)

        next()

    } catch(error){
        res.status(400).json({msg:"Token Inválido"})

    }
}

app.use(express.json())

const User = require('./models/User')

//rotas privadas
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id

    //checka no banco se o usuário existe
    const user = await User.findById(id, '-password')
    if(!user){
        return res.status(404).json({msg: "Usuário não encontrado"})
    }
    res.status(200).json({ user })

})


//Registrar usuário
app.post('/auth/register', async(req, res) => {

    const {usuario, password, confirmpassword} = req.body

    if(!usuario){
        return res.status(422).json({msg: "O usuário é obrigatório!"})
    }

    if(!password){
        return res.status(422).json({msg: "A senha é obrigatória"})
    }

    if(!confirmpassword){
        return res.status(422).json({msg: "Por favor confirme a senha"})
    }

    if(password != confirmpassword){
        return res.status(422).json({msg: "A senha é diferente da confirmação de senha"})
    }

    const userExists = await User.findOne({ usuario: usuario })

    if (userExists){
        return res.status(422).json({msg: "Usuário já existe"})
    }

    

    //encriptar a senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //criação de usuário no bd
    const user = new User({
        usuario,
        password: passwordHash
    })

    try{

        await user.save()
        res.status(201).json({msg: 'Usuário criado com sucesso'})

        
    } catch(error){
        console.log(error)
        res.status(500).json({msg: "Aconteceu um erro inesperado, por favor tente novamente"})
    }


})

//Autenticação
app.post("/auth/login", async (req, res) => {
    const { usuario, password } = req.body
    //validação
    if(!usuario){
        return res.status(422).json({msg: "O usuário é obrigatório!"})
    }

    if(!password){
        return res.status(422).json({msg: "A senha é obrigatória"})
    }

    const user = await User.findOne({ usuario: usuario })

    if (!user){
        return res.status(422).json({msg: "Usuário não encontrado"})
    }

    //checagem de senha
    const checkPassword = await bcrypt.compare(password, user.password)
    if (!checkPassword){
        return res.status(422).json({msg: "Senha inválida"})
    }

    try{
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id,
        },
        secret,
        )

        res.status(200).json({msg: "Autenticado com sucesso", token})

    } catch(err){
        console.log(err)
        res.status(500).json({
            msg: "Aconteceu um erro inesperado no servidor, tente novamente"
        })

    }

})

mongoose.connect(`mongodb://localhost:27017/`).then(() =>{
    app.listen(3000)
    console.log("Conectou ao BD")
}).catch(err => console.log(err))



