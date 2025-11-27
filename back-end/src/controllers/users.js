import prisma from '../database/client.js'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

const controller = {}     // Objeto vazio

controller.create = async function(req, res) {
  try {

    // Somente usuários administradores podem acessar este recurso
    // HTTP 403: Forbidden(
    if(! req?.authUser?.is_admin) return res.status(403).end()

    // Verifica se existe o campo "password" em "req.body".
    // Caso positivo, geramos o hash da senha antes de enviá-la
    // ao BD
    // (12 na chamada a bcrypt.hash() corresponde ao número de
    // passos de criptografia utilizados no processo)
    if(req.body.password) {
      req.body.password = await bcrypt.hash(req.body.password, 12)
    }

    await prisma.user.create({ data: req.body })

    // HTTP 201: Created
    res.status(201).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}




controller.retrieveAll = async function(req, res) {
  try {

    /*
      aqui é a vulnerabilidade API6:2023 Acesso irrestrito a fluxos de negócios sensíveis

      a vulnerabilidade foi evitada ao implementar os métodos de controle de acesso
      para que somente usuários administradores possam acessar a lista de usuários do sistema
    */

    // Somente usuários administradores podem acessar este recurso
    // HTTP 403: Forbidden(
    if(! req?.authUser?.is_admin) return res.status(403).end()
      
      /*
        aqui é a vulnerabilidade API3:2023 - Falha de autenticação a nível de propriedade

        a senha é omitida da resposta, evitando exposição de hashes de senha
      */

    const result = await prisma.user.findMany(
      // Omite o campo "password" do resultado
      // por questão de segurança
      { omit: { password: true } } 
    )

    // HTTP 200: OK (implícito)
    res.send(result)
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}



controller.retrieveOne = async function(req, res) {
  try {

    /*
      Aqui foi a API1:2023 - Falha de autenticação a nível de objeto

      sem a verificalção, qualquer usuário autenticado poderia acessar os dados de qualquer outro usuário alterando o ID na URL
    */

    // Somente usuários administradores ou o próprio usuário
    // autenticado podem acessar este recurso
    // HTTP 403: Forbidden
    if(! (req?.authUser?.is_admin || 
      Number(req?.authUser?.id) === Number(req.params.id))) 
      return res.status(403).end()
      
    const result = await prisma.user.findUnique({
      // Omite o campo "password" do resultado
      // por questão de segurança
      omit: { password: true },
      where: { id: Number(req.params.id) }
    })

    // Encontrou ~> retorna HTTP 200: OK (implícito)
    if(result) res.send(result)
    // Não encontrou ~> retorna HTTP 404: Not Found
    else res.status(404).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}


controller.update = async function(req, res) {
  try {

    // Somente usuários adminsitradores podem acessar este recurso
    // HTTP 403: Forbidden(
    if(! req?.authUser?.is_admin) return res.status(403).end()

    // Verifica se existe o campo "password" em "req.body".
    // Caso positivo, geramos o hash da senha antes de enviá-la
    // ao BD
    // (12 na chamada a bcrypt.hash() corresponde ao número de
    // passos de criptografia utilizados no processo)
    if(req.body.password) {
      req.body.password = await bcrypt.hash(req.body.password, 12)
    }

    const result = await prisma.user.update({
      where: { id: Number(req.params.id) },
      data: req.body
    })

    // Encontrou e atualizou ~> HTTP 204: No Content
    if(result) res.status(204).end()
    // Não encontrou (e não atualizou) ~> HTTP 404: Not Found
    else res.status(404).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}


controller.delete = async function(req, res) {
  try {
    // Somente usuários administradores podem acessar este recurso
    // HTTP 403: Forbidden(
    if(! req?.authUser?.is_admin) return res.status(403).end()
      
    await prisma.user.delete({
      where: { id: Number(req.params.id) }
    })

    // Encontrou e excluiu ~> HTTP 204: No Content
    res.status(204).end()
  }
  catch(error) {
    if(error?.code === 'P2025') {
      // Não encontrou e não excluiu ~> HTTP 404: Not Found
      res.status(404).end()
    }
    else {
      // Outros tipos de erro
      console.error(error)

      // HTTP 500: Internal Server Error
      res.status(500).end()
    }
  }
}


controller.login = async function(req, res) {
  try {

      // Busca o usuário no BD usando o valor dos campos
      // "username" OU "email"
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            { username: req.body?.username },
            { email: req.body?.email }
          ]
        }
      })

      // Se o usuário não for encontrado, retorna
      // HTTP 401: Unauthorized
      if(! user) return res.status(401).end()

      // REMOVENDO VULNERABILIDADE DE AUTENTICAÇÃO FIXA
      // if(req.body?.username === 'admin' && req.body?.password === 'admin123') passwordIsValid = true
      // else passwordIsValid = user.password === req.body?.password
      // passwordIsValid = user.password === req.body?.password
      
      // Chamando bcrypt.compare() para verificar se o hash da senha
      // enviada coincide com o hash da senha armazenada no BD

      /* prova 2:
      Vulnerabilidade: API2:223 - Falha de autenticação
       aqui foi removida a autenticação fixa e implementada uma validação segura com bcryp, que seria referente a API2, de falha de autenticação.
       é seguro agora pois há a comparação do hash da senha com bcrypt.compare(), garantindo que a senha enviada é a mesma no banco.
      */
      const passwordIsValid = await bcrypt.compare(req.body?.password, user.password)

      // Se a senha estiver errada, retorna
      // HTTP 401: Unauthorized
      if(! passwordIsValid) return res.status(401).end()

      // Por motivos de segurança, exclui o campo "password" dos dados do usuário
      // para que ele não seja incluído no token
      if(user.password) delete user.password

      // Usuário e senha OK, passamos ao procedimento de gerar o token
      const token = jwt.sign(
        user,                       // Dados do usuário
        process.env.TOKEN_SECRET,   // Senha para criptografar o token
        { expiresIn: '24h' }        // Prazo de validade do token
      )

      // Formamos o cookie para enviar ao front-end
      res.cookie(process.env.AUTH_COOKIE_NAME, token, {
        httpOnly: true, // O cookie ficará inacessível para o JS no front-end
        secure: true,   // O cookie será criptografado em conexões https
        sameSite: 'None',
        path: '/',
        maxAge: 24 * 60 * 60 * 100  // 24h
      })

      // Cookie não HTTP-only, acessível pelo JS no front-end
      res.cookie('not-http-only', 'Este-cookie-NAO-eh-http-only', {
        httpOnly: false,
        secure: true,
        sameSite: 'None',
        path: '/',
        maxAge: 24 * 60 * 60 * 100  // 24h
      })

      // Retorna o token e o usuário autenticado com
      // HTTP 200: OK (implícito)
      res.send({user})

  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}


controller.me = function(req, res) {
  // Retorna as informações do usuário autenticado
  // HTTP 200: OK (implícito)
  res.send(req?.authUser)
}

controller.logout = function(req, res) {
  // Apaga no front-end o cookie que armazena o token
  res.clearCookie(process.env.AUTH_COOKIE_NAME)
  // HTTP 204: No Content
  res.status(204).end()
}


export default controller