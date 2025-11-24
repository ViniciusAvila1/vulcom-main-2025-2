import { z } from 'zod'


// Data de abertura da loja: 20/03/2020
const minSellingDate = new Date('2020-03-20')


// Data máxima: hoje
const maxSellingDate = new Date()


// Ano atual
const currentYear = new Date().getFullYear()


// Cores permitidas
const cores = [
  'AMARELO', 'AZUL', 'BRANCO', 'CINZA', 'DOURADO', 'LARANJA',
  'MARROM', 'PRATA', 'PRETO', 'ROSA', 'ROXO', 'VERDE', 'VERMELHO'
]


const Car = z.object({
  brand: z.string()
    .trim()
    .min(1, { message: 'A marca deve ter, no mínimo, 1 caractere.' })
    .max(25, { message: 'A marca deve ter, no máximo, 25 caracteres.' }),


  model: z.string()
    .trim()
    .min(1, { message: 'O modelo deve ter, no mínimo, 1 caractere.' })
    .max(25, { message: 'O modelo deve ter, no máximo, 25 caracteres.' }),


  color: z.enum(cores, {
    message: 'Cor inválida.'
  }),


  year_manufacture: z.coerce.number()
    .int({ message: 'O ano de fabricação deve ser um número inteiro.' })
    .min(1960, { message: 'O ano de fabricação deve ser, no mínimo, 1960.' })
    .max(currentYear, { message: `O ano de fabricação não pode ser posterior a ${currentYear}.` }),


  imported: z.boolean({
    message: 'O campo "importado" deve ser verdadeiro ou falso.'
  }),


  plates: z.string()
    // Remove eventuais espaços (da máscara do campo usada no
    // front-end), caso a placa não tenha sido completamente preenchida
    .transform(val => val.replace(/\s/g, ''))
    .refine(val => val.length === 8, {
      message: 'A placa deve ter exatamente 8 caracteres.'
    }),


  selling_date: z.coerce.date()
    .min(minSellingDate, {
      message: 'A data de venda não pode ser anterior a 20/03/2020.'
    })
    .max(maxSellingDate, {
      message: 'A data de venda não pode ser posterior à data de hoje.'
    })
    .nullish(),    // O campo é opcional


  selling_price: z.coerce.number()
    .min(5000, { message: 'O preço de venda deve ser, no mínimo, R$ 5.000,00.' })
    .max(5000000, { message: 'O preço de venda deve ser, no máximo, R$ 5.000.000,00.' })
    .nullish(),    // O campo é opcional


  customer_id: z.coerce.number()
    .int()
    .positive()
    .nullish()     // O campo é opcional
})


export default Car
