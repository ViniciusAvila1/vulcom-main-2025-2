import { z } from 'zod'

// Lista de cores válidas para os carros
const coresPermitidas = [
  'AMARELO', 'AZUL', 'BRANCO', 'CINZA', 'DOURADO', 'LARANJA',
  'MARROM', 'PRATA', 'PRETO', 'ROSA', 'ROXO', 'VERDE', 'VERMELHO'
]

// Data de abertura da loja (limite inferior para data de venda)
const storeOpeningDate = new Date('2020-03-20')

const Car = z.object({
  brand: z.string()
    .trim()
    .min(1, { message: 'A marca deve ter, no mínimo, 1 caractere.' })
    .max(25, { message: 'A marca deve ter, no máximo, 25 caracteres.' }),

  model: z.string()
    .trim()
    .min(1, { message: 'O modelo deve ter, no mínimo, 1 caractere.' })
    .max(25, { message: 'O modelo deve ter, no máximo, 25 caracteres.' }),

  color: z.enum(coresPermitidas, {
    message: 'Cor inválida. Escolha uma das cores disponíveis.'
  }),

  year_manufacture: z.number({
    required_error: 'O ano de fabricação é obrigatório.',
    invalid_type_error: 'O ano de fabricação deve ser um número.'
  })
    .int({ message: 'O ano de fabricação deve ser um número inteiro.' })
    .min(1960, { message: 'O ano de fabricação deve ser no mínimo 1960.' })
    .max(new Date().getFullYear(), { message: `O ano de fabricação deve ser no máximo ${new Date().getFullYear()}.` }),

  imported: z.boolean({
    required_error: 'O campo importado é obrigatório.',
    invalid_type_error: 'O campo importado deve ser verdadeiro ou falso.'
  }),

  plates: z.string()
    .trim()
    .transform(val => val.replace(/\s/g, ''))
    .refine(val => val.length === 8, {
      message: 'A placa deve ter exatamente 8 caracteres.'
    }),

  selling_date: z.coerce.date()
    .min(storeOpeningDate, {
      message: 'A data de venda não pode ser anterior a 20/03/2020.'
    })
    .max(new Date(), {
      message: 'A data de venda não pode ser posterior à data de hoje.'
    })
    .nullish(),

  selling_price: z.number({
    invalid_type_error: 'O preço de venda deve ser um número.'
  })
    .min(5000, { message: 'O preço de venda deve ser no mínimo R$ 5.000,00.' })
    .max(5000000, { message: 'O preço de venda deve ser no máximo R$ 5.000.000,00.' })
    .nullish()
})

export default Car