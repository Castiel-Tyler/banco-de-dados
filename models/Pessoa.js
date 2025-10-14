const mongoose = require('mongoose');
const pessoaSchema = new mongoose.Schema(
    {
        nome: {type: String, required: true},
        idade: {type: Number, required: true}
    },
    {timestamps: true}
)

module.exports = mongoose.model('Pessoa', pessoaSchema)