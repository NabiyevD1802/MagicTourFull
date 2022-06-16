const app = require('./app');
const dotenv = require('dotenv');
const mongoose = require('mongoose');

dotenv.config({ path: './config.env' });

const DB = process.env.DATABASE;

mongoose.connect(DB, {}).then(() => {
  console.log('DB connected');
});

const tourSchema = mongoose.Schema({
  name: {
    type: String,
    required: [true],
  },
  price: Number,
  rating: Number,
});

const Tour = mongoose.model('Tour', tourSchema);

console.log('PORT:' + process.env.PORT);
const port = 8000;
app.listen(port, () => {
  console.log(`Server running on ${port} port...`);
});
