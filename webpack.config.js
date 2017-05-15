const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: {
    write_credit: path.resolve(__dirname, 'minigrid/static/src/js/minigrid_write_credit.js'),
    read_card: path.resolve(__dirname, 'minigrid/static/src/js/read_card.js'),
  },
  output: {
    path: path.resolve(__dirname, 'minigrid/static/dist/'),
    filename: '[name].bundle.js',
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
        }
      }
    ]
  }
}