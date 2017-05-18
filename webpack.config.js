const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: {
    write_credit: path.resolve(__dirname, 'minigrid/static/src/js/minigrid_write_credit.js'),
    read_card: path.resolve(__dirname, 'minigrid/static/src/js/read_card.js'),
    tariffs: path.resolve(__dirname, 'minigrid/static/src/js/tariffs.js')
  },
  output: {
    path: path.resolve(__dirname, 'minigrid/static/dist/'),
    filename: '[name].bundle.js',
  },
  module: {
    loaders: [
      {
        test: /\.css$/,
        loader: "style-loader!css-loader"
      },
      { test: /\.js$/,
        exclude: /node_modules/,
        loader: 'babel-loader'
      }
    ]
  },
  resolve: {
    modules: ['node_modules', 'src'],
      alias: {
        'flatpickr.css': path.join(__dirname, 'node_modules/flatpickr/dist/flatpickr.css')
      }
  }
}
