const path = require('path');
const webpack = require('webpack');

module.exports = {
  context: path.resolve(__dirname, './minigrid/static/js'),
  entry: {
    app: './minigrid_write_credit.js',
  },
  output: {
    path: path.resolve(__dirname, './minigrid/static/js'),
    filename: '[name].bundle.js',
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['env']
          }
        }
      }
    ]
  },
};