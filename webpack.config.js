const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: {
    write_card: './minigrid/static/src/js/minigrid_write_card.js',
    read_card: './minigrid/static/src/js/read_card.js',
    tariffs: './minigrid/static/src/js/tariffs.js'
  },
  output: {
    path: path.resolve(__dirname, 'minigrid/static/dist/'),
    filename: '[name].bundle.js',
  },
  module: {
    rules: [
      {
        test: /\.css$/,
        use: [
          "style-loader",
          "css-loader"
        ]
      },
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', { targets: "defaults" }]
            ]
          }
        }
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
