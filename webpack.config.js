const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: {
    app: path.resolve(__dirname, 'minigrid/static/src/js/minigrid_write_credit.js'),
  },
  output: {
    path: path.resolve(__dirname, 'minigrid/static/bundles/'),
    filename: 'app.bundle.js',
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
  },
  plugins: [
        new webpack.optimize.UglifyJsPlugin({
            compress: {
                warnings: false,
            },
            output: {
                comments: false,
            },
        }),
    ]
};