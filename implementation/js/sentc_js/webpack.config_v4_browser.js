/*
Webpack config for webpack v4 with only browser (no ssr):

- use babel with babel-plugin-bundled-import-meta to change the import.meta.url
- now the same as v4 in node solution

Dependencies:
"babel-loader": "^8.2.5",
"@babel/preset-env": "^7.18.10",
"@babel/core": "^7.18.10",

"babel-plugin-bundled-import-meta": "^0.3.2",

"copy-webpack-plugin": "^6.4.1",
"webpack": "^4.46.0",
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");

const wasmOutDir = path.resolve(__dirname, "../sentc_wasm/pkg");

// eslint-disable-next-line @typescript-eslint/no-var-requires
const copyWebpackPlugin = require("copy-webpack-plugin");

module.exports = {
	entry: ["./src/index.ts", "./tests/web_test/web/index.ts"],
	devtool: "inline-source-map",
	mode: "production",
	module: {
		rules: [
			{
				test: /\.tsx?$/,
				use: [{
					loader: "ts-loader",
					options: {
						configFile: path.resolve(__dirname, "tsconfig.spec.json")
					}
				}],
				exclude: /node_modules/
			},
			{
				test: /\.m?js$/,
				use: {
					loader: "babel-loader",
					options: {
						presets: ["@babel/preset-env"],
						plugins: [
							[
								"babel-plugin-bundled-import-meta",
								{
									"bundleDir": wasmOutDir,
									"importStyle": "cjs"
								}
							]
						]
					}
				}
			}
		]
	},
	plugins: [
		new copyWebpackPlugin({
			patterns: [
				{from: wasmOutDir + "/sentc_wasm_bg.wasm"}
			]
		})
	],
	resolve: {
		mainFields: ["browser", "main"],	//use common js
		extensions: [".tsx", ".ts", ".js", ".wasm"]
	},
	output: {
		filename: "main.js",
		path: path.resolve(__dirname, "tests/web_test/web/dist")
	}
};