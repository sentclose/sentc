// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");

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
				test: /\.wasm$/,
				type: "asset/resource"
			}
		]
	},
	resolve: {
		extensions: [".tsx", ".ts", ".js"]
	},
	output: {
		filename: "main.js",
		path: path.resolve(__dirname, "tests/web_test/web/dist")
	}
};