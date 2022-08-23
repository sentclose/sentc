// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require("path");

module.exports = {
	entry: ["./src/index.ts"],
	devtool: "inline-source-map",
	mode: "production",
	module: {
		rules: [
			{
				test: /\.tsx?$/,
				use: [{
					loader: "ts-loader",
					options: {
						configFile: path.resolve(__dirname, "../tsconfig.spec.json")
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
		//mainFields: ["browser", "main"],	//activate this to build the web test with cjs
		extensions: [".tsx", ".ts", ".js"]
	},
	output: {
		filename: "sentc.min.js",
		library: "Sentc",
		libraryTarget: "umd",
		clean: true,
		path: path.resolve(__dirname, "../tests/web_test/web_cdn/dist")
	}
};