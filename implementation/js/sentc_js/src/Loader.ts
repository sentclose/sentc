/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/21
 */

class Loader
{
	// eslint-disable-next-line @typescript-eslint/naming-convention
	private _wasm;

	async load()
	{
		if (this._wasm) {
			return;
		}

		this._wasm = await import("sentc_wasm");
	}

	get wasm() {
		return this._wasm;
	}
}

export default new Loader();