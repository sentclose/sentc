/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/17
 */

export abstract class AbstractCrypto
{
	protected constructor(protected base_url: string, protected app_token: string) {}
}