/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2021/07/12
 */
import {StorageInterface, IndexeddbStorage, MemoryStorage} from ".";

export type ResCallBack = (msg: {err?: string, warn?: string}) => void;

export class StorageFactory
{
	public static async getStorage(res: ResCallBack, ...args): Promise<StorageInterface>
	{
		//go with indexeddb first
		let storage: StorageInterface;

		storage = new IndexeddbStorage(...args);

		const storageReturn = await storage.init();

		if (storageReturn.status === true) {
			return storage;
		}

		storage = new MemoryStorage();

		const storageReturn1 = await storage.init();
		res({warn: storageReturn1.warn, err: storageReturn.err});

		return storage;
	}
}