/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/07/16
 */
import {InitReturn, StorageInterface} from ".";
import {IDBPDatabase, openDB} from "idb";

export class IndexeddbStorage implements StorageInterface
{
	private db: IDBPDatabase;

	public isInit = false;

	constructor(
		private dbName: string = "sentc_encrypt_files",
		private storeName: string = "decrypted_files"
	) {}

	public async init(): Promise<InitReturn>
	{
		if (!("indexedDB" in window)) {
			return {
				status: false,
				err: "Indexeddb is not supported"
			};
		}

		const name = this.storeName;

		try {
			this.db = await openDB(this.dbName, 1, {
				upgrade(db) {
					db.createObjectStore(name, {autoIncrement: true});
				}
			});
		} catch (e) {
			return {
				status: false,
				err: "Indexeddb is not supported"
			};
		}

		this.isInit = true;

		return {status: true};
	}

	public async getDownloadUrl(): Promise<string>
	{
		const blobs = [];

		let cursor = await this.db.transaction(this.storeName).store.openCursor();

		while (cursor) {
			blobs.push(cursor.value.blob);
			// eslint-disable-next-line no-await-in-loop
			cursor = await cursor.continue();
		}

		return URL.createObjectURL(new Blob(blobs));
	}

	public cleanStorage(): Promise<void>
	{
		return this.db.clear(this.storeName);
	}

	public async storePart(chunk: ArrayBuffer): Promise<void>
	{
		try {
			await this.db.put(this.storeName, {blob: new Blob([chunk])});
		} catch (e) {
			console.error("Can't save the part");
			throw e;
		}
	}

	public delete(key: string): Promise<void>
	{
		return this.db.delete(this.storeName, key);
	}

	public getItem(key: string)
	{
		return this.db.get(this.storeName, key);
	}

	public set(key: string, item: any)
	{
		return this.db.put(this.storeName, item, key);
	}
}