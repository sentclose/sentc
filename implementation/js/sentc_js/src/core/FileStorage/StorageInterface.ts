/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/07/16
 */

export type InitReturn = {
	status: boolean, 	//if this store is supported
	err?: string	//if not supported -> explain why (eg Indexeddb not supported)
	warn?: string	//this store can be use but with drawbacks (eg MemoryStore not for large files or localStore not for files in general)
}

export interface StorageInterface
{
	init(): Promise<InitReturn>;

	getDownloadUrl(): Promise<string>;

	cleanStorage(): Promise<void>;

	storePart(chunk: ArrayBuffer): Promise<void>;

	delete(key: string): Promise<void>;

	getItem(key: string): Promise<any | undefined>;

	set(key: string, item: any): Promise<void | any>;
}