/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/20
 */
import {Module, VuexModule, Mutation, Action} from "vuex-module-decorators";
import {Sentc} from "@sentclose/sentc/lib";

@Module({
	stateFactory: true
})
export default class User extends VuexModule
{
	//@ts-ignore
	private sentc: Sentc = "";

	get getSentc() {
		return this.sentc;
	}

	@Mutation
	public setSentc(sentc: Sentc)
	{
		this.sentc = sentc;
	}

	@Action({rawError: true})
	public async initUser()
	{
		const sentc = await Sentc.init({
			// @ts-ignore -> env must be set
			app_token: process.env.NUXT_ENV_APP_PUBLIC_TOKEN,
			base_url: process.env.NUXT_ENV_APP_SECRET_TOKEN
		});

		this.context.commit("setSentc", sentc);
	}
}