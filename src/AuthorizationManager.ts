export class AuthorizationManager {
    private user: any;

    constructor(user: any) {
        this.user = user;
    }

    /**
     * Determine if the user can perform the given ability.
     */
    public async can(ability: string, ...args: any[]): Promise<boolean> {
        const { Gate } = require('./Gate');
        return await Gate.forUser(this.user).allows(ability, ...args);
    }

    /**
     * Determine if the user cannot perform the given ability.
     */
    public async cannot(ability: string, ...args: any[]): Promise<boolean> {
        return !(await this.can(ability, ...args));
    }

    /**
     * Authorize or throw exception.
     */
    public async authorize(ability: string, ...args: any[]): Promise<void> {
        const { Gate } = require('./Gate');
        await Gate.forUser(this.user).authorize(ability, ...args);
    }
}
