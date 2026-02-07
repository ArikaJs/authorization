import { PolicyResolver } from './PolicyResolver';
import { AuthorizationException } from './Exceptions/AuthorizationException';

type GateCallback = (user: any, ...args: any[]) => boolean | Promise<boolean>;

export class Gate {
    private static abilities: Map<string, GateCallback> = new Map();
    private static policyResolver: PolicyResolver = new PolicyResolver();
    private static currentUser: any = null;

    /**
     * Define a new ability.
     */
    public static define(ability: string, callback: GateCallback): void {
        this.abilities.set(ability, callback);
    }

    /**
     * Register a policy for a model.
     */
    public static policy(model: any, policy: any): void {
        this.policyResolver.register(model, policy);
    }

    /**
     * Set the current user for authorization checks.
     */
    public static forUser(user: any): typeof Gate {
        this.currentUser = user;
        return this;
    }

    /**
     * Determine if the user is authorized to perform an ability.
     */
    public static async allows(ability: string, ...args: any[]): Promise<boolean> {
        // 1. Check if it's a direct gate definition
        if (this.abilities.has(ability)) {
            const callback = this.abilities.get(ability)!;
            return await callback(this.currentUser, ...args);
        }

        // 2. Check if it's a policy method
        if (args.length > 0) {
            const resource = args[0];
            const policy = this.policyResolver.resolvePolicy(resource);

            if (policy) {
                const method = this.policyResolver.getPolicyMethod(policy, ability);
                if (method) {
                    return await method(this.currentUser, ...args);
                }
            }
        }

        // 3. Default deny
        return false;
    }

    /**
     * Determine if the user is NOT authorized.
     */
    public static async denies(ability: string, ...args: any[]): Promise<boolean> {
        return !(await this.allows(ability, ...args));
    }

    /**
     * Authorize or throw exception.
     */
    public static async authorize(ability: string, ...args: any[]): Promise<void> {
        if (!(await this.allows(ability, ...args))) {
            throw new AuthorizationException();
        }
    }

    /**
     * Check authorization (alias for allows).
     */
    public static async check(ability: string, ...args: any[]): Promise<boolean> {
        return await this.allows(ability, ...args);
    }

    /**
     * Reset all gates and policies (useful for testing).
     */
    public static reset(): void {
        this.abilities.clear();
        this.policyResolver = new PolicyResolver();
        this.currentUser = null;
    }
}
