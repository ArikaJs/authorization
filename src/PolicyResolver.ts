import { Policy } from './Contracts/Policy';

export class PolicyResolver {
    private policies: Map<any, any> = new Map();

    /**
     * Register a policy for a given model/class.
     */
    public register(model: any, policy: any): void {
        this.policies.set(model, policy);
    }

    /**
     * Resolve the policy for a given resource.
     */
    public resolvePolicy(resource: any): any | null {
        if (!resource) return null;

        // Check if resource has a constructor
        const constructor = resource.constructor;
        if (constructor && this.policies.has(constructor)) {
            return this.policies.get(constructor);
        }

        // Direct lookup
        if (this.policies.has(resource)) {
            return this.policies.get(resource);
        }

        return null;
    }

    /**
     * Get policy method for ability.
     */
    public getPolicyMethod(policy: any, ability: string): Function | null {
        if (!policy) return null;

        const instance = typeof policy === 'function' ? new policy() : policy;

        if (typeof instance[ability] === 'function') {
            return instance[ability].bind(instance);
        }

        return null;
    }
}
