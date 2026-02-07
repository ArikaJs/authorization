import { Gate } from '../Gate';
import { AuthorizationException } from '../Exceptions/AuthorizationException';

export class Authorize {
    /**
     * Handle authorization middleware.
     * 
     * @param request - The request object (should have user attached)
     * @param next - The next middleware function
     * @param ability - The ability to check (e.g., 'edit-post' or 'update')
     * @param resourceKey - Optional resource key from request (e.g., 'post')
     */
    public async handle(
        request: any,
        next: () => Promise<any>,
        ability: string,
        resourceKey?: string
    ): Promise<any> {
        const user = request.user;

        if (!user) {
            throw new AuthorizationException('User not authenticated.');
        }

        Gate.forUser(user);

        // If resourceKey is provided, get resource from request
        const resource = resourceKey ? request[resourceKey] : null;

        if (resource) {
            await Gate.authorize(ability, resource);
        } else {
            await Gate.authorize(ability);
        }

        return next();
    }
}
