import { describe, it, beforeEach, afterEach } from 'node:test';
import * as assert from 'node:assert';
import { Gate, AuthorizationManager, AuthorizationException, Policy } from '../src';

class Post {
    constructor(public id: number, public userId: number, public title: string) { }
}

class PostPolicy implements Policy {
    view(user: any, post: Post): boolean {
        return true; // Anyone can view
    }

    update(user: any, post: Post): boolean {
        return user.id === post.userId;
    }

    delete(user: any, post: Post): boolean {
        return user.id === post.userId && user.isAdmin;
    }
}

describe('Arika Authorization', () => {
    const user = { id: 1, name: 'John', isAdmin: false };
    const adminUser = { id: 2, name: 'Admin', isAdmin: true };
    const post = new Post(1, 1, 'Test Post');
    const otherPost = new Post(2, 2, 'Other Post');

    beforeEach(() => {
        Gate.reset();
    });

    afterEach(() => {
        Gate.reset();
    });

    it('defines and checks gates', async () => {
        Gate.define('edit-post', (user, post) => {
            return user.id === post.userId;
        });

        const canEdit = await Gate.forUser(user).allows('edit-post', post);
        assert.strictEqual(canEdit, true);

        const cannotEdit = await Gate.forUser(user).allows('edit-post', otherPost);
        assert.strictEqual(cannotEdit, false);
    });

    it('denies unauthorized actions', async () => {
        Gate.define('delete-post', (user, post) => {
            return user.isAdmin;
        });

        const denied = await Gate.forUser(user).denies('delete-post', post);
        assert.strictEqual(denied, true);

        const allowed = await Gate.forUser(adminUser).denies('delete-post', post);
        assert.strictEqual(allowed, false);
    });

    it('works with policies', async () => {
        Gate.policy(Post, PostPolicy);

        const canView = await Gate.forUser(user).allows('view', post);
        assert.strictEqual(canView, true);

        const canUpdate = await Gate.forUser(user).allows('update', post);
        assert.strictEqual(canUpdate, true);

        const cannotUpdate = await Gate.forUser(user).allows('update', otherPost);
        assert.strictEqual(cannotUpdate, false);
    });

    it('throws AuthorizationException on unauthorized', async () => {
        Gate.define('admin-only', (user) => user.isAdmin);

        await assert.rejects(
            async () => await Gate.forUser(user).authorize('admin-only'),
            AuthorizationException
        );

        // Should not throw for admin
        await assert.doesNotReject(
            async () => await Gate.forUser(adminUser).authorize('admin-only')
        );
    });

    it('works with AuthorizationManager', async () => {
        Gate.define('edit-post', (user, post) => user.id === post.userId);

        const authz = new AuthorizationManager(user);

        const can = await authz.can('edit-post', post);
        assert.strictEqual(can, true);

        const cannot = await authz.cannot('edit-post', otherPost);
        assert.strictEqual(cannot, true);
    });

    it('handles policy methods with multiple arguments', async () => {
        Gate.policy(Post, PostPolicy);

        const canDelete = await Gate.forUser(adminUser).allows('delete', post);
        assert.strictEqual(canDelete, false); // adminUser owns post 2, not post 1

        const adminPost = new Post(3, 2, 'Admin Post');
        const canDeleteOwn = await Gate.forUser(adminUser).allows('delete', adminPost);
        assert.strictEqual(canDeleteOwn, true);
    });
});
