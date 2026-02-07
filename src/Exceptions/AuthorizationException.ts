export class AuthorizationException extends Error {
    public statusCode: number = 403;

    constructor(message: string = 'This action is unauthorized.') {
        super(message);
        this.name = 'AuthorizationException';
    }
}
