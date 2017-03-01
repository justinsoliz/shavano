
// test/role_authorizer.spec.js

describe('Authorizer', () => {
  let authorizer;

  describe('Permissions based strategy', () => {
    beforeEach(() => {
      authorizer = new PermissionStrategy({
        roles: { 'admin': { allow: [ 'users:get_user' ] } }
      });
    });

    it('should handle non-existant actions', () => {
      const action  = 'invalid';
      const roles = [ 'admin' ];
      const authorized = authorizer(roles, action);
      expect(authorized).toEqual(false);
    });

    it('should handle non-existant roles', () => {
      const action  = 'users:get_user';
      const roles = [ 'invalid', 'admin' ];
      const authorized = authorizer(roles, action);
      expect(authorized).toEqual(true);
    })

    it('should authorize permissions (actions)', () => {
      const action  = 'users:get_user';
      const roles = [ 'admin', 'user' ];
      const authorized = authorizer(roles, action);
      expect(authorized).toEqual(true);
    });
  });
});

function PermissionStrategy(config) {
  const configuredRoles = config.roles;
  return (roles, action) => {
    let authorized = false;
    for (let role of roles) {
      if (!configuredRoles[role]) continue;
      const allowedActions = configuredRoles[role].allow;
      if (allowedActions && allowedActions.indexOf(action) > -1) {
        authorized = true;
        break;
      } 
    }
    return authorized;
  };
}

