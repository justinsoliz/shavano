
// test/policy_authorizer.spec.js

describe('Policy authorizer', () => {
  let authorizer;
  beforeEach(() => {
    authorizer = PolicyAuthorizer({
      roles: { 'admin': { policies: [ basicPolicy ] } }
    });
  });

  it.skip('should authorize resources at the field level', () => {
    const user = { id: 'ac123', name: 'public name', email: 'private email' };
    const action = `users:${user.id}:email`;
    const roles = [ 'admin' ];
    const authorized = authorizer({ roles, action });
    expect(authorized).toEqual(true);
  });

  it('should authorize resources at the entity level', () => {
    const authorized = authorizer({ 
      action: 'users:list_users',
      roles: [ 'admin' ],
      resource: 'users'
    });

    expect(authorized).toEqual(true);
  });
});

function PolicyAuthorizer(config) {
  const configuredRoles = config.roles;

  return ({ roles, action, resource }) => {
    let authorized = false;

    for (let role of roles) {
      for (let policy of configuredRoles[role].policies) {
        for (let statement of policy.statements) {
          if (statement.effect === 'allow') {
            console.log(`requested action: ${action}, allowed action: ${statement.action}`);
            if (statement.action === action) {
              authorized = true;
              break;
            }
          }
        }
      }
    }

    return authorized;
  };
}

const basicPolicy = {
  name: 'allow_user_things',
  statements: [{
    effect: 'allow',
    action: 'users:list_users',
    resource: 'users'
  }]
};

