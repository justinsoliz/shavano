
// test/permission_authorizer.spec.js

describe('Permissions Authorizer', () => {

  describe('Simple permission test', () => {
    let authorizer, validPermission = 'users:list_users';
    beforeEach(() => {
      authorizer = PermissionAuthorizer({
        roles: { 'admin': { permissions: [ validPermission ] } }
      });
    });

    it('should authorize a permission', () => {
      const action = validPermission;
      const roles = [ 'admin' ];
      const authorized = authorizer({ action, roles });
      expect(authorized).toEqual(true);
    });

    it('should authorize a permission for multiple roles', () => {
      const action = validPermission;
      const roles = [ 'user', 'admin' ];
      const authorized = authorizer({ action, roles });
      expect(authorized).toEqual(true);
    });
  });

  describe('Advanced permission subtypes', () => {
    let authorizer;
    beforeEach(() => {
      authorizer = PermissionAuthorizer({
        roles: { 
          'user': { permissions: [ 'users:get_user' ] },
          'admin': { permissions: [ 'users:get_user:private_data' ] } 
        }
      });
    });

    it('should authorize permission for specific type of action', () => {
      const action = 'users:get_user:private_data';
      const adminAuthorized = authorizer({ action, roles: ['admin'] });
      const userAuthorized = authorizer({ action, roles: ['user'] });
      expect(adminAuthorized).toEqual(true);
      expect(userAuthorized).toEqual(false);
    });
  });

  describe('Granular permission types defined by "*" syntax', () => {
    let authorizer;
    beforeEach(() => {
      authorizer = PermissionAuthorizer({
        roles: { 
          'user': { permissions: [ 'users:get_user' ] },
          'admin': { permissions: [ 'users:get_user:*' ] },
          'moderator': { 
            permissions: [ 'users:list_users', 'users:get_user:*' ] 
          },
          'user1': { permissions: [ 'users:*:private_data' ] },
          'user2': { permissions: [ 'users:*:private_data' ] }
        }
      });
    });

    it('should authorize valid role with multiple permissions', () => {
      const action = 'users:get_user:private_data';
      const moderatorAuthorized = authorizer({ action, roles: ['moderator'] });
      const userAuthorized = authorizer({ action, roles: ['user'] });
      expect(moderatorAuthorized).toEqual(true);
      expect(userAuthorized).toEqual(false);
    });

    it('should authorize permission', () => {
      const action = 'users:get_user:private_data';
      const adminAuthorized = authorizer({ action, roles: ['admin'] });
      const userAuthorized = authorizer({ action, roles: ['user'] });
      expect(adminAuthorized).toEqual(true);
      expect(userAuthorized).toEqual(false);
    });
  });
});

describe('Permission part validator', () => {
  let roleConfig = { roles:{} }, authorizer, dupRoles = {};
  beforeEach(() => {
    roleConfig = generateRoleConfig(6);
    console.log('inspect role config');
    console.log(JSON.stringify(roleConfig, null, 2));
    authorizer = PermissionAuthorizer(roleConfig);
  });

  /**
   * build up role configuration struture
   *  roleConfig = {
   *    roles: {
   *      'role1': { permissions: [ 'permission1' ] },
   *      'role2': { permissions: [ 'permission2' ] }
   *    }
   *  }
   */
  function generateRoleConfig(multiplier) {
    const partMultiplier = 5;
    let roleConfig = { roles: {} };

    // generate X roles
    for (var i = 0; i < multiplier; i++) {
      const role = generateId(10);
      roleConfig.roles[role] = { permissions: [] };
      // generate Y permissions for each role
      for (var a = 0; a < multiplier; a++) {
        const permissionParts = [];
        for (var b = 0; b < partMultiplier; b++) {
          const permPart = b === a && a < partMultiplier ? '*' : generateId(3);
          dupRoles[permPart] = dupRoles[permPart] ? dupRoles[permPart] + 1 : 1;
          permissionParts.push(permPart);
        }
        roleConfig.roles[role].permissions.push(permissionParts.join(':'));
      }
    }

    console.log(`inspect dup roles`);
    console.log(JSON.stringify(dupRoles, null, 2))

    return roleConfig;
  }

  /**
   * come up with optimized trie structure to map permission down each node depth
   */
  it.skip('should authorized for last permission of last role', () => {

    // resolve last permission of last role
    const configKeys = Object.keys(roleConfig.roles);
    const lastRole = configKeys[configKeys.length - 1];
    const lastPermission = roleConfig.roles[lastRole]
      .permissions[roleConfig.roles[lastRole].permissions.length - 1];

    console.log('inspect last permission and last role');
    console.log({ lastRole, lastPermission });

    var startTime = process.hrtime();
    const authorized = authorizer({ 
      action: lastPermission,
      roles: [ lastRole ]
    });

    printElapsedTime(startTime);

    expect(authorized).toEqual(true);
  });
});

/**
 * better resolution for measuring function execution time
 * http://stackoverflow.com/questions/10617070/how-to-measure-execution-time-of-javascript-code-with-callbacks/14551263#14551263
 * https://blog.tompawlak.org/measure-execution-time-nodejs-javascript
 */
function printElapsedTime(startTime) {
  // 3 decimal places
  const precision = 3;
  const hrend = process.hrtime(startTime);
  console.log(`Execution time: ${hrend[0]}s ${hrend[1]/1000000}ms`);

  // divide by a million to get nano to milli
  // var elapsed = process.hrtime(startTime)[1] / 1000000;
  // print message + time
  // console.log(process.hrtime(startTime)[0] + " s, " + 
              // elapsed.toFixed(precision) + " ms");
}

function PermissionAuthorizer(config) {
  const configuredRoles = config.roles;

  return ({ roles, action }) => {
    let authorized = false;

    for (let role of roles) {
      if (!configuredRoles[role]) continue;
      const { permissions } = configuredRoles[role];

      // destructure requested action on ':'
      const actionParts = action.split(':');

      // match action to permissions by each piece
      if (actionParts.length > 0) {

        // loop through each permission
        for (let permission of permissions) {
          // destructure permission on semicolon
          let permissionParts = permission.split(':');

          /*
           * console.log(`checking permission: ${permission}`);
           * console.log(`action parts: ${actionParts}`);
           * console.log(`permission parts: ${permissionParts}`);
           */

          // deny if actionParts length is longer than permissionParts
          if (actionParts.length > permissionParts.length) {
            continue;
          }

          // loop through each permission part, check against respective
          // action part index
          for (let i = 0; i < actionParts.length; i++) {

            // permission part is potentiall still valid
            if (permissionParts[i] === '*' || 
               actionParts[i] === permissionParts[i]) {
              continue;
            } else {
              // permisssion part invalid, break from loop
              // try next permission
              // console.log(`permissionPart invalid: ${permissionParts[i]}`)
              break;
            }
          }

          // permission is valid if we get through each actionPart with a match
          authorized = true;
          break;
        }
      } else {
        // if action is not destructured, try straight string match in array
        if (permissions.indexOf(action) > -1) {
          authorized = true;
          break;
        } 
      }
    }
    return authorized;
  };
}

function generateId(length) {
  let text = '';
  let possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  for (var i = 0; i < length; i++ ) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

