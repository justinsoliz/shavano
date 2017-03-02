
// lib/permission_strategy.js

export default function PermissionStrategy(config) {
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

