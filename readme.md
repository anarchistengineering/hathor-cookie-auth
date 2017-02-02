Hathor Cookie Auth
===

Installation
---

```
npm install --save hathor-cookie-auth
```

Configuration
---

```js
auth: {
  static: true, // it's better to not protect your static assets by default
  key: String, // Key/password for authentication

  // What module to utilize for authentication
  module: `hathor-cookie-auth`,

  // Value in milliseconds
  // for 1 year: 365 * 24 * 60 * 60 * 1000
  ttl: 1000 * 60 * 3,

  // If you need to allow access to a specific asset because you set static to false
  whitelist: [ // Always allow access to the login folder
    'login'
  ],

  blacklist: [ // If you have files that you don't want access to without auth, then blacklist them
    'login/private.html'
  ],

  // One option to provide username's and passwords
  users: [
    {
      username: 'test',
      password: 'person' // This value can be bcrypt'd so plain text isn't ever shown
    }
  ],

  // The "more appropriate" way
  userHandler(username, password, callback){},

  plugin: {} // Any values you want to override or push down into the hapi-auth-cookie module
}
```

Usage
---

### Using "validateFunc"

By providing a validateFunc you can setup your own token validation that can be used for things like expiring tokens when a certain criteria are met, users are edited/removed from the application and other common things that may change the state associated with the token.

The callback takes three parameters; error, isValid, and (optional) credentials.  A simple example below:

```js
const validateFunc = (decoded, request, callback){
  myUserProvider.byId(decoded.id, (err, user)=>{
    if(err){
      return callback(err);
    }
    return callback(null, !!user);
  });
}
```

If you wanted to change the credentials associated with a token (overwrite the decoded value), as an example to change the expires time, you would return a new credentials object.

### Using the "users" array

The users array is provided for development mode testing, it should never be used in a live environment.  Adding, editing, deleting users requires that you restart the application.

### Using a custom "userHandler"

If you setup and configure the userHandler method within the configuration it will take precedence over the users array.  This means that none of the user accounts specified within the users array will work if there is a userHandler defined.  If, for example you want to utilize the users array for local development and userHandler when running within a specified environment, it is recommended that you setup the userHandler in code when you load your configuration.  An example of this is given below.

The callback takes three parameters; error, isValid, and credentials

```js
const userHandler = (username, password, callback){
  myUserProvider.get(username, password, (err, user)=>{
    if(err){
      return callback(err);
    }
    return callback(null, !!user, user?{id: user.id}:false);
  });
}
```

Whatever you return in the credentials object will be encoded and sent back in the token.  If you need to change the encoded values later on you should use the validateFunc property to provide the new data.

Authorization
---

Once your application has a JSON Web Token it can pass this back to the server in either the Authorization header or in the query parameters of each call in the token parameter.

Routes Provided
---

### GET:/login
Returns the login index page from your application.

### POST:/login

Accepts username and password, returns a set cookie response that will be passed back in all subsequent requests to the application.

### POST|GET:/logout

Clears the token and "logs" the user out.  Unless this case is handled by your application code the token could still be valid.
