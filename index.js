const Joi = require('joi');
const bcrypt = require('bcryptjs');
const {
  isHtmlPage
} = require('hathor-utils');

const generateRandomKey = ()=>{
  return require('crypto').randomBytes(256).toString('base64');
};

const findUser = (username, password, config, callback)=>{
  const userHandler = config.get('userHandler', false);
  if(userHandler){
    return userHandler(username, password, callback);
  }
  const users = config.get('users', false);
  if(Array.isArray(users)){
    const uname = username.toLowerCase();
    const matches = users.filter((user)=>user.username.toLowerCase()===uname);
    const user = matches.shift();
    if(!user){
      return callback(null, false);
    }
    return bcrypt.compare(password, user.password, (err, isValid)=>{
      if(err){
        return callback(err);
      }
      if((!isValid) && (user.password === password)){
        return callback(null, true, user);
      }
      return callback(err, isValid, user);
    });
  }
  return callback(new Error('Attempt to use cookie auth with no users or no userHandler defined!'));
};

module.exports = {
  type: 'session',

  routes(server, options){
    const config = options.get('auth');
    const logger = server.logger;
    const {
      whitelist = [],
      blacklist = [],
      loginLandingPage,
      logoutPath,
      logoutRedirectTo
    } = config.toJS();
    const whitelistPages = (whitelist && whitelist.length)?
            whitelist.map((page)=>{
              const pageIsHTML = isHtmlPage(page);
              return pageIsHTML?{
                method: 'GET',
                path: `/${page}`,
                auth: false,
                handler: {
                  file: {
                    path: page
                  }
                }
              }:{
                method: 'GET',
                path: `/${page}/{param*}`,
                auth: false,
                handler: {
                  directory: {
                    path: `${page}/.`,
                    redirectToSlash: true,
                    index: true
                  }
                }
              };
            }).filter((p)=>!!p):
            [];
    const blacklistPages = (blacklist && blacklist.length)?
            blacklist.map((page)=>{
              const pageIsHTML = isHtmlPage(page);
              return pageIsHTML?{
                method: 'GET',
                path: `/${page}`,
                auth: true,
                handler: {
                  file: {
                    path: page
                  }
                }
              }:{
                method: 'GET',
                path: `/${page}/{param*}`,
                auth: true,
                handler: {
                  directory: {
                    path: `${page}/.`,
                    redirectToSlash: true,
                    index: true
                  }
                }
              };
            }).filter((p)=>!!p):
            [];
    return [...[
      {
        method: 'POST',
        path: config.get('loginPath', '/login'),
        config: {
          description: 'Validates login credentials',
          notes: 'Validates login credentials (username and password) contained in the payload, on scucess sets a browser cookie for authentication and returns a redirect to '+(loginLandingPage||'/')+'.',
          tags: ['api'],
          validate: {
            payload: Joi.object().keys({
              username: Joi.string().required(),
              password: Joi.string().required()
            })
          },
          response: {
            schema: Joi.description('Redirect to '+(loginLandingPage||'/')),
            status: {
              200: Joi.description('Redirect to '+(loginLandingPage||'/')),
              400: Joi.object().keys({
                statusCode: Joi.number().default(400),
                error: Joi.string().default('Bad Request'),
                message: Joi.string().default('child "username" fails because ["username" is required]'),
                validation: {
                  source: Joi.string().default('payload'),
                  keys: Joi.array().items(Joi.string()).default(['username'])
                }
              }).description('Required fields missing'),
              401: Joi.string().description('Invalid reason')
            }
          }
        },
        handler(req, reply){
          const {
            username,
            password
          } = req.payload;
          if(username && password){
            logger.info(`User auth attempt:`, username);
            return findUser(username, password, config, (err, isValid, account)=>{
              if(err){
                return reply(err.toString()).code(401);
              }
              if(!isValid){
                return reply('Invalid username or password').code(401);
              }
              const sid = username+(new Date()).getTime();
              req.server.app.cache.set(sid, { account }, 0, (err) => {
                if(err){
                  reply(err);
                }

                req.cookieAuth.set({sid});
                const nextPage = req.query.next||loginLandingPage||'/';
                logger.info(`Validated user:`, username, sid, `redirect to:`, nextPage);
                return reply.redirect(nextPage);
              });
            });
          }
          return reply('Missing username or password').code(401);
        }
      },
      {
        method: ['GET', 'POST'],
        path: logoutPath || '/logout',
        config: {
          tags: ['api'],
          description: 'Perform logout process',
          notes: 'Clears browser cookie and logs user out. Returns a redirect to '+(logoutRedirectTo || '/'),
        },
        handler(req, reply){
          req.cookieAuth.clear();
          return reply.redirect(logoutRedirectTo || '/');
        }
      }
    ], ...whitelistPages, ...blacklistPages];
  },

  postRegister(server, options, next){
    const config = options.get('auth');
    const logger = server.logger;
    const ttl = config.get('TTL', config.get('ttl'));
    const cache = server.cache({segment: 'sessions', expiresIn: ttl});
    server.app.cache = cache;
    const validateCookie = (req, session, callback)=>{
      logger.debug(`validateCooke`, session);
      cache.get(session.sid, (err, cached)=>{
        if(err){
          return callback(err, false);
        }
        if(!cached){
          return callback(null, false);
        }
        return callback(null, true, cached.account);
      });
    };
    const key = config.get('key', generateRandomKey());
    server.auth.strategy('session', 'cookie', Object.assign({
      cookie: config.get('cookie', 'sid'),
      password: key,
      clearInvalid: true,
      keepAlive: true,
      redirectTo: config.get('loginPath', '/login/'),
      ttl,
      isSecure: false,
      appendNext: 'redirectTo',
      validateFunc: validateCookie
    }, config.get('plugin', {}).toJS()));
    return next();
  },

  plugin: require('hapi-auth-cookie')
};
