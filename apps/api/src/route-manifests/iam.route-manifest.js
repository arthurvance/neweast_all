const IAM_ROUTE_MANIFEST = Object.freeze([
  {
    method: 'GET',
    path: '/health',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'GET',
    path: '/openapi.json',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'GET',
    path: '/auth/ping',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'POST',
    path: '/auth/login',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'POST',
    path: '/auth/otp/send',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'POST',
    path: '/auth/otp/login',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'POST',
    path: '/auth/refresh',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'POST',
    path: '/auth/logout',
    access: 'protected',
    permission_code: 'auth.session.logout',
    scope: 'session'
  },
  {
    method: 'POST',
    path: '/auth/change-password',
    access: 'protected',
    permission_code: 'auth.session.change_password',
    scope: 'session'
  },
  {
    method: 'GET',
    path: '/smoke',
    access: 'public',
    permission_code: '',
    scope: 'public'
  }
]);

module.exports = {
  IAM_ROUTE_MANIFEST
};
