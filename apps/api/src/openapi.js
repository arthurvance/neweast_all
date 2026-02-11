const buildOpenApiSpec = () => ({
  openapi: '3.1.0',
  info: {
    title: 'Neweast API',
    version: '0.1.0',
    description: 'Auth and session lifecycle contract with password login, refresh rotation, logout, and password change'
  },
  paths: {
    '/health': {
      get: {
        summary: 'Health check',
        responses: {
          200: { description: 'Service is healthy' },
          503: {
            description: 'Dependency degraded',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['ok', 'dependencies', 'request_id'],
                  properties: {
                    ok: { type: 'boolean' },
                    request_id: { type: 'string' }
                  }
                }
              }
            }
          }
        }
      }
    },
    '/auth/ping': {
      get: {
        summary: 'Auth module readiness endpoint',
        responses: {
          200: {
            description: 'Auth module status'
          }
        }
      }
    },
    '/auth/login': {
      post: {
        summary: 'Password login',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/AuthLoginRequest' },
              examples: {
                success_case: {
                  value: {
                    phone: '13800000000',
                    password: 'Passw0rd!'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Login succeeded',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthTokenResponse' }
              }
            }
          },
          401: {
            description: 'Unified login failure semantics',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_credentials_or_disabled: {
                    value: {
                      type: 'about:blank',
                      title: 'Unauthorized',
                      status: 401,
                      detail: '手机号或密码错误',
                      error_code: 'AUTH-401-LOGIN-FAILED',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    '/auth/refresh': {
      post: {
        summary: 'Refresh session token pair with rotation',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/AuthRefreshRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Refresh succeeded and previous refresh token rotated out',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthTokenResponse' }
              }
            }
          },
          401: {
            description: 'Refresh invalid, expired, or replayed',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_refresh: {
                    value: {
                      type: 'about:blank',
                      title: 'Unauthorized',
                      status: 401,
                      detail: '会话已失效，请重新登录',
                      error_code: 'AUTH-401-INVALID-REFRESH',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    '/auth/logout': {
      post: {
        summary: 'Logout current session only',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Current session revoked; concurrent sessions remain active',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['ok', 'session_id', 'request_id'],
                  properties: {
                    ok: { type: 'boolean' },
                    session_id: { type: 'string' },
                    request_id: { type: 'string' }
                  }
                }
              }
            }
          },
          401: {
            description: 'Invalid access token',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/auth/change-password': {
      post: {
        summary: 'Change password and require relogin',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ChangePasswordRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Password hash updated and current auth session invalidated',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['password_changed', 'relogin_required', 'request_id'],
                  properties: {
                    password_changed: { type: 'boolean' },
                    relogin_required: { type: 'boolean' },
                    request_id: { type: 'string' }
                  }
                }
              }
            }
          },
          400: {
            description: 'Weak password or malformed payload',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          401: {
            description: 'Invalid session or current password mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/smoke': {
      get: {
        summary: 'Smoke chain probe',
        responses: {
          200: { description: 'db and redis are both connected' },
          503: { description: 'at least one dependency is degraded' }
        }
      }
    }
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT'
      }
    },
    schemas: {
      AuthLoginRequest: {
        type: 'object',
        required: ['phone', 'password'],
        properties: {
          phone: { type: 'string', description: '手机号' },
          password: { type: 'string', format: 'password' }
        }
      },
      AuthRefreshRequest: {
        type: 'object',
        required: ['refresh_token'],
        properties: {
          refresh_token: { type: 'string' }
        }
      },
      ChangePasswordRequest: {
        type: 'object',
        required: ['current_password', 'new_password'],
        properties: {
          current_password: { type: 'string', format: 'password' },
          new_password: { type: 'string', format: 'password', minLength: 6 }
        }
      },
      AuthTokenResponse: {
        type: 'object',
        required: [
          'token_type',
          'access_token',
          'refresh_token',
          'expires_in',
          'refresh_expires_in',
          'session_id',
          'request_id'
        ],
        properties: {
          token_type: { type: 'string', enum: ['Bearer'] },
          access_token: { type: 'string' },
          refresh_token: { type: 'string' },
          expires_in: { type: 'integer' },
          refresh_expires_in: { type: 'integer' },
          session_id: { type: 'string' },
          request_id: { type: 'string' }
        }
      },
      ProblemDetails: {
        type: 'object',
        required: ['title', 'status', 'request_id'],
        properties: {
          type: { type: 'string' },
          title: { type: 'string' },
          status: { type: 'integer' },
          detail: { type: 'string' },
          request_id: { type: 'string' },
          error_code: { type: 'string' }
        }
      }
    }
  }
});

module.exports = { buildOpenApiSpec };
