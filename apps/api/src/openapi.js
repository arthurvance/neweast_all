const RATE_LIMIT_RESPONSE_HEADERS = {
  'Retry-After': {
    description: 'Seconds until this route can be retried',
    schema: { type: 'integer', minimum: 1 }
  },
  'X-RateLimit-Limit': {
    description: 'Allowed requests in the current window',
    schema: { type: 'integer', minimum: 1 }
  },
  'X-RateLimit-Remaining': {
    description: 'Remaining requests in the current window',
    schema: { type: 'integer', minimum: 0 }
  },
  'X-RateLimit-Reset': {
    description: 'Seconds until the current limit window resets',
    schema: { type: 'integer', minimum: 1 }
  },
  'X-RateLimit-Policy': {
    description: 'Applied limit policy in limit;w=window format',
    schema: { type: 'string' }
  }
};

const buildOpenApiSpec = () => ({
  openapi: '3.1.0',
  info: {
    title: 'Neweast API',
    version: '0.1.0',
    description: 'Auth and session lifecycle contract with permission-declared protected routes and fail-closed preflight'
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
                    request_id: { type: 'string' },
                    dependencies: {
                      type: 'object',
                      additionalProperties: {
                        type: 'object',
                        properties: {
                          ok: { type: 'boolean' },
                          latency_ms: { type: 'number' }
                        }
                      }
                    }
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
                    password: 'Passw0rd!',
                    entry_domain: 'platform'
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
          400: {
            description: 'Invalid login payload',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_payload: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: '请求参数不完整或格式错误',
                      error_code: 'AUTH-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          413: {
            description: 'JSON payload exceeds allowed size',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  payload_too_large: {
                    value: {
                      type: 'about:blank',
                      title: 'Payload Too Large',
                      status: 413,
                      detail: 'JSON payload exceeds allowed size',
                      error_code: 'AUTH-413-PAYLOAD-TOO-LARGE',
                      request_id: 'request_id_unset'
                    }
                  }
                }
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
          },
          403: {
            description: 'No access to target domain',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  no_domain: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '当前入口无可用访问域权限',
                      error_code: 'AUTH-403-NO-DOMAIN',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          429: {
            description: 'Per-phone action rate limit exceeded',
            headers: RATE_LIMIT_RESPONSE_HEADERS,
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  rate_limited: {
                    value: {
                      type: 'about:blank',
                      title: 'Too Many Requests',
                      status: 429,
                      detail: '请求过于频繁，请稍后重试',
                      error_code: 'AUTH-429-RATE-LIMITED',
                      rate_limit_action: 'password_login',
                      retry_after_seconds: 32,
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
    '/auth/otp/send': {
      post: {
        summary: 'Send OTP code for phone login',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/OtpSendRequest' },
              examples: {
                send_otp: {
                  value: {
                    phone: '13800000000'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'OTP accepted and server-side resend hint returned',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/OtpSendResponse' },
                examples: {
                  otp_sent: {
                    summary: 'OTP successfully sent',
                    value: {
                      sent: true,
                      resend_after_seconds: 60,
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          400: {
            description: 'Invalid send payload',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_payload: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: '请求参数不完整或格式错误',
                      error_code: 'AUTH-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          413: {
            description: 'JSON payload exceeds allowed size',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  payload_too_large: {
                    value: {
                      type: 'about:blank',
                      title: 'Payload Too Large',
                      status: 413,
                      detail: 'JSON payload exceeds allowed size',
                      error_code: 'AUTH-413-PAYLOAD-TOO-LARGE',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          429: {
            description: 'OTP send rate limit exceeded',
            headers: RATE_LIMIT_RESPONSE_HEADERS,
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  otp_send_rate_limited: {
                    value: {
                      type: 'about:blank',
                      title: 'Too Many Requests',
                      status: 429,
                      detail: '请求过于频繁，请稍后重试',
                      error_code: 'AUTH-429-RATE-LIMITED',
                      rate_limit_action: 'otp_send',
                      retry_after_seconds: 41,
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
    '/auth/otp/login': {
      post: {
        summary: 'Login by phone + OTP',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/OtpLoginRequest' },
              examples: {
                otp_login: {
                  value: {
                    phone: '13800000000',
                    otp_code: '123456',
                    entry_domain: 'platform'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'OTP login succeeded',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthTokenResponse' }
              }
            }
          },
          400: {
            description: 'Invalid OTP login payload',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_payload: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: '请求参数不完整或格式错误',
                      error_code: 'AUTH-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          413: {
            description: 'JSON payload exceeds allowed size',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  payload_too_large: {
                    value: {
                      type: 'about:blank',
                      title: 'Payload Too Large',
                      status: 413,
                      detail: 'JSON payload exceeds allowed size',
                      error_code: 'AUTH-413-PAYLOAD-TOO-LARGE',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          401: {
            description: 'Invalid/expired/used OTP unified semantics',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  otp_invalid_or_expired: {
                    value: {
                      type: 'about:blank',
                      title: 'Unauthorized',
                      status: 401,
                      detail: '验证码错误或已失效',
                      error_code: 'AUTH-401-OTP-FAILED',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          403: {
            description: 'No access to target domain',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  no_domain: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '当前入口无可用访问域权限',
                      error_code: 'AUTH-403-NO-DOMAIN',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          429: {
            description: 'OTP login rate limit exceeded',
            headers: RATE_LIMIT_RESPONSE_HEADERS,
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  otp_login_rate_limited: {
                    value: {
                      type: 'about:blank',
                      title: 'Too Many Requests',
                      status: 429,
                      detail: '请求过于频繁，请稍后重试',
                      error_code: 'AUTH-429-RATE-LIMITED',
                      rate_limit_action: 'otp_login',
                      retry_after_seconds: 27,
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
    '/auth/tenant/options': {
      get: {
        summary: 'List current user tenant options and active session context',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Tenant options and session context',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantContextResponse' }
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
          },
          403: {
            description: 'No access to tenant domain',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  no_domain: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '当前入口无可用访问域权限',
                      error_code: 'AUTH-403-NO-DOMAIN',
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
    '/auth/tenant/select': {
      post: {
        summary: 'Select active tenant for current session',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/TenantSelectRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Tenant selected and persisted to session context',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantSelectResponse' }
              }
            }
          },
          400: {
            description: 'Invalid payload',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
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
          },
          403: {
            description: 'No access to selected tenant',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  no_domain: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '当前入口无可用访问域权限',
                      error_code: 'AUTH-403-NO-DOMAIN',
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
    '/auth/tenant/switch': {
      post: {
        summary: 'Switch active tenant in current session',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/TenantSelectRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Tenant switched and persisted to session context',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantSelectResponse' }
              }
            }
          },
          400: {
            description: 'Invalid payload',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
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
          },
          403: {
            description: 'No access to selected tenant',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  no_domain: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '当前入口无可用访问域权限',
                      error_code: 'AUTH-403-NO-DOMAIN',
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
    '/auth/tenant/member-admin/probe': {
      get: {
        summary: 'Probe tenant member-admin operate permission with unified authorization semantics',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Current session is authorized for member-admin operate capability',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['ok', 'request_id'],
                  properties: {
                    ok: { type: 'boolean' },
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
          },
          403: {
            description:
              'Tenant route blocked due to missing tenant domain context or insufficient tenant permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  no_domain: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '当前入口无可用访问域权限',
                      error_code: 'AUTH-403-NO-DOMAIN',
                      request_id: 'request_id_unset'
                    }
                  },
                  forbidden: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '当前操作无权限',
                      error_code: 'AUTH-403-FORBIDDEN',
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
    '/auth/platform/member-admin/probe': {
      get: {
        summary: 'Probe platform member-admin view permission with unified authorization semantics',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Current session is authorized for platform member-admin view capability',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['ok', 'request_id'],
                  properties: {
                    ok: { type: 'boolean' },
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
          },
          403: {
            description:
              'Platform route blocked due to missing platform domain context or insufficient platform permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  no_domain: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '当前入口无可用访问域权限',
                      error_code: 'AUTH-403-NO-DOMAIN',
                      request_id: 'request_id_unset'
                    }
                  },
                  forbidden: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '当前操作无权限',
                      error_code: 'AUTH-403-FORBIDDEN',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          503: {
            description: 'Platform permission snapshot sync temporarily degraded',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  snapshot_sync_degraded: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '平台权限同步暂时不可用，请稍后重试',
                      error_code: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
                      request_id: 'request_id_unset',
                      degradation_reason: 'db-deadlock'
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
          400: {
            description: 'Invalid refresh payload',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_payload: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: '请求参数不完整或格式错误',
                      error_code: 'AUTH-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          413: {
            description: 'JSON payload exceeds allowed size',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  payload_too_large: {
                    value: {
                      type: 'about:blank',
                      title: 'Payload Too Large',
                      status: 413,
                      detail: 'JSON payload exceeds allowed size',
                      error_code: 'AUTH-413-PAYLOAD-TOO-LARGE',
                      request_id: 'request_id_unset'
                    }
                  }
                }
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
          413: {
            description: 'JSON payload exceeds allowed size',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  payload_too_large: {
                    value: {
                      type: 'about:blank',
                      title: 'Payload Too Large',
                      status: 413,
                      detail: 'JSON payload exceeds allowed size',
                      error_code: 'AUTH-413-PAYLOAD-TOO-LARGE',
                      request_id: 'request_id_unset'
                    }
                  }
                }
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
    '/auth/platform/role-facts/replace': {
      post: {
        summary: 'Replace platform role facts and sync permission snapshot',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ReplacePlatformRoleFactsRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Platform role facts replaced and permission snapshot synchronized',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ReplacePlatformRoleFactsResponse' }
              }
            }
          },
          400: {
            description: 'Malformed payload or invalid role fact status',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          413: {
            description: 'JSON payload exceeds allowed size',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  payload_too_large: {
                    value: {
                      type: 'about:blank',
                      title: 'Payload Too Large',
                      status: 413,
                      detail: 'JSON payload exceeds allowed size',
                      error_code: 'AUTH-413-PAYLOAD-TOO-LARGE',
                      request_id: 'request_id_unset'
                    }
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
          },
          403: {
            description: 'Current session lacks platform role-facts operate permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'Platform role-facts synchronization temporarily degraded',
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
          password: { type: 'string', format: 'password' },
          entry_domain: {
            type: 'string',
            enum: ['platform', 'tenant'],
            default: 'platform',
            description: '可选，默认 platform'
          }
        }
      },
      AuthRefreshRequest: {
        type: 'object',
        required: ['refresh_token'],
        properties: {
          refresh_token: { type: 'string' }
        }
      },
      OtpSendRequest: {
        type: 'object',
        required: ['phone'],
        properties: {
          phone: { type: 'string', description: '手机号（11位）' }
        }
      },
      OtpSendResponse: {
        type: 'object',
        required: ['sent', 'resend_after_seconds', 'request_id'],
        properties: {
          sent: { type: 'boolean' },
          resend_after_seconds: { type: 'integer', minimum: 0 },
          request_id: { type: 'string' }
        }
      },
      OtpLoginRequest: {
        type: 'object',
        required: ['phone', 'otp_code'],
        properties: {
          phone: { type: 'string' },
          otp_code: { type: 'string', minLength: 6, maxLength: 6 },
          entry_domain: {
            type: 'string',
            enum: ['platform', 'tenant'],
            default: 'platform',
            description: '可选，默认 platform'
          }
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
      ReplacePlatformRoleFactsRequest: {
        type: 'object',
        required: ['user_id', 'roles'],
        properties: {
          user_id: {
            type: 'string',
            minLength: 1,
            pattern: '.*\\S.*'
          },
          roles: {
            type: 'array',
            maxItems: 5,
            uniqueItems: true,
            description: '最多 5 条角色事实；服务端按 role_id（大小写不敏感）判重并拒绝重复',
            items: { $ref: '#/components/schemas/PlatformRoleFact' }
          }
        }
      },
      PlatformRoleFact: {
        type: 'object',
        required: ['role_id'],
        properties: {
          role_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '.*\\S.*'
          },
          status: {
            type: 'string',
            enum: ['active', 'enabled', 'disabled'],
            default: 'active'
          },
          permission: { $ref: '#/components/schemas/PlatformRolePermission' }
        }
      },
      PlatformRolePermission: {
        type: 'object',
        properties: {
          can_view_member_admin: { type: 'boolean' },
          can_operate_member_admin: { type: 'boolean' },
          can_view_billing: { type: 'boolean' },
          can_operate_billing: { type: 'boolean' }
        }
      },
      PlatformPermissionContext: {
        type: 'object',
        required: [
          'scope_label',
          'can_view_member_admin',
          'can_operate_member_admin',
          'can_view_billing',
          'can_operate_billing'
        ],
        properties: {
          scope_label: { type: 'string' },
          can_view_member_admin: { type: 'boolean' },
          can_operate_member_admin: { type: 'boolean' },
          can_view_billing: { type: 'boolean' },
          can_operate_billing: { type: 'boolean' }
        }
      },
      ReplacePlatformRoleFactsResponse: {
        type: 'object',
        required: ['synced', 'reason', 'platform_permission_context', 'request_id'],
        properties: {
          synced: { type: 'boolean' },
          reason: { type: 'string' },
          platform_permission_context: {
            $ref: '#/components/schemas/PlatformPermissionContext'
          },
          request_id: { type: 'string' }
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
          'entry_domain',
          'tenant_selection_required',
          'tenant_permission_context',
          'request_id'
        ],
        properties: {
          token_type: { type: 'string', enum: ['Bearer'] },
          access_token: { type: 'string' },
          refresh_token: { type: 'string' },
          expires_in: { type: 'integer' },
          refresh_expires_in: { type: 'integer' },
          session_id: { type: 'string' },
          entry_domain: { type: 'string', enum: ['platform', 'tenant'] },
          active_tenant_id: { type: 'string', nullable: true },
          tenant_selection_required: { type: 'boolean' },
          tenant_options: {
            type: 'array',
            items: { $ref: '#/components/schemas/TenantOption' }
          },
          tenant_permission_context: {
            $ref: '#/components/schemas/TenantPermissionContext'
          },
          request_id: { type: 'string' }
        }
      },
      TenantOption: {
        type: 'object',
        required: ['tenant_id'],
        properties: {
          tenant_id: { type: 'string' },
          tenant_name: { type: 'string', nullable: true }
        }
      },
      TenantContextResponse: {
        type: 'object',
        required: [
          'session_id',
          'entry_domain',
          'active_tenant_id',
          'tenant_selection_required',
          'tenant_options',
          'tenant_permission_context',
          'request_id'
        ],
        properties: {
          session_id: { type: 'string' },
          entry_domain: { type: 'string', enum: ['platform', 'tenant'] },
          active_tenant_id: { type: 'string', nullable: true },
          tenant_selection_required: { type: 'boolean' },
          tenant_options: {
            type: 'array',
            items: { $ref: '#/components/schemas/TenantOption' }
          },
          tenant_permission_context: {
            $ref: '#/components/schemas/TenantPermissionContext'
          },
          request_id: { type: 'string' }
        }
      },
      TenantSelectRequest: {
        type: 'object',
        required: ['tenant_id'],
        properties: {
          tenant_id: { type: 'string' }
        }
      },
      TenantSelectResponse: {
        type: 'object',
        required: [
          'session_id',
          'entry_domain',
          'active_tenant_id',
          'tenant_selection_required',
          'tenant_permission_context',
          'request_id'
        ],
        properties: {
          session_id: { type: 'string' },
          entry_domain: { type: 'string', enum: ['tenant'] },
          active_tenant_id: { type: 'string' },
          tenant_selection_required: { type: 'boolean' },
          tenant_permission_context: {
            $ref: '#/components/schemas/TenantPermissionContext'
          },
          request_id: { type: 'string' }
        }
      },
      TenantPermissionContext: {
        type: 'object',
        required: [
          'scope_label',
          'can_view_member_admin',
          'can_operate_member_admin',
          'can_view_billing',
          'can_operate_billing'
        ],
        properties: {
          scope_label: { type: 'string' },
          can_view_member_admin: { type: 'boolean' },
          can_operate_member_admin: { type: 'boolean' },
          can_view_billing: { type: 'boolean' },
          can_operate_billing: { type: 'boolean' }
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
          error_code: { type: 'string' },
          retry_after_seconds: { type: 'integer', minimum: 1 },
          rate_limit_action: {
            type: 'string',
            enum: ['password_login', 'otp_send', 'otp_login']
          },
          rate_limit_limit: { type: 'integer', minimum: 1 },
          rate_limit_window_seconds: { type: 'integer', minimum: 1 }
        }
      }
    }
  }
});

module.exports = { buildOpenApiSpec };
