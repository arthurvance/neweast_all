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

const IDEMPOTENCY_KEY_SCHEMA = {
  type: 'string',
  minLength: 1,
  maxLength: 128,
  pattern: '^(?=.*\\S)[^,]{1,128}$'
};

const DEPENDENCY_PROBE_STATUS_SCHEMA = {
  type: 'object',
  required: ['ok', 'mode', 'detail'],
  properties: {
    ok: { type: 'boolean' },
    mode: { type: 'string' },
    detail: { type: 'string' },
    latency_ms: { type: 'number' }
  },
  additionalProperties: true
};

const DEPENDENCY_PROBE_SNAPSHOT_SCHEMA = {
  type: 'object',
  required: ['db', 'redis'],
  properties: {
    db: DEPENDENCY_PROBE_STATUS_SCHEMA,
    redis: DEPENDENCY_PROBE_STATUS_SCHEMA
  },
  additionalProperties: false
};

const HEALTH_RESPONSE_SCHEMA = {
  type: 'object',
  required: ['ok', 'service', 'request_id', 'dependencies'],
  properties: {
    ok: { type: 'boolean' },
    service: { type: 'string' },
    request_id: { type: 'string' },
    dependencies: DEPENDENCY_PROBE_SNAPSHOT_SCHEMA
  }
};

const SMOKE_RESPONSE_SCHEMA = {
  type: 'object',
  required: ['ok', 'chain', 'request_id', 'dependencies'],
  properties: {
    ok: { type: 'boolean' },
    chain: { type: 'string' },
    request_id: { type: 'string' },
    dependencies: DEPENDENCY_PROBE_SNAPSHOT_SCHEMA
  }
};

const ensureProblemDetailsRetryableExamples = (spec = {}) => {
  for (const pathItem of Object.values(spec.paths || {})) {
    for (const operation of Object.values(pathItem || {})) {
      for (const response of Object.values(operation?.responses || {})) {
        const problemContent = response?.content?.['application/problem+json'];
        const examples = problemContent?.examples;
        if (!examples || typeof examples !== 'object') {
          continue;
        }
        for (const example of Object.values(examples)) {
          const value = example?.value;
          if (!value || typeof value !== 'object' || Array.isArray(value)) {
            continue;
          }
          if (
            Object.prototype.hasOwnProperty.call(value, 'error_code')
            && typeof value.retryable !== 'boolean'
          ) {
            value.retryable = false;
          }
        }
      }
    }
  }
  return spec;
};

const buildOpenApiSpec = () => {
  const spec = {
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
          200: {
            description: 'Service is healthy',
            content: {
              'application/json': {
                schema: HEALTH_RESPONSE_SCHEMA
              }
            }
          },
          503: {
            description: 'Dependency degraded',
            content: {
              'application/json': {
                schema: HEALTH_RESPONSE_SCHEMA
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
                      retryable: true,
                      rate_limit_action: 'password_login',
                      rate_limit_limit: 10,
                      rate_limit_window_seconds: 60,
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
                      retryable: true,
                      rate_limit_action: 'otp_send',
                      rate_limit_limit: 10,
                      rate_limit_window_seconds: 60,
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
                      retryable: true,
                      rate_limit_action: 'otp_login',
                      rate_limit_limit: 10,
                      rate_limit_window_seconds: 60,
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
    '/auth/tenant/member-admin/provision-user': {
      post: {
        summary: 'Provision tenant member user by phone with default password policy',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'header',
            name: 'Idempotency-Key',
            required: false,
            description: '关键写幂等键；同键重复提交返回首次语义，同键不同载荷返回冲突',
            schema: IDEMPOTENCY_KEY_SCHEMA
          }
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ProvisionUserRequest' },
              examples: {
                create_or_reuse_tenant_user: {
                  value: {
                    phone: '13800000002',
                    tenant_name: 'Tenant A'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'User provisioned and tenant relationship created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ProvisionUserResponse' }
              }
            }
          },
          400: {
            description: 'Invalid payload',
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
                  },
                  invalid_idempotency_key: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: 'Idempotency-Key 必须为 1 到 128 个非空字符',
                      error_code: 'AUTH-400-IDEMPOTENCY-KEY-INVALID',
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
            description: 'Invalid access token',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          403: {
            description: 'Tenant route blocked due to missing tenant context or insufficient permission',
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
          409: {
            description: 'Duplicate relationship request conflict',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  duplicate_relationship_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '用户关系已存在，请勿重复提交',
                      error_code: 'AUTH-409-PROVISION-CONFLICT',
                      retryable: false,
                      request_id: 'request_id_unset'
                    }
                  },
                  idempotency_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '幂等键与请求载荷不一致，请更换 Idempotency-Key 后重试',
                      error_code: 'AUTH-409-IDEMPOTENCY-CONFLICT',
                      retryable: false,
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          503: {
            description: 'Default password secure config unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  default_password_config_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '默认密码配置不可用，请稍后重试',
                      error_code: 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE',
                      retryable: true,
                      degradation_reason: 'default-password-config-unavailable',
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
                      retryable: true,
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
    '/auth/platform/member-admin/provision-user': {
      post: {
        summary: 'Provision platform member user by phone with default password policy',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'header',
            name: 'Idempotency-Key',
            required: false,
            description: '关键写幂等键；同键重复提交返回首次语义，同键不同载荷返回冲突',
            schema: IDEMPOTENCY_KEY_SCHEMA
          }
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ProvisionPlatformUserRequest' },
              examples: {
                create_or_reuse_platform_user: {
                  value: {
                    phone: '13800000003'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'User provisioned and platform relationship created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ProvisionUserResponse' }
              }
            }
          },
          400: {
            description: 'Invalid payload',
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
                  },
                  invalid_idempotency_key: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: 'Idempotency-Key 必须为 1 到 128 个非空字符',
                      error_code: 'AUTH-400-IDEMPOTENCY-KEY-INVALID',
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
            description: 'Invalid access token',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          403: {
            description: 'Platform route blocked due to missing platform context or insufficient permission',
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
          409: {
            description: 'Duplicate relationship request conflict',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  duplicate_relationship_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '用户关系已存在，请勿重复提交',
                      error_code: 'AUTH-409-PROVISION-CONFLICT',
                      retryable: false,
                      request_id: 'request_id_unset'
                    }
                  },
                  idempotency_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '幂等键与请求载荷不一致，请更换 Idempotency-Key 后重试',
                      error_code: 'AUTH-409-IDEMPOTENCY-CONFLICT',
                      retryable: false,
                      request_id: 'request_id_unset'
                    }
                  }
                }
              }
            }
          },
          503: {
            description: 'Default password secure config unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  default_password_config_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '默认密码配置不可用，请稍后重试',
                      error_code: 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE',
                      retryable: true,
                      degradation_reason: 'default-password-config-unavailable',
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
    '/platform/orgs': {
      post: {
        summary: 'Create organization with required initial owner phone',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'header',
            name: 'Idempotency-Key',
            required: false,
            description: '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键',
            schema: IDEMPOTENCY_KEY_SCHEMA
          }
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreatePlatformOrgRequest' },
              examples: {
                create_org: {
                  value: {
                    org_name: '华东测试组织',
                    initial_owner_phone: '13800000011'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Organization and initial owner governance relationship created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CreatePlatformOrgResponse' }
              }
            }
          },
          400: {
            description: 'Missing required field or invalid payload',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  initial_owner_phone_required: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: '创建组织必须提供 initial_owner_phone',
                      error_code: 'ORG-400-INITIAL-OWNER-PHONE-REQUIRED',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  },
                  invalid_payload: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: '请求参数不完整或格式错误',
                      error_code: 'ORG-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  },
                  invalid_idempotency_key: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: 'Idempotency-Key 必须为 1 到 128 个非空字符',
                      error_code: 'AUTH-400-IDEMPOTENCY-KEY-INVALID',
                      request_id: 'request_id_unset',
                      retryable: false
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
                      request_id: 'request_id_unset',
                      retryable: false
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
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_access_token: {
                    value: {
                      type: 'about:blank',
                      title: 'Unauthorized',
                      status: 401,
                      detail: '当前会话无效，请重新登录',
                      error_code: 'AUTH-401-INVALID-ACCESS',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          403: {
            description: 'Current session lacks platform permission context',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  forbidden: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '当前操作无权限',
                      error_code: 'AUTH-403-FORBIDDEN',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Organization conflict or idempotency payload mismatch conflict',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  org_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '组织已存在或负责人关系已建立，请勿重复提交',
                      error_code: 'ORG-409-ORG-CONFLICT',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  },
                  idempotency_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '幂等键与请求载荷不一致，请更换 Idempotency-Key 后重试',
                      error_code: 'AUTH-409-IDEMPOTENCY-CONFLICT',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          503: {
            description: 'Organization governance dependency or idempotency storage is unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '组织治理依赖暂不可用，请稍后重试',
                      error_code: 'ORG-503-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      retryable: true
                    }
                  },
                  idempotency_store_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '幂等服务暂时不可用，请稍后重试',
                      error_code: 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      retryable: true,
                      degradation_reason: 'idempotency-store-unavailable'
                    }
                  },
                  idempotency_pending_timeout: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '幂等请求处理中，请稍后重试',
                      error_code: 'AUTH-503-IDEMPOTENCY-PENDING-TIMEOUT',
                      request_id: 'request_id_unset',
                      retryable: true,
                      degradation_reason: 'idempotency-pending-timeout'
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
        parameters: [
          {
            in: 'header',
            name: 'Idempotency-Key',
            required: false,
            description: '关键写幂等键；同键重复提交返回首次语义，同键不同载荷返回冲突',
            schema: IDEMPOTENCY_KEY_SCHEMA
          }
        ],
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
            description: 'Malformed payload, invalid role fact status, or invalid Idempotency-Key',
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
                  },
                  invalid_idempotency_key: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: 'Idempotency-Key 必须为 1 到 128 个非空字符',
                      error_code: 'AUTH-400-IDEMPOTENCY-KEY-INVALID',
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
          409: {
            description: 'Idempotency-Key payload mismatch conflict',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  idempotency_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '幂等键与请求载荷不一致，请更换 Idempotency-Key 后重试',
                      error_code: 'AUTH-409-IDEMPOTENCY-CONFLICT',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
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
          200: {
            description: 'db and redis are both connected',
            content: {
              'application/json': {
                schema: SMOKE_RESPONSE_SCHEMA
              }
            }
          },
          503: {
            description: 'at least one dependency is degraded',
            content: {
              'application/json': {
                schema: SMOKE_RESPONSE_SCHEMA
              }
            }
          }
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
      ProvisionPlatformUserRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['phone'],
        properties: {
          phone: {
            type: 'string',
            minLength: 11,
            maxLength: 11,
            pattern: '^1\\d{10}$',
            description: '手机号（11位）'
          }
        }
      },
      ProvisionUserRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['phone'],
        properties: {
          phone: {
            type: 'string',
            minLength: 11,
            maxLength: 11,
            pattern: '^1\\d{10}$',
            description: '手机号（11位）'
          },
          tenant_name: {
            type: 'string',
            nullable: true,
            maxLength: 128,
            pattern: '.*\\S.*',
            description: '可选，仅 tenant provision 接口使用'
          }
        }
      },
      ProvisionUserResponse: {
        type: 'object',
        required: [
          'user_id',
          'phone',
          'created_user',
          'reused_existing_user',
          'credential_initialized',
          'first_login_force_password_change',
          'entry_domain',
          'active_tenant_id',
          'request_id'
        ],
        properties: {
          user_id: { type: 'string' },
          phone: { type: 'string' },
          created_user: { type: 'boolean' },
          reused_existing_user: { type: 'boolean' },
          credential_initialized: { type: 'boolean' },
          first_login_force_password_change: { type: 'boolean', enum: [false] },
          entry_domain: { type: 'string', enum: ['platform', 'tenant'] },
          active_tenant_id: { type: 'string', nullable: true },
          request_id: { type: 'string' }
        }
      },
      CreatePlatformOrgRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['org_name', 'initial_owner_phone'],
        properties: {
          org_name: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$',
            description: '组织名称'
          },
          initial_owner_phone: {
            type: 'string',
            minLength: 11,
            maxLength: 11,
            pattern: '^1\\d{10}$',
            description: '初始负责人手机号（11位）'
          }
        }
      },
      CreatePlatformOrgResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'org_id',
          'owner_user_id',
          'created_owner_user',
          'reused_existing_user',
          'request_id'
        ],
        properties: {
          org_id: { type: 'string' },
          owner_user_id: { type: 'string' },
          created_owner_user: { type: 'boolean' },
          reused_existing_user: { type: 'boolean' },
          request_id: { type: 'string' }
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
        required: ['title', 'status', 'request_id', 'error_code', 'retryable'],
        properties: {
          type: { type: 'string' },
          title: { type: 'string' },
          status: { type: 'integer' },
          detail: { type: 'string' },
          request_id: { type: 'string' },
          error_code: { type: 'string' },
          retryable: { type: 'boolean' },
          degradation_reason: { type: 'string' },
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
  };
  return ensureProblemDetailsRetryableExamples(spec);
};

module.exports = { buildOpenApiSpec };
