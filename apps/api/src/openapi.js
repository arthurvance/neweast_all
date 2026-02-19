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
const PLATFORM_ROLE_ID_PATTERN = '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$';
const TENANT_MEMBERSHIP_ID_PATTERN = '^[^\\s\\x00-\\x1F\\x7F]{1,64}$';

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
            description: 'Invalid payload or invalid Idempotency-Key',
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
    '/tenant/members': {
      get: {
        summary: 'List tenant members under current active tenant context',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'query',
            name: 'page',
            required: false,
            description: '页码（从 1 开始，默认 1）',
            schema: { type: 'integer', minimum: 1, maximum: 100000, default: 1 }
          },
          {
            in: 'query',
            name: 'page_size',
            required: false,
            description: '每页条数（默认 50，最大 200）',
            schema: { type: 'integer', minimum: 1, maximum: 200, default: 50 }
          }
        ],
        responses: {
          200: {
            description: 'Tenant members listed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantMemberListResponse' }
              }
            }
          },
          400: {
            description: 'Invalid request parameters',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_query: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: 'page 必须为正整数',
                      error_code: 'AUTH-400-INVALID-PAYLOAD',
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
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  },
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
          404: {
            description: 'Tenant not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  org_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标组织不存在',
                      error_code: 'AUTH-404-ORG-NOT-FOUND',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Request conflict with tenant membership state',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  org_not_active: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '当前组织不可用',
                      error_code: 'AUTH-409-ORG-NOT-ACTIVE',
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
          503: {
            description: 'Tenant member dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '组织成员治理依赖暂不可用，请稍后重试',
                      error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      retryable: true
                    }
                  }
                }
              }
            }
          }
        }
      },
      post: {
        summary: 'Create tenant member by phone with identity reuse first',
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
              schema: { $ref: '#/components/schemas/TenantMemberCreateRequest' },
              examples: {
                create_member: {
                  value: {
                    phone: '13800000012'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Tenant member created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantMemberCreateResponse' }
              }
            }
          },
          400: {
            description: 'Invalid payload or invalid Idempotency-Key',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_payload: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: 'phone 格式错误',
                      error_code: 'AUTH-400-INVALID-PAYLOAD',
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
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  },
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
          404: {
            description: 'Tenant not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  org_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标组织不存在',
                      error_code: 'AUTH-404-ORG-NOT-FOUND',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Relationship conflict or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  relationship_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '用户关系已存在，请勿重复提交',
                      error_code: 'AUTH-409-PROVISION-CONFLICT',
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
          503: {
            description: 'Tenant member dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '组织成员治理依赖暂不可用，请稍后重试',
                      error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE',
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
                  }
                }
              }
            }
          }
        }
      }
    },
    '/tenant/members/{membership_id}/status': {
      patch: {
        summary: 'Update tenant member status (active|disabled|left)',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'membership_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: TENANT_MEMBERSHIP_ID_PATTERN
            },
            description: '成员关系主键'
          },
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
              schema: { $ref: '#/components/schemas/TenantMemberStatusUpdateRequest' },
              examples: {
                disable_member: {
                  value: {
                    status: 'disabled',
                    reason: '离职停用'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Tenant member status updated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantMemberStatusUpdateResponse' }
              }
            }
          },
          400: {
            description: 'Invalid payload or invalid Idempotency-Key',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_payload: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: 'membership_id 不能为空',
                      error_code: 'AUTH-400-INVALID-PAYLOAD',
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
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  },
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
          404: {
            description: 'Tenant membership not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  membership_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标成员关系不存在',
                      error_code: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Membership status conflict or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  status_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '成员状态冲突，请刷新后重试',
                      error_code: 'AUTH-409-PROVISION-CONFLICT',
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
          503: {
            description: 'Tenant member dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '组织成员治理依赖暂不可用，请稍后重试',
                      error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE',
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
            description: 'Invalid payload or invalid Idempotency-Key',
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
    '/platform/roles': {
      get: {
        summary: 'List platform role catalog',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Platform role catalog listed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformRoleListResponse' }
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
            description: 'Current session lacks platform permission context',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'Platform role governance dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '平台角色治理依赖暂不可用，请稍后重试',
                      error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      retryable: true
                    }
                  }
                }
              }
            }
          }
        }
      },
      post: {
        summary: 'Create platform role',
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
              schema: { $ref: '#/components/schemas/CreatePlatformRoleRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Platform role created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformRoleCatalogItem' }
              }
            }
          },
          400: {
            description: 'Invalid payload or invalid Idempotency-Key',
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
                      error_code: 'ROLE-400-INVALID-PAYLOAD',
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
          401: {
            description: 'Invalid access token',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          403: {
            description: 'Current session lacks platform permission context',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Role code/role_id conflict or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  role_code_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '角色编码冲突，请使用其他 code',
                      error_code: 'ROLE-409-CODE-CONFLICT',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  },
                  role_id_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '角色标识冲突，请使用其他 role_id',
                      error_code: 'ROLE-409-ROLE-ID-CONFLICT',
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
          413: {
            description: 'JSON payload exceeds allowed size',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'Platform role governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '平台角色治理依赖暂不可用，请稍后重试',
                      error_code: 'ROLE-503-DEPENDENCY-UNAVAILABLE',
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
                  }
                }
              }
            }
          }
        }
      }
    },
    '/platform/roles/{role_id}': {
      patch: {
        summary: 'Update platform role by role_id',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'role_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              pattern: PLATFORM_ROLE_ID_PATTERN
            }
          },
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
              schema: { $ref: '#/components/schemas/UpdatePlatformRoleRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Platform role updated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformRoleCatalogItem' }
              }
            }
          },
          400: {
            description: 'Invalid payload or invalid Idempotency-Key',
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
            description: 'Current session lacks permission or target role is protected',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  system_role_protected: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '受保护系统角色不允许编辑或删除',
                      error_code: 'ROLE-403-SYSTEM-ROLE-PROTECTED',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          404: {
            description: 'Role not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  role_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标平台角色不存在',
                      error_code: 'ROLE-404-ROLE-NOT-FOUND',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Role code conflict or idempotency payload mismatch',
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
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'Platform role governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      },
      delete: {
        summary: 'Delete platform role by role_id (soft delete)',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'role_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              pattern: PLATFORM_ROLE_ID_PATTERN
            }
          },
          {
            in: 'header',
            name: 'Idempotency-Key',
            required: false,
            description: '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键',
            schema: IDEMPOTENCY_KEY_SCHEMA
          }
        ],
        responses: {
          200: {
            description: 'Platform role soft deleted',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/DeletePlatformRoleResponse' }
              }
            }
          },
          400: {
            description: 'Invalid role_id or invalid Idempotency-Key',
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
            description: 'Current session lacks permission or target role is protected',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Role not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Idempotency payload mismatch conflict',
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
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'Platform role governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/platform/roles/{role_id}/permissions': {
      get: {
        summary: 'Get platform role permission grants by role_id',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'role_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              pattern: PLATFORM_ROLE_ID_PATTERN
            }
          }
        ],
        responses: {
          200: {
            description: 'Platform role permission grants fetched',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/PlatformRolePermissionGrantsReadResponse'
                }
              }
            }
          },
          400: {
            description: 'Invalid role_id',
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
            description: 'Current session lacks permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Role not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'Platform role permission dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      },
      put: {
        summary: 'Replace platform role permission grants by role_id',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'role_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              pattern: PLATFORM_ROLE_ID_PATTERN
            }
          },
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
              schema: {
                $ref: '#/components/schemas/ReplacePlatformRolePermissionGrantsRequest'
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Platform role permission grants replaced and affected snapshots resynced',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/PlatformRolePermissionGrantsWriteResponse'
                }
              }
            }
          },
          400: {
            description: 'Invalid payload or invalid Idempotency-Key',
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
            description: 'Current session lacks permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Role not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Idempotency payload mismatch conflict',
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
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'Platform role permission dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
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
    '/platform/orgs/status': {
      post: {
        summary: 'Update organization status (active|disabled, tenant-domain scoped)',
        description: '组织状态治理仅影响 tenant 域访问可用性；平台域（platform）访问不因该接口直接改变。',
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
              schema: { $ref: '#/components/schemas/UpdatePlatformOrgStatusRequest' },
              examples: {
                disable_org: {
                  value: {
                    org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                    status: 'disabled',
                    reason: '组织经营状态异常，平台临时禁用'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Organization status updated (or no-op). Only tenant-domain access is affected.',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UpdatePlatformOrgStatusResponse' }
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
          404: {
            description: 'Organization not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  org_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标组织不存在',
                      error_code: 'ORG-404-ORG-NOT-FOUND',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Idempotency payload mismatch conflict',
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
    '/platform/orgs/owner-transfer': {
      post: {
        summary: 'Submit organization owner-transfer request (entry + precheck only)',
        description: '仅交付发起入口与前置校验，不在本接口执行 owner 真正切换与自动接管。',
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
              schema: { $ref: '#/components/schemas/PlatformOrgOwnerTransferRequest' },
              examples: {
                submit_owner_transfer: {
                  value: {
                    org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                    new_owner_phone: '13800000062',
                    reason: '治理责任移交'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Owner-transfer request accepted for downstream orchestration.',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformOrgOwnerTransferResponse' }
              }
            }
          },
          400: {
            description: 'Invalid payload or invalid Idempotency-Key',
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
                      error_code: 'ORG-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset',
                      org_id: null,
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
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
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
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
                      org_id: null,
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
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
                      org_id: null,
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          404: {
            description: 'Organization or candidate owner not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  org_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标组织不存在',
                      error_code: 'ORG-404-ORG-NOT-FOUND',
                      request_id: 'request_id_unset',
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
                      retryable: false
                    }
                  },
                  new_owner_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '候选新负责人不存在',
                      error_code: 'ORG-404-NEW-OWNER-NOT-FOUND',
                      request_id: 'request_id_unset',
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Conflict from precheck, concurrent org transfer, or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  concurrent_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '组织负责人变更请求处理中，请稍后重试',
                      error_code: 'ORG-409-OWNER-TRANSFER-CONFLICT',
                      request_id: 'request_id_unset',
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'conflict',
                      retryable: true
                    }
                  },
                  org_not_active: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '目标组织当前不可发起负责人变更，请先启用后重试',
                      error_code: 'ORG-409-ORG-NOT-ACTIVE',
                      request_id: 'request_id_unset',
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
                      retryable: false
                    }
                  },
                  new_owner_inactive: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '候选新负责人状态不可用，请确认激活后重试',
                      error_code: 'ORG-409-NEW-OWNER-INACTIVE',
                      request_id: 'request_id_unset',
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
                      retryable: false
                    }
                  },
                  same_owner: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '新负责人不能与当前负责人相同',
                      error_code: 'ORG-409-OWNER-TRANSFER-SAME-OWNER',
                      request_id: 'request_id_unset',
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: 'owner-user-current',
                      new_owner_user_id: 'owner-user-current',
                      result_status: 'rejected',
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
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'conflict',
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
                      org_id: null,
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
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
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
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
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
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
                      org_id: 'f11e9c4b-8d5b-4e44-84df-cd5d0fc5f432',
                      old_owner_user_id: null,
                      new_owner_user_id: null,
                      result_status: 'rejected',
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
    '/platform/users': {
      post: {
        summary: 'Create or reuse platform user by phone',
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
              schema: { $ref: '#/components/schemas/CreatePlatformUserRequest' },
              examples: {
                create_user: {
                  value: {
                    phone: '13800000051'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Platform user created or reused',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/CreatePlatformUserResponse' }
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
            description: 'User provisioning conflict or idempotency payload mismatch conflict',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  provision_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '用户关系已存在，请勿重复提交',
                      error_code: 'AUTH-409-PROVISION-CONFLICT',
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
            description: 'User provisioning dependency or idempotency storage is unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '默认密码配置不可用，请稍后重试',
                      error_code: 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      retryable: true,
                      degradation_reason: 'default-password-config-unavailable'
                    }
                  },
                  governance_dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '平台用户治理依赖暂不可用，请稍后重试',
                      error_code: 'USR-503-DEPENDENCY-UNAVAILABLE',
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
    '/platform/users/status': {
      post: {
        summary: 'Update platform user status (active|disabled, platform-domain scoped)',
        description: '平台用户状态治理仅影响 platform 域访问可用性；组织域（tenant）访问不因该接口直接改变。',
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
              schema: { $ref: '#/components/schemas/UpdatePlatformUserStatusRequest' },
              examples: {
                disable_user: {
                  value: {
                    user_id: '88888888-8888-4888-8888-888888888888',
                    status: 'disabled',
                    reason: 'manual-governance'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Platform user status updated (or no-op). Only platform-domain access is affected.',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UpdatePlatformUserStatusResponse' }
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
                      error_code: 'USR-400-INVALID-PAYLOAD',
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
          404: {
            description: 'Target platform user not found or has no platform-domain access',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  user_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标平台用户不存在或无 platform 域访问',
                      error_code: 'USR-404-USER-NOT-FOUND',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Idempotency payload mismatch conflict',
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
            description: 'Platform user governance dependency or idempotency storage is unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '平台用户治理依赖暂不可用，请稍后重试',
                      error_code: 'USR-503-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      retryable: true
                    }
                  },
                  platform_snapshot_degraded: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '平台权限同步暂时不可用，请稍后重试',
                      error_code: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
                      request_id: 'request_id_unset',
                      retryable: true,
                      degradation_reason: 'db-deadlock'
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
      TenantMemberRecord: {
        type: 'object',
        additionalProperties: false,
        required: [
          'membership_id',
          'user_id',
          'tenant_id',
          'phone',
          'status'
        ],
        properties: {
          membership_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: TENANT_MEMBERSHIP_ID_PATTERN,
            description: '成员关系主键（跨故事稳定锚点）'
          },
          user_id: { type: 'string' },
          tenant_id: { type: 'string' },
          tenant_name: { type: 'string', nullable: true },
          phone: {
            type: 'string',
            minLength: 11,
            maxLength: 11,
            pattern: '^1\\d{10}$'
          },
          status: {
            type: 'string',
            enum: ['active', 'disabled', 'left']
          },
          joined_at: {
            type: 'string',
            format: 'date-time',
            nullable: true
          },
          left_at: {
            type: 'string',
            format: 'date-time',
            nullable: true
          }
        }
      },
      TenantMemberListResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['tenant_id', 'page', 'page_size', 'members', 'request_id'],
        properties: {
          tenant_id: { type: 'string' },
          page: { type: 'integer', minimum: 1 },
          page_size: { type: 'integer', minimum: 1, maximum: 200 },
          members: {
            type: 'array',
            items: { $ref: '#/components/schemas/TenantMemberRecord' }
          },
          request_id: { type: 'string' }
        }
      },
      TenantMemberCreateRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['phone'],
        properties: {
          phone: {
            type: 'string',
            minLength: 11,
            maxLength: 11,
            pattern: '^1\\d{10}$',
            description: '成员手机号（11位）'
          }
        }
      },
      TenantMemberCreateResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'membership_id',
          'user_id',
          'tenant_id',
          'status',
          'created_user',
          'reused_existing_user',
          'request_id'
        ],
        properties: {
          membership_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: TENANT_MEMBERSHIP_ID_PATTERN
          },
          user_id: { type: 'string' },
          tenant_id: { type: 'string' },
          status: {
            type: 'string',
            enum: ['active', 'disabled', 'left']
          },
          created_user: { type: 'boolean' },
          reused_existing_user: { type: 'boolean' },
          request_id: { type: 'string' }
        }
      },
      TenantMemberStatusUpdateRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['status'],
        properties: {
          status: {
            type: 'string',
            enum: ['active', 'enabled', 'disabled', 'left']
          },
          reason: {
            type: 'string',
            minLength: 1,
            maxLength: 256,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
          }
        }
      },
      TenantMemberStatusUpdateResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'membership_id',
          'user_id',
          'tenant_id',
          'previous_status',
          'current_status',
          'request_id'
        ],
        properties: {
          membership_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: TENANT_MEMBERSHIP_ID_PATTERN
          },
          user_id: { type: 'string' },
          tenant_id: { type: 'string' },
          previous_status: {
            type: 'string',
            enum: ['active', 'disabled', 'left']
          },
          current_status: {
            type: 'string',
            enum: ['active', 'disabled', 'left']
          },
          request_id: { type: 'string' }
        }
      },
      PlatformRoleCatalogItem: {
        type: 'object',
        additionalProperties: false,
        required: [
          'role_id',
          'code',
          'name',
          'status',
          'is_system',
          'created_at',
          'updated_at',
          'request_id'
        ],
        properties: {
          role_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_ROLE_ID_PATTERN
          },
          code: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '.*\\S.*'
          },
          name: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
          },
          status: {
            type: 'string',
            enum: ['active', 'disabled']
          },
          is_system: {
            type: 'boolean'
          },
          created_at: {
            type: 'string',
            format: 'date-time'
          },
          updated_at: {
            type: 'string',
            format: 'date-time'
          },
          request_id: { type: 'string' }
        }
      },
      PlatformRoleListResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['roles', 'request_id'],
        properties: {
          roles: {
            type: 'array',
            items: { $ref: '#/components/schemas/PlatformRoleCatalogItem' }
          },
          request_id: { type: 'string' }
        }
      },
      CreatePlatformRoleRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['role_id', 'code', 'name'],
        properties: {
          role_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_ROLE_ID_PATTERN
          },
          code: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '.*\\S.*'
          },
          name: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
          },
          status: {
            type: 'string',
            enum: ['active', 'disabled'],
            default: 'active'
          },
          is_system: {
            type: 'boolean',
            default: false
          }
        }
      },
      UpdatePlatformRoleRequest: {
        type: 'object',
        additionalProperties: false,
        properties: {
          code: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '.*\\S.*'
          },
          name: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
          },
          status: {
            type: 'string',
            enum: ['active', 'disabled']
          }
        }
      },
      DeletePlatformRoleResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['role_id', 'status', 'request_id'],
        properties: {
          role_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_ROLE_ID_PATTERN
          },
          status: {
            type: 'string',
            enum: ['active', 'disabled']
          },
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
      UpdatePlatformOrgStatusRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['org_id', 'status'],
        properties: {
          org_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$',
            description: '组织唯一标识'
          },
          status: {
            type: 'string',
            enum: ['active', 'disabled'],
            description: '目标组织状态（仅影响 tenant 域访问可用性，不影响 platform 域）'
          },
          reason: {
            type: 'string',
            minLength: 1,
            maxLength: 256,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$',
            description: '状态变更备注（可选）'
          }
        }
      },
      UpdatePlatformOrgStatusResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'org_id',
          'previous_status',
          'current_status',
          'request_id'
        ],
        properties: {
          org_id: { type: 'string' },
          previous_status: {
            type: 'string',
            enum: ['active', 'disabled'],
            description: '组织状态更新前值（tenant 域治理状态）'
          },
          current_status: {
            type: 'string',
            enum: ['active', 'disabled'],
            description: '组织状态更新后值（tenant 域治理状态）'
          },
          request_id: { type: 'string' }
        }
      },
      PlatformOrgOwnerTransferRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['org_id', 'new_owner_phone'],
        properties: {
          org_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^(?!.*\\s)[^\\x00-\\x1F\\x7F]+$',
            description: '组织唯一标识'
          },
          new_owner_phone: {
            type: 'string',
            minLength: 11,
            maxLength: 11,
            pattern: '^1\\d{10}$',
            description: '候选新负责人手机号（11位）'
          },
          reason: {
            type: 'string',
            minLength: 1,
            maxLength: 256,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]+$',
            description: '负责人变更发起原因（可选）'
          }
        }
      },
      PlatformOrgOwnerTransferResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'request_id',
          'org_id',
          'old_owner_user_id',
          'new_owner_user_id',
          'result_status',
          'error_code',
          'retryable'
        ],
        properties: {
          request_id: { type: 'string' },
          org_id: { type: 'string' },
          old_owner_user_id: { type: 'string' },
          new_owner_user_id: { type: 'string' },
          result_status: {
            type: 'string',
            enum: ['accepted', 'rejected', 'conflict']
          },
          error_code: { type: 'string' },
          retryable: { type: 'boolean' }
        }
      },
      CreatePlatformUserRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['phone'],
        properties: {
          phone: {
            type: 'string',
            minLength: 11,
            maxLength: 11,
            pattern: '^1\\d{10}$',
            description: '平台用户手机号（11位）'
          }
        }
      },
      CreatePlatformUserResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'user_id',
          'created_user',
          'reused_existing_user',
          'request_id'
        ],
        properties: {
          user_id: { type: 'string' },
          created_user: { type: 'boolean' },
          reused_existing_user: { type: 'boolean' },
          request_id: { type: 'string' }
        }
      },
      UpdatePlatformUserStatusRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['user_id', 'status'],
        properties: {
          user_id: {
            type: 'string',
            minLength: 1,
            pattern: '.*\\S.*',
            description: '用户唯一标识'
          },
          status: {
            type: 'string',
            enum: ['active', 'disabled', 'enabled'],
            description: '目标平台用户状态（仅影响 platform 域访问可用性，不影响 tenant 域）'
          },
          reason: {
            type: 'string',
            minLength: 1,
            maxLength: 256,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$',
            description: '状态变更备注（可选）'
          }
        }
      },
      UpdatePlatformUserStatusResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'user_id',
          'previous_status',
          'current_status',
          'request_id'
        ],
        properties: {
          user_id: { type: 'string' },
          previous_status: {
            type: 'string',
            enum: ['active', 'disabled'],
            description: '平台用户状态更新前值（platform 域治理状态）'
          },
          current_status: {
            type: 'string',
            enum: ['active', 'disabled'],
            description: '平台用户状态更新后值（platform 域治理状态）'
          },
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
            minItems: 1,
            maxItems: 5,
            uniqueItems: true,
            description: '最少 1 条、最多 5 条角色事实；服务端按 role_id（大小写不敏感）判重并拒绝重复',
            items: { $ref: '#/components/schemas/PlatformRoleFact' }
          }
        }
      },
      PlatformRoleFact: {
        type: 'object',
        additionalProperties: false,
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
            enum: ['active', 'enabled'],
            default: 'active'
          }
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
      ReplacePlatformRolePermissionGrantsRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['permission_codes'],
        properties: {
          permission_codes: {
            type: 'array',
            uniqueItems: true,
            maxItems: 64,
            description: '仅允许 platform.* 权限码，按大小写不敏感语义判重',
            items: {
              type: 'string',
              pattern: '^platform\\.[A-Za-z0-9._-]+$'
            }
          }
        }
      },
      PlatformRolePermissionGrantsReadResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'role_id',
          'permission_codes',
          'available_permission_codes',
          'request_id'
        ],
        properties: {
          role_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_ROLE_ID_PATTERN
          },
          permission_codes: {
            type: 'array',
            items: {
              type: 'string',
              pattern: '^platform\\.[A-Za-z0-9._-]+$'
            }
          },
          available_permission_codes: {
            type: 'array',
            items: {
              type: 'string',
              pattern: '^platform\\.[A-Za-z0-9._-]+$'
            }
          },
          request_id: { type: 'string' }
        }
      },
      PlatformRolePermissionGrantsWriteResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'role_id',
          'permission_codes',
          'available_permission_codes',
          'affected_user_count',
          'request_id'
        ],
        properties: {
          role_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_ROLE_ID_PATTERN
          },
          permission_codes: {
            type: 'array',
            items: {
              type: 'string',
              pattern: '^platform\\.[A-Za-z0-9._-]+$'
            }
          },
          available_permission_codes: {
            type: 'array',
            items: {
              type: 'string',
              pattern: '^platform\\.[A-Za-z0-9._-]+$'
            }
          },
          affected_user_count: {
            type: 'integer',
            minimum: 0
          },
          request_id: { type: 'string' }
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
