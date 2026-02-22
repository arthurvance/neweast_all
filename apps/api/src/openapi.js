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
const PLATFORM_INTEGRATION_ID_PATTERN = '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$';
const PLATFORM_INTEGRATION_CODE_PATTERN = '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$';
const PLATFORM_INTEGRATION_LIFECYCLE_ENUM = ['draft', 'active', 'paused', 'retired'];
const PLATFORM_INTEGRATION_DIRECTION_ENUM = ['inbound', 'outbound', 'bidirectional'];
const PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM = ['openapi', 'event'];
const PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM = [
  'candidate',
  'active',
  'deprecated',
  'retired'
];
const PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT_ENUM = [
  'compatible',
  'incompatible'
];
const PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM = [
  'pending',
  'retrying',
  'succeeded',
  'failed',
  'dlq',
  'replayed'
];
const PLATFORM_INTEGRATION_FREEZE_STATUS_ENUM = [
  'active',
  'released'
];
const PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN =
  '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$';
const PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN = '^[A-Fa-f0-9]{64}$';
const PLATFORM_INTEGRATION_RECOVERY_ID_PATTERN =
  '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$';
const PLATFORM_INTEGRATION_FREEZE_ID_PATTERN =
  '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$';
const TENANT_MEMBERSHIP_ID_PATTERN = '^[^\\s\\x00-\\x1F\\x7F]{1,64}$';
const PLATFORM_USER_ID_PATTERN = '^[^\\s\\x00-\\x1F\\x7F]+$';
const PLATFORM_USER_ID_MAX_LENGTH = 64;

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
    '/tenant/audit/events': {
      get: {
        summary: 'List tenant-domain audit events under current active tenant context',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'query',
            name: 'page',
            required: false,
            schema: { type: 'integer', minimum: 1, maximum: 100000, default: 1 }
          },
          {
            in: 'query',
            name: 'page_size',
            required: false,
            schema: { type: 'integer', minimum: 1, maximum: 200, default: 50 }
          },
          {
            in: 'query',
            name: 'from',
            required: false,
            schema: { type: 'string', format: 'date-time' }
          },
          {
            in: 'query',
            name: 'to',
            required: false,
            schema: { type: 'string', format: 'date-time' }
          },
          {
            in: 'query',
            name: 'event_type',
            required: false,
            schema: { type: 'string', maxLength: 128 }
          },
          {
            in: 'query',
            name: 'result',
            required: false,
            schema: {
              type: 'string',
              enum: ['success', 'rejected', 'failed']
            }
          },
          {
            in: 'query',
            name: 'request_id',
            required: false,
            schema: { type: 'string', maxLength: 128 }
          },
          {
            in: 'query',
            name: 'traceparent',
            required: false,
            schema: {
              type: 'string',
              maxLength: 128,
              pattern: '^[0-9a-fA-F]{2}-[0-9a-fA-F]{32}-[0-9a-fA-F]{16}-[0-9a-fA-F]{2}$'
            }
          },
          {
            in: 'query',
            name: 'actor_user_id',
            required: false,
            schema: { type: 'string', maxLength: 64 }
          },
          {
            in: 'query',
            name: 'target_type',
            required: false,
            schema: { type: 'string', maxLength: 64 }
          },
          {
            in: 'query',
            name: 'target_id',
            required: false,
            schema: { type: 'string', maxLength: 128 }
          }
        ],
        responses: {
          200: {
            description: 'Tenant-domain audit events listed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuditEventListResponse' }
              }
            }
          },
          400: {
            description: 'Invalid query parameters',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_query: {
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
          503: {
            description: 'Audit dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '审计依赖暂不可用，请稍后重试',
                      error_code: 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE',
                      retryable: true,
                      degradation_reason: 'audit-query-failed',
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
    '/tenant/members/{membership_id}': {
      get: {
        summary: 'Get tenant member profile detail by membership_id',
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
          }
        ],
        responses: {
          200: {
            description: 'Tenant member profile detail fetched',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantMemberDetailResponse' }
              }
            }
          },
          400: {
            description: 'Invalid membership_id',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_membership_id: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: 'membership_id 格式错误',
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
      }
    },
    '/tenant/members/{membership_id}/profile': {
      patch: {
        summary: 'Update tenant member profile by membership_id',
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
              schema: { $ref: '#/components/schemas/TenantMemberProfileUpdateRequest' },
              examples: {
                update_profile: {
                  value: {
                    display_name: '成员乙',
                    department_name: '产品部'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Tenant member profile updated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantMemberDetailResponse' }
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
                      detail: 'display_name 为必填字段',
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
    '/tenant/members/{membership_id}/roles': {
      get: {
        summary: 'Get tenant member role bindings by membership_id',
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
          }
        ],
        responses: {
          200: {
            description: 'Tenant member role bindings fetched',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantMemberRoleBindingsResponse' }
              }
            }
          },
          400: {
            description: 'Invalid membership_id',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_membership_id: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: 'membership_id 格式错误',
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
      put: {
        summary: 'Replace tenant member role bindings by membership_id',
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
            description: '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键',
            schema: IDEMPOTENCY_KEY_SCHEMA
          }
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ReplaceTenantMemberRoleBindingsRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Tenant member role bindings replaced and snapshot synced',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantMemberRoleBindingsResponse' }
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
                      detail: 'role_ids 数量必须在 1 到 5 之间',
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
            description: 'Tenant membership or role not found',
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
                  },
                  role_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标角色不存在',
                      error_code: 'AUTH-404-ROLE-NOT-FOUND',
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
            description: 'Tenant member dependency or idempotency storage unavailable',
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
    '/tenant/roles': {
      get: {
        summary: 'List tenant role catalog under current active tenant context',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Tenant role catalog listed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantRoleListResponse' }
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
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'Tenant role governance dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '组织角色治理依赖暂不可用，请稍后重试',
                      error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE',
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
        summary: 'Create tenant role',
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
              schema: { $ref: '#/components/schemas/CreateTenantRoleRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Tenant role created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantRoleCatalogItem' }
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
            description: 'Tenant route blocked due to missing tenant context or insufficient permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  system_role_protected: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '受保护系统角色定义不允许创建、编辑或删除',
                      error_code: 'TROLE-403-SYSTEM-ROLE-PROTECTED',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Tenant role conflict or idempotency payload mismatch',
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
            description: 'Tenant role governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/tenant/roles/{role_id}': {
      patch: {
        summary: 'Update tenant role by role_id',
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
              schema: { $ref: '#/components/schemas/UpdateTenantRoleRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Tenant role updated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/TenantRoleCatalogItem' }
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
            description: 'Tenant route blocked due to missing tenant context, insufficient permission, or protected role constraint',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  system_role_protected: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '受保护系统角色定义不允许创建、编辑或删除',
                      error_code: 'TROLE-403-SYSTEM-ROLE-PROTECTED',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          404: {
            description: 'Tenant role not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Tenant role conflict or idempotency payload mismatch',
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
            description: 'Tenant role governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      },
      delete: {
        summary: 'Delete tenant role by role_id (soft delete)',
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
            description: 'Tenant role soft deleted',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/DeleteTenantRoleResponse' }
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
            description: 'Tenant route blocked due to missing tenant context, insufficient permission, or protected role constraint',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  system_role_protected: {
                    value: {
                      type: 'about:blank',
                      title: 'Forbidden',
                      status: 403,
                      detail: '受保护系统角色定义不允许创建、编辑或删除',
                      error_code: 'TROLE-403-SYSTEM-ROLE-PROTECTED',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          404: {
            description: 'Tenant role not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Tenant role deletion precondition conflict or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  delete_condition_not_met: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '禁用状态角色不允许删除',
                      error_code: 'TROLE-409-DELETE-CONDITION-NOT-MET',
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
            description: 'Tenant role governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/tenant/roles/{role_id}/permissions': {
      get: {
        summary: 'Get tenant role permission grants by role_id',
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
            description: 'Tenant role permission grants fetched',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/TenantRolePermissionGrantsReadResponse'
                },
                examples: {
                  final_authorization_read: {
                    value: {
                      role_id: 'tenant_permission_target',
                      permission_codes: [
                        'tenant.billing.operate',
                        'tenant.member_admin.operate'
                      ],
                      available_permission_codes: [
                        'tenant.billing.operate',
                        'tenant.billing.view',
                        'tenant.member_admin.operate',
                        'tenant.member_admin.view'
                      ],
                      request_id: 'req-tenant-role-permission-read'
                    }
                  }
                }
              }
            }
          },
          400: {
            description: 'Invalid role_id',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_role_id: {
                    value: {
                      type: 'about:blank',
                      title: 'Bad Request',
                      status: 400,
                      detail: 'role_id 不能为空',
                      error_code: 'TROLE-400-INVALID-PAYLOAD',
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
            description: 'Current session lacks permission',
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
                      detail: '目标角色不存在',
                      error_code: 'TROLE-404-ROLE-NOT-FOUND',
                      request_id: 'request_id_unset',
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          503: {
            description: 'Tenant role permission dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '组织角色治理依赖暂不可用，请稍后重试',
                      error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE',
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
      put: {
        summary: 'Replace tenant role permission grants by role_id',
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
                $ref: '#/components/schemas/ReplaceTenantRolePermissionGrantsRequest'
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Tenant role permission grants replaced and affected snapshots resynced',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/TenantRolePermissionGrantsWriteResponse'
                },
                examples: {
                  final_authorization_write: {
                    value: {
                      role_id: 'tenant_permission_target',
                      permission_codes: [
                        'tenant.billing.operate',
                        'tenant.member_admin.operate'
                      ],
                      available_permission_codes: [
                        'tenant.billing.operate',
                        'tenant.billing.view',
                        'tenant.member_admin.operate',
                        'tenant.member_admin.view'
                      ],
                      affected_user_count: 2,
                      request_id: 'req-tenant-role-permission-write'
                    }
                  }
                }
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
                      detail: 'permission_codes 不能包含前后空白字符',
                      error_code: 'TROLE-400-INVALID-PAYLOAD',
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
            description: 'Current session lacks permission',
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
                      detail: '目标角色不存在',
                      error_code: 'TROLE-404-ROLE-NOT-FOUND',
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
            description: 'Tenant role permission dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '组织角色治理依赖暂不可用，请稍后重试',
                      error_code: 'TROLE-503-DEPENDENCY-UNAVAILABLE',
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
    '/platform/audit/events': {
      get: {
        summary: 'List platform-domain audit events with optional tenant filter',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'query',
            name: 'page',
            required: false,
            schema: { type: 'integer', minimum: 1, maximum: 100000, default: 1 }
          },
          {
            in: 'query',
            name: 'page_size',
            required: false,
            schema: { type: 'integer', minimum: 1, maximum: 200, default: 50 }
          },
          {
            in: 'query',
            name: 'from',
            required: false,
            schema: { type: 'string', format: 'date-time' }
          },
          {
            in: 'query',
            name: 'to',
            required: false,
            schema: { type: 'string', format: 'date-time' }
          },
          {
            in: 'query',
            name: 'event_type',
            required: false,
            schema: { type: 'string', maxLength: 128 }
          },
          {
            in: 'query',
            name: 'result',
            required: false,
            schema: {
              type: 'string',
              enum: ['success', 'rejected', 'failed']
            }
          },
          {
            in: 'query',
            name: 'request_id',
            required: false,
            schema: { type: 'string', maxLength: 128 }
          },
          {
            in: 'query',
            name: 'traceparent',
            required: false,
            schema: {
              type: 'string',
              maxLength: 128,
              pattern: '^[0-9a-fA-F]{2}-[0-9a-fA-F]{32}-[0-9a-fA-F]{16}-[0-9a-fA-F]{2}$'
            }
          },
          {
            in: 'query',
            name: 'actor_user_id',
            required: false,
            schema: { type: 'string', maxLength: 64 }
          },
          {
            in: 'query',
            name: 'target_type',
            required: false,
            schema: { type: 'string', maxLength: 64 }
          },
          {
            in: 'query',
            name: 'target_id',
            required: false,
            schema: { type: 'string', maxLength: 128 }
          },
          {
            in: 'query',
            name: 'tenant_id',
            required: false,
            schema: { type: 'string', maxLength: 64 }
          }
        ],
        responses: {
          200: {
            description: 'Platform-domain audit events listed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuditEventListResponse' }
              }
            }
          },
          400: {
            description: 'Invalid query parameters',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  invalid_query: {
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
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
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
            description: 'Audit dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '审计依赖暂不可用，请稍后重试',
                      error_code: 'AUTH-503-AUDIT-DEPENDENCY-UNAVAILABLE',
                      retryable: true,
                      degradation_reason: 'audit-query-failed',
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
                },
                examples: {
                  final_authorization_read: {
                    value: {
                      role_id: 'platform_permission_editor',
                      permission_codes: [
                        'platform.billing.operate',
                        'platform.member_admin.operate'
                      ],
                      available_permission_codes: [
                        'platform.billing.operate',
                        'platform.billing.view',
                        'platform.member_admin.operate',
                        'platform.member_admin.view',
                        'platform.system_config.operate',
                        'platform.system_config.view'
                      ],
                      request_id: 'req-platform-role-permission-read'
                    }
                  }
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
                },
                examples: {
                  final_authorization_write: {
                    value: {
                      role_id: 'platform_permission_editor',
                      permission_codes: [
                        'platform.billing.operate',
                        'platform.member_admin.operate'
                      ],
                      available_permission_codes: [
                        'platform.billing.operate',
                        'platform.billing.view',
                        'platform.member_admin.operate',
                        'platform.member_admin.view',
                        'platform.system_config.operate',
                        'platform.system_config.view'
                      ],
                      affected_user_count: 3,
                      request_id: 'req-platform-role-permission-write'
                    }
                  }
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
        summary: 'Submit organization owner-transfer request and complete takeover convergence',
        description: '完成负责人变更事务提交，并在同一链路内收敛新负责人成员关系、角色绑定与最小治理权限。',
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
            description: 'Owner-transfer request accepted with takeover transaction committed.',
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
    '/platform/system-configs/{config_key}': {
      get: {
        summary: 'Get platform controlled sensitive config metadata by key',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'config_key',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 128,
              pattern: '^auth\\.[A-Za-z0-9._-]+$'
            }
          }
        ],
        responses: {
          200: {
            description: 'Controlled config metadata fetched',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SystemConfigReadResponse' }
              }
            }
          },
          400: {
            description: 'Invalid config key',
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
            description: 'Current session lacks system config read permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Config not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'System config dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      },
      put: {
        summary: 'Update platform controlled sensitive config with optimistic concurrency',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'config_key',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 128,
              pattern: '^auth\\.[A-Za-z0-9._-]+$'
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
              schema: { $ref: '#/components/schemas/UpdateSystemConfigRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Controlled config updated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/UpdateSystemConfigResponse' }
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
            description: 'Current session lacks system config update permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Config not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Version conflict or idempotency payload mismatch',
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
            description: 'System config dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/platform/integrations': {
      get: {
        summary: 'List platform integration catalog with filters',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'query',
            name: 'page',
            required: false,
            schema: {
              type: 'integer',
              minimum: 1,
              default: 1
            }
          },
          {
            in: 'query',
            name: 'page_size',
            required: false,
            schema: {
              type: 'integer',
              minimum: 1,
              maximum: 100,
              default: 20
            }
          },
          {
            in: 'query',
            name: 'direction',
            required: false,
            schema: {
              type: 'string',
              enum: PLATFORM_INTEGRATION_DIRECTION_ENUM
            }
          },
          {
            in: 'query',
            name: 'protocol',
            required: false,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$'
            }
          },
          {
            in: 'query',
            name: 'auth_mode',
            required: false,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$'
            }
          },
          {
            in: 'query',
            name: 'lifecycle_status',
            required: false,
            schema: {
              type: 'string',
              enum: PLATFORM_INTEGRATION_LIFECYCLE_ENUM
            }
          },
          {
            in: 'query',
            name: 'keyword',
            required: false,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 128,
              pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
            }
          }
        ],
        responses: {
          200: {
            description: 'Integration catalog listed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformIntegrationCatalogListResponse' }
              }
            }
          },
          400: {
            description: 'Invalid query filters',
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
                      error_code: 'INT-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset',
                      traceparent: null,
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
            description: 'Current session lacks required permission',
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
                      traceparent: null,
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          503: {
            description: 'Integration catalog dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '集成目录治理依赖暂不可用，请稍后重试',
                      error_code: 'INT-503-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: true,
                      degradation_reason: 'dependency-unavailable'
                    }
                  }
                }
              }
            }
          }
        }
      },
      post: {
        summary: 'Create platform integration catalog entry',
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
              schema: { $ref: '#/components/schemas/CreatePlatformIntegrationRequest' },
              examples: {
                create_integration: {
                  value: {
                    integration_id: 'erp-outbound-main',
                    code: 'ERP_OUTBOUND_MAIN',
                    name: 'ERP 出站主通道',
                    direction: 'outbound',
                    protocol: 'https',
                    auth_mode: 'hmac',
                    endpoint: '/orders/sync',
                    base_url: 'https://erp.example.com/api',
                    timeout_ms: 8000,
                    retry_policy: {
                      max_attempts: 3,
                      backoff_ms: 500
                    },
                    idempotency_policy: {
                      key_from: 'order_id'
                    },
                    version_strategy: 'header:x-api-version',
                    runbook_url: 'https://runbook.example.com/integration/erp',
                    lifecycle_status: 'draft',
                    lifecycle_reason: '首次接入'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Integration catalog entry created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformIntegrationCatalogItem' }
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
                      error_code: 'INT-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset',
                      traceparent: null,
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
                      traceparent: null,
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Duplicate integration code/id or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  code_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '集成编码冲突，请使用其他 code',
                      error_code: 'INT-409-CODE-CONFLICT',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false
                    }
                  },
                  integration_id_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '集成标识冲突，请重试创建流程',
                      error_code: 'INT-409-INTEGRATION-ID-CONFLICT',
                      request_id: 'request_id_unset',
                      traceparent: null,
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
                      traceparent: null,
                      retryable: false
                    }
                  },
                  freeze_blocked: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '发布冻结窗口生效，当前集成变更操作已阻断',
                      error_code: 'INT-409-INTEGRATION-FREEZE-BLOCKED',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      freeze_id: 'release-window-2026-02-22',
                      frozen_at: '2026-02-22T09:00:00.000Z'
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
                      traceparent: null,
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          503: {
            description: 'Integration catalog dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '集成目录治理依赖暂不可用，请稍后重试',
                      error_code: 'INT-503-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: true,
                      degradation_reason: 'dependency-unavailable'
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
                      traceparent: null,
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
                      traceparent: null,
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
    '/platform/integrations/{integration_id}': {
      get: {
        summary: 'Get platform integration catalog entry detail',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'integration_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_ID_PATTERN
            }
          }
        ],
        responses: {
          200: {
            description: 'Integration catalog entry loaded',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformIntegrationCatalogItem' }
              }
            }
          },
          400: {
            description: 'Invalid integration_id',
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Integration catalog entry not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标集成目录不存在',
                      error_code: 'INT-404-NOT-FOUND',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          503: {
            description: 'Integration catalog dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      },
      patch: {
        summary: 'Update platform integration catalog entry',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'integration_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_ID_PATTERN
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
              schema: { $ref: '#/components/schemas/UpdatePlatformIntegrationRequest' }
            }
          }
        },
        responses: {
          200: {
            description: 'Integration catalog entry updated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformIntegrationCatalogItem' }
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Integration catalog entry not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Conflict on integration code or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  code_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '集成编码冲突，请使用其他 code',
                      error_code: 'INT-409-CODE-CONFLICT',
                      request_id: 'request_id_unset',
                      traceparent: null,
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
                      traceparent: null,
                      retryable: false
                    }
                  },
                  freeze_blocked: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '发布冻结窗口生效，当前集成变更操作已阻断',
                      error_code: 'INT-409-INTEGRATION-FREEZE-BLOCKED',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      freeze_id: 'release-window-2026-02-22',
                      frozen_at: '2026-02-22T09:00:00.000Z'
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
            description: 'Integration catalog dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/platform/integrations/{integration_id}/lifecycle': {
      post: {
        summary: 'Change platform integration lifecycle status',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'integration_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_ID_PATTERN
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
              schema: { $ref: '#/components/schemas/ChangePlatformIntegrationLifecycleRequest' },
              examples: {
                activate: {
                  value: {
                    status: 'active',
                    reason: '完成联调，开启流量'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Integration lifecycle changed',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ChangePlatformIntegrationLifecycleResponse'
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Integration catalog entry not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Lifecycle transition conflict or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  lifecycle_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '生命周期状态流转冲突',
                      error_code: 'INT-409-LIFECYCLE-CONFLICT',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      previous_status: 'retired',
                      requested_status: 'active'
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
                      traceparent: null,
                      retryable: false
                    }
                  },
                  freeze_blocked: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '发布冻结窗口生效，当前集成变更操作已阻断',
                      error_code: 'INT-409-INTEGRATION-FREEZE-BLOCKED',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      freeze_id: 'release-window-2026-02-22',
                      frozen_at: '2026-02-22T09:00:00.000Z'
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
            description: 'Integration catalog dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '集成目录治理依赖暂不可用，请稍后重试',
                      error_code: 'INT-503-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: true,
                      degradation_reason: 'dependency-unavailable'
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
                      traceparent: null,
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
    '/platform/integrations/{integration_id}/contracts': {
      get: {
        summary: 'List platform integration contract versions',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'integration_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_ID_PATTERN
            }
          },
          {
            in: 'query',
            name: 'contract_type',
            required: false,
            schema: {
              type: 'string',
              enum: PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM
            }
          },
          {
            in: 'query',
            name: 'status',
            required: false,
            schema: {
              type: 'string',
              enum: PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM
            }
          }
        ],
        responses: {
          200: {
            description: 'Contract versions listed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformIntegrationContractListResponse' }
              }
            }
          },
          400: {
            description: 'Invalid integration_id or query filters',
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Integration catalog entry not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'Contract governance dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      },
      post: {
        summary: 'Create platform integration contract version',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'integration_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_ID_PATTERN
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
              schema: { $ref: '#/components/schemas/CreatePlatformIntegrationContractRequest' },
              examples: {
                create_contract: {
                  value: {
                    contract_type: 'openapi',
                    contract_version: 'v2026.02.22',
                    schema_ref: 's3://contracts/erp/v2026.02.22/openapi.json',
                    schema_checksum: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    status: 'candidate',
                    is_backward_compatible: true,
                    compatibility_notes: '新增可选字段，不影响旧调用方'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Contract version created',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformIntegrationContractItem' }
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Integration catalog entry not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Contract version conflict or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  version_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '契约版本冲突，请调整 contract_version 后重试',
                      error_code: 'integration_contract_conflict',
                      request_id: 'request_id_unset',
                      traceparent: null,
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
                      traceparent: null,
                      retryable: false
                    }
                  },
                  freeze_blocked: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '发布冻结窗口生效，当前契约变更操作已阻断',
                      error_code: 'INT-409-INTEGRATION-FREEZE-BLOCKED',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      freeze_id: 'release-window-2026-02-22',
                      frozen_at: '2026-02-22T09:00:00.000Z'
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
            description: 'Contract governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/platform/integrations/{integration_id}/contracts/compatibility-check': {
      post: {
        summary: 'Evaluate compatibility between baseline and candidate contract versions',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'integration_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_ID_PATTERN
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
                $ref: '#/components/schemas/EvaluatePlatformIntegrationContractCompatibilityRequest'
              },
              examples: {
                evaluate: {
                  value: {
                    contract_type: 'openapi',
                    baseline_version: 'v2026.01.15',
                    candidate_version: 'v2026.02.22',
                    diff_summary: {
                      breaking_changes: []
                    }
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Compatibility evaluated',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/PlatformIntegrationContractCompatibilityCheckResponse'
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Integration or contract version not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  contract_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标契约版本不存在',
                      error_code: 'integration_contract_not_found',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Idempotency payload mismatch',
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
            description: 'Contract governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/platform/integrations/{integration_id}/contracts/consistency-check': {
      post: {
        summary: 'Check release-gate consistency using latest compatibility evaluation result',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'integration_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_ID_PATTERN
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
                $ref: '#/components/schemas/CheckPlatformIntegrationContractConsistencyRequest'
              },
              examples: {
                check_consistency: {
                  value: {
                    contract_type: 'openapi',
                    baseline_version: 'v2026.01.15',
                    candidate_version: 'v2026.02.22'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Consistency check passed',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/PlatformIntegrationContractConsistencyCheckResponse'
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Integration or contract version not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Consistency blocked or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  blocked_missing_latest_check: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '契约一致性校验未通过，发布已阻断',
                      error_code: 'integration_contract_consistency_blocked',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      check_result: 'blocked',
                      blocking: true,
                      failure_reason: 'missing_latest_compatibility_check',
                      baseline_version: 'v2026.01.15',
                      candidate_version: 'v2026.02.22'
                    }
                  },
                  blocked_incompatible: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '契约一致性校验未通过，发布已阻断',
                      error_code: 'integration_contract_consistency_blocked',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      check_result: 'blocked',
                      blocking: true,
                      failure_reason: 'latest_compatibility_incompatible',
                      baseline_version: 'v2026.01.15',
                      candidate_version: 'v2026.02.22',
                      breaking_change_count: 2,
                      diff_summary: {
                        breaking_changes: [
                          'remove field customer_id',
                          'rename field total_amount'
                        ]
                      }
                    }
                  },
                  blocked_baseline_mismatch: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '契约一致性校验未通过，发布已阻断',
                      error_code: 'integration_contract_consistency_blocked',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      check_result: 'blocked',
                      blocking: true,
                      failure_reason: 'baseline_version_mismatch',
                      baseline_version: 'v2026.01.15',
                      candidate_version: 'v2026.03.01',
                      diff_summary: {
                        expected_active_baseline_version: 'v2026.02.22',
                        requested_baseline_version: 'v2026.01.15'
                      }
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
            description: 'Contract governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_malformed: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '契约治理依赖暂不可用，请稍后重试',
                      error_code: 'INT-503-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: true,
                      degradation_reason:
                        'integration-contract-consistency-check-read-result-malformed'
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    '/platform/integrations/{integration_id}/contracts/{contract_version}/activate': {
      post: {
        summary: 'Activate contract version after compatibility validation',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'integration_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_ID_PATTERN
            }
          },
          {
            in: 'path',
            name: 'contract_version',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
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
                $ref: '#/components/schemas/ActivatePlatformIntegrationContractRequest'
              },
              examples: {
                activate: {
                  value: {
                    contract_type: 'openapi',
                    baseline_version: 'v2026.01.15'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Contract activated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ActivatePlatformIntegrationContractResponse' }
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Integration or contract version not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  contract_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标契约版本不存在',
                      error_code: 'integration_contract_not_found',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Activation blocked or incompatible contract version or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  incompatible: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '候选版本与基线版本不兼容，禁止激活',
                      error_code: 'integration_contract_incompatible',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false
                    }
                  },
                  activation_blocked: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '契约版本激活被阻断',
                      error_code: 'integration_contract_activation_blocked',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false
                    }
                  },
                  freeze_blocked: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '发布冻结窗口生效，当前契约变更操作已阻断',
                      error_code: 'INT-409-INTEGRATION-FREEZE-BLOCKED',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      freeze_id: 'release-window-2026-02-22',
                      frozen_at: '2026-02-22T09:00:00.000Z'
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
            description: 'Contract governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/platform/integrations/{integration_id}/recovery/queue': {
      get: {
        summary: 'List platform integration retry-recovery queue items',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'integration_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_ID_PATTERN
            }
          },
          {
            in: 'query',
            name: 'status',
            required: false,
            schema: {
              type: 'string',
              enum: PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM
            }
          },
          {
            in: 'query',
            name: 'limit',
            required: false,
            schema: {
              type: 'integer',
              minimum: 1,
              maximum: 200,
              default: 50
            }
          }
        ],
        responses: {
          200: {
            description: 'Recovery queue listed',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/PlatformIntegrationRecoveryQueueListResponse'
                }
              }
            }
          },
          400: {
            description: 'Invalid integration_id or query filters',
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
                      error_code: 'INT-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset',
                      traceparent: null,
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Integration catalog entry not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  integration_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标集成目录不存在',
                      error_code: 'INT-404-NOT-FOUND',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          503: {
            description: 'Recovery governance dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '集成恢复治理依赖暂不可用，请稍后重试',
                      error_code: 'INT-503-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: true,
                      degradation_reason: 'dependency-unavailable'
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    '/platform/integrations/{integration_id}/recovery/queue/{recovery_id}/replay': {
      post: {
        summary: 'Replay a failed or DLQ platform integration recovery queue item',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'integration_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_ID_PATTERN
            }
          },
          {
            in: 'path',
            name: 'recovery_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_INTEGRATION_RECOVERY_ID_PATTERN
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
          required: false,
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ReplayPlatformIntegrationRecoveryRequest'
              },
              examples: {
                replay: {
                  value: {
                    reason: 'manual replay after downstream rollback'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Recovery queue replay accepted',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/PlatformIntegrationRecoveryReplayResponse'
                }
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
                      error_code: 'INT-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset',
                      traceparent: null,
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          404: {
            description: 'Integration or recovery queue entry not found',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  integration_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标集成目录不存在',
                      error_code: 'INT-404-NOT-FOUND',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false
                    }
                  },
                  recovery_not_found: {
                    value: {
                      type: 'about:blank',
                      title: 'Not Found',
                      status: 404,
                      detail: '目标恢复队列项不存在',
                      error_code: 'INT-404-RECOVERY-NOT-FOUND',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false
                    }
                  }
                }
              }
            }
          },
          409: {
            description: 'Replay status conflict or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  replay_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '恢复队列状态冲突，当前不可重放',
                      error_code: 'INT-409-RECOVERY-REPLAY-CONFLICT',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      previous_status: 'succeeded',
                      requested_status: 'replayed'
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
            description: 'Recovery governance dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '集成恢复治理依赖暂不可用，请稍后重试',
                      error_code: 'INT-503-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: true,
                      degradation_reason: 'dependency-unavailable'
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    '/platform/integrations/freeze': {
      get: {
        summary: 'Get platform integration freeze status and latest freeze window',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Freeze status loaded',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/PlatformIntegrationFreezeStatusResponse'
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          503: {
            description: 'Freeze governance dependency unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  dependency_unavailable: {
                    value: {
                      type: 'about:blank',
                      title: 'Service Unavailable',
                      status: 503,
                      detail: '集成冻结治理依赖暂不可用，请稍后重试',
                      error_code: 'INT-503-DEPENDENCY-UNAVAILABLE',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: true,
                      degradation_reason: 'dependency-unavailable'
                    }
                  }
                }
              }
            }
          }
        }
      },
      post: {
        summary: 'Activate platform integration freeze window',
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
              schema: {
                $ref: '#/components/schemas/ActivatePlatformIntegrationFreezeRequest'
              },
              examples: {
                activate_freeze: {
                  value: {
                    freeze_id: 'release-window-2026-02-22',
                    freeze_reason: 'production release window opened'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Freeze window activated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformIntegrationFreezeWindow' }
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
                      error_code: 'INT-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset',
                      traceparent: null,
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'Freeze already active or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  freeze_already_active: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '集成清单已处于冻结窗口，请先解冻后再重复冻结',
                      error_code: 'INT-409-INTEGRATION-FREEZE-ACTIVE',
                      request_id: 'request_id_unset',
                      traceparent: null,
                      retryable: false,
                      freeze_id: 'release-window-2026-02-22',
                      frozen_at: '2026-02-22T00:00:00.000Z'
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
            description: 'Freeze governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/platform/integrations/freeze/release': {
      post: {
        summary: 'Release current platform integration freeze window',
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
          required: false,
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ReleasePlatformIntegrationFreezeRequest'
              },
              examples: {
                release_freeze: {
                  value: {
                    rollback_reason: 'release validation completed'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: {
            description: 'Freeze window released',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/PlatformIntegrationFreezeReleaseResponse'
                }
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
                      error_code: 'INT-400-INVALID-PAYLOAD',
                      request_id: 'request_id_unset',
                      traceparent: null,
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
            description: 'Current session lacks required permission',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          },
          409: {
            description: 'No active freeze window or idempotency payload mismatch',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' },
                examples: {
                  release_conflict: {
                    value: {
                      type: 'about:blank',
                      title: 'Conflict',
                      status: 409,
                      detail: '当前不存在 active 冻结窗口，无法执行解冻',
                      error_code: 'INT-409-INTEGRATION-FREEZE-RELEASE-CONFLICT',
                      request_id: 'request_id_unset',
                      traceparent: null,
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
            description: 'Freeze governance dependency or idempotency storage unavailable',
            content: {
              'application/problem+json': {
                schema: { $ref: '#/components/schemas/ProblemDetails' }
              }
            }
          }
        }
      }
    },
    '/platform/users': {
      get: {
        summary: 'List platform users with filters and pagination',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'query',
            name: 'page',
            required: false,
            schema: {
              type: 'integer',
              minimum: 1,
              default: 1
            }
          },
          {
            in: 'query',
            name: 'page_size',
            required: false,
            schema: {
              type: 'integer',
              minimum: 1,
              maximum: 100,
              default: 20
            }
          },
          {
            in: 'query',
            name: 'status',
            required: false,
            schema: {
              type: 'string',
              enum: ['active', 'disabled']
            }
          },
          {
            in: 'query',
            name: 'keyword',
            required: false,
            schema: {
              type: 'string',
              maxLength: 64
            }
          }
        ],
        responses: {
          200: {
            description: 'Platform users listed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformUserListResponse' }
              }
            }
          },
          400: {
            description: 'Invalid query filters',
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
          503: {
            description: 'Platform user governance dependency unavailable',
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
                  }
                }
              }
            }
          }
        }
      },
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
    '/platform/users/{user_id}': {
      get: {
        summary: 'Get platform user detail',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'user_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: PLATFORM_USER_ID_MAX_LENGTH,
              pattern: PLATFORM_USER_ID_PATTERN
            }
          }
        ],
        responses: {
          200: {
            description: 'Platform user detail loaded',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlatformUserDetailResponse' }
              }
            }
          },
          400: {
            description: 'Invalid user_id path parameter',
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
          503: {
            description: 'Platform user governance dependency unavailable',
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
                  }
                }
              }
            }
          }
        }
      },
      delete: {
        summary: 'Soft-delete platform user and revoke all sessions',
        description: '平台用户软删除后，撤销该用户在 platform/tenant 域的全部活跃会话与 refresh token；重复执行保持幂等语义。',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'user_id',
            required: true,
            schema: {
              type: 'string',
              minLength: 1,
              maxLength: PLATFORM_USER_ID_MAX_LENGTH,
              pattern: PLATFORM_USER_ID_PATTERN
            }
          },
          {
            in: 'header',
            name: 'Idempotency-Key',
            required: false,
            description: '关键写幂等键；同键同路由参数返回首次持久化语义，参数校验失败等非持久响应不会占用该键',
            schema: IDEMPOTENCY_KEY_SCHEMA
          }
        ],
        responses: {
          200: {
            description: 'Platform user soft-deleted (or no-op) with global session/token revocation result.',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SoftDeletePlatformUserResponse' }
              }
            }
          },
          400: {
            description: 'Invalid user_id path parameter',
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
      AuditEventRecord: {
        type: 'object',
        additionalProperties: false,
        required: [
          'event_id',
          'domain',
          'request_id',
          'event_type',
          'target_type',
          'result',
          'occurred_at'
        ],
        properties: {
          event_id: { type: 'string' },
          domain: { type: 'string', enum: ['platform', 'tenant'] },
          tenant_id: { type: 'string', nullable: true },
          request_id: { type: 'string' },
          traceparent: { type: 'string', nullable: true },
          event_type: { type: 'string' },
          actor_user_id: { type: 'string', nullable: true },
          actor_session_id: { type: 'string', nullable: true },
          target_type: { type: 'string' },
          target_id: { type: 'string', nullable: true },
          result: { type: 'string', enum: ['success', 'rejected', 'failed'] },
          before_state: { type: 'object', nullable: true, additionalProperties: true },
          after_state: { type: 'object', nullable: true, additionalProperties: true },
          metadata: { type: 'object', nullable: true, additionalProperties: true },
          occurred_at: { type: 'string', format: 'date-time' }
        }
      },
      AuditEventListResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['domain', 'page', 'page_size', 'total', 'events', 'request_id'],
        properties: {
          domain: { type: 'string', enum: ['platform', 'tenant'] },
          page: { type: 'integer', minimum: 1 },
          page_size: { type: 'integer', minimum: 1, maximum: 200 },
          total: { type: 'integer', minimum: 0 },
          events: {
            type: 'array',
            items: { $ref: '#/components/schemas/AuditEventRecord' }
          },
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
          display_name: {
            type: 'string',
            nullable: true,
            maxLength: 64,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
          },
          department_name: {
            type: 'string',
            nullable: true,
            maxLength: 128,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
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
      TenantMemberDetailResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'membership_id',
          'user_id',
          'tenant_id',
          'phone',
          'status',
          'display_name',
          'department_name',
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
          display_name: {
            type: 'string',
            nullable: true,
            maxLength: 64,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
          },
          department_name: {
            type: 'string',
            nullable: true,
            maxLength: 128,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
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
      TenantMemberProfileUpdateRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['display_name'],
        properties: {
          display_name: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
          },
          department_name: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 128,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
          }
        }
      },
      ReplaceTenantMemberRoleBindingsRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['role_ids'],
        properties: {
          role_ids: {
            type: 'array',
            uniqueItems: true,
            minItems: 1,
            maxItems: 5,
            items: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_ROLE_ID_PATTERN
            }
          }
        }
      },
      TenantMemberRoleBindingsResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['membership_id', 'role_ids', 'request_id'],
        properties: {
          membership_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: TENANT_MEMBERSHIP_ID_PATTERN
          },
          role_ids: {
            type: 'array',
            items: {
              type: 'string',
              minLength: 1,
              maxLength: 64,
              pattern: PLATFORM_ROLE_ID_PATTERN
            }
          },
          request_id: { type: 'string' }
        }
      },
      TenantRoleCatalogItem: {
        type: 'object',
        additionalProperties: false,
        required: [
          'role_id',
          'tenant_id',
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
          tenant_id: {
            type: 'string',
            minLength: 1
          },
          code: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
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
      TenantRoleListResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['tenant_id', 'roles', 'request_id'],
        properties: {
          tenant_id: {
            type: 'string',
            minLength: 1
          },
          roles: {
            type: 'array',
            items: { $ref: '#/components/schemas/TenantRoleCatalogItem' }
          },
          request_id: { type: 'string' }
        }
      },
      CreateTenantRoleRequest: {
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
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
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
          }
        }
      },
      UpdateTenantRoleRequest: {
        type: 'object',
        additionalProperties: false,
        minProperties: 1,
        properties: {
          code: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
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
      DeleteTenantRoleResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['role_id', 'tenant_id', 'status', 'request_id'],
        properties: {
          role_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_ROLE_ID_PATTERN
          },
          tenant_id: {
            type: 'string',
            minLength: 1
          },
          status: {
            type: 'string',
            enum: ['disabled']
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
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
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
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
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
        minProperties: 1,
        properties: {
          code: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
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
            enum: ['disabled']
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
      PlatformUserReadModel: {
        type: 'object',
        additionalProperties: false,
        required: ['user_id', 'phone', 'status'],
        properties: {
          user_id: {
            type: 'string',
            minLength: 1,
            maxLength: PLATFORM_USER_ID_MAX_LENGTH,
            pattern: PLATFORM_USER_ID_PATTERN
          },
          phone: {
            type: 'string',
            minLength: 1,
            maxLength: 32
          },
          status: {
            type: 'string',
            enum: ['active', 'disabled']
          }
        }
      },
      PlatformUserDetailResponse: {
        allOf: [
          { $ref: '#/components/schemas/PlatformUserReadModel' },
          {
            type: 'object',
            additionalProperties: false,
            required: ['request_id'],
            properties: {
              request_id: { type: 'string' }
            }
          }
        ]
      },
      PlatformUserListResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['items', 'total', 'page', 'page_size', 'request_id'],
        properties: {
          items: {
            type: 'array',
            items: { $ref: '#/components/schemas/PlatformUserReadModel' }
          },
          total: {
            type: 'integer',
            minimum: 0
          },
          page: {
            type: 'integer',
            minimum: 1
          },
          page_size: {
            type: 'integer',
            minimum: 1,
            maximum: 100
          },
          request_id: { type: 'string' }
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
      SoftDeletePlatformUserResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'user_id',
          'previous_status',
          'current_status',
          'revoked_session_count',
          'revoked_refresh_token_count',
          'request_id'
        ],
        properties: {
          user_id: {
            type: 'string',
            minLength: 1,
            maxLength: PLATFORM_USER_ID_MAX_LENGTH,
            pattern: PLATFORM_USER_ID_PATTERN
          },
          previous_status: {
            type: 'string',
            enum: ['active', 'disabled'],
            description: '软删除执行前的用户状态'
          },
          current_status: {
            type: 'string',
            enum: ['disabled'],
            description: '软删除执行后的用户状态'
          },
          revoked_session_count: {
            type: 'integer',
            minimum: 0
          },
          revoked_refresh_token_count: {
            type: 'integer',
            minimum: 0
          },
          request_id: { type: 'string' }
        }
      },
      UpdateSystemConfigRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['encrypted_value', 'expected_version'],
        properties: {
          encrypted_value: {
            type: 'string',
            minLength: 1,
            pattern: '^enc:v1:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]{22}:[A-Za-z0-9_-]+$',
            description: '受控配置密文值（enc:v1 信封）'
          },
          expected_version: {
            type: 'integer',
            minimum: 0,
            description: '乐观并发版本号，必须与当前版本一致'
          },
          status: {
            type: 'string',
            enum: ['active', 'disabled', 'enabled'],
            description: '配置状态（enabled 作为 active 的兼容别名）'
          }
        }
      },
      SystemConfigReadResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['data', 'meta'],
        properties: {
          data: {
            type: 'object',
            additionalProperties: false,
            required: [
              'config_key',
              'version',
              'status',
              'updated_by_user_id',
              'updated_at'
            ],
            properties: {
              config_key: {
                type: 'string',
                enum: ['auth.default_password']
              },
              version: {
                type: 'integer',
                minimum: 1
              },
              status: {
                type: 'string',
                enum: ['active', 'disabled']
              },
              updated_by_user_id: {
                type: 'string'
              },
              updated_at: {
                type: 'string',
                format: 'date-time'
              }
            }
          },
          meta: {
            type: 'object',
            additionalProperties: false,
            required: ['request_id'],
            properties: {
              request_id: { type: 'string' }
            }
          }
        }
      },
      UpdateSystemConfigResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['data', 'meta'],
        properties: {
          data: {
            type: 'object',
            additionalProperties: false,
            required: [
              'config_key',
              'previous_version',
              'version',
              'status',
              'updated_by_user_id',
              'updated_at'
            ],
            properties: {
              config_key: {
                type: 'string',
                enum: ['auth.default_password']
              },
              previous_version: {
                type: 'integer',
                minimum: 0
              },
              version: {
                type: 'integer',
                minimum: 1
              },
              status: {
                type: 'string',
                enum: ['active', 'disabled']
              },
              updated_by_user_id: {
                type: 'string'
              },
              updated_at: {
                type: 'string',
                format: 'date-time'
              }
            }
          },
          meta: {
            type: 'object',
            additionalProperties: false,
            required: ['request_id'],
            properties: {
              request_id: { type: 'string' }
            }
          }
        }
      },
      PlatformIntegrationCatalogItem: {
        type: 'object',
        additionalProperties: false,
        required: [
          'integration_id',
          'code',
          'name',
          'direction',
          'protocol',
          'auth_mode',
          'timeout_ms',
          'retry_policy',
          'idempotency_policy',
          'lifecycle_status',
          'effective_invocation_enabled',
          'created_at',
          'updated_at',
          'request_id'
        ],
        properties: {
          integration_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_ID_PATTERN
          },
          code: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CODE_PATTERN
          },
          name: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          direction: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_DIRECTION_ENUM
          },
          protocol: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$'
          },
          auth_mode: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$'
          },
          endpoint: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          base_url: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          timeout_ms: {
            type: 'integer',
            minimum: 1,
            maximum: 300000
          },
          retry_policy: {
            type: ['object', 'array', 'null'],
            additionalProperties: true
          },
          idempotency_policy: {
            type: ['object', 'array', 'null'],
            additionalProperties: true
          },
          version_strategy: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          runbook_url: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          lifecycle_status: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_LIFECYCLE_ENUM
          },
          lifecycle_reason: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 256,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,256}$'
          },
          created_by_user_id: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 64
          },
          updated_by_user_id: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 64
          },
          created_at: {
            type: 'string',
            format: 'date-time'
          },
          updated_at: {
            type: 'string',
            format: 'date-time'
          },
          effective_invocation_enabled: { type: 'boolean' },
          request_id: { type: 'string' }
        }
      },
      PlatformIntegrationCatalogListResponse: {
        type: 'object',
        additionalProperties: false,
        required: ['page', 'page_size', 'total', 'integrations', 'request_id'],
        properties: {
          page: { type: 'integer', minimum: 1 },
          page_size: { type: 'integer', minimum: 1, maximum: 100 },
          total: { type: 'integer', minimum: 0 },
          integrations: {
            type: 'array',
            items: { $ref: '#/components/schemas/PlatformIntegrationCatalogItem' }
          },
          request_id: { type: 'string' }
        }
      },
      CreatePlatformIntegrationRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['code', 'name', 'direction', 'protocol', 'auth_mode'],
        properties: {
          integration_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_ID_PATTERN
          },
          code: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CODE_PATTERN
          },
          name: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          direction: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_DIRECTION_ENUM
          },
          protocol: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$'
          },
          auth_mode: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$'
          },
          endpoint: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          base_url: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          timeout_ms: {
            type: 'integer',
            minimum: 1,
            maximum: 300000,
            default: 3000
          },
          retry_policy: {
            type: ['object', 'array', 'null'],
            additionalProperties: true
          },
          idempotency_policy: {
            type: ['object', 'array', 'null'],
            additionalProperties: true
          },
          version_strategy: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          runbook_url: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          lifecycle_status: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_LIFECYCLE_ENUM,
            default: 'draft'
          },
          lifecycle_reason: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 256,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,256}$'
          }
        }
      },
      UpdatePlatformIntegrationRequest: {
        type: 'object',
        additionalProperties: false,
        minProperties: 1,
        properties: {
          code: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CODE_PATTERN
          },
          name: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          direction: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_DIRECTION_ENUM
          },
          protocol: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$'
          },
          auth_mode: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,64}$'
          },
          endpoint: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          base_url: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          timeout_ms: {
            type: 'integer',
            minimum: 1,
            maximum: 300000
          },
          retry_policy: {
            type: ['object', 'array', 'null'],
            additionalProperties: true
          },
          idempotency_policy: {
            type: ['object', 'array', 'null'],
            additionalProperties: true
          },
          version_strategy: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          runbook_url: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          lifecycle_reason: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 256,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,256}$'
          }
        }
      },
      ChangePlatformIntegrationLifecycleRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['status'],
        properties: {
          status: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_LIFECYCLE_ENUM
          },
          reason: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 256,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,256}$'
          }
        }
      },
      ChangePlatformIntegrationLifecycleResponse: {
        allOf: [
          { $ref: '#/components/schemas/PlatformIntegrationCatalogItem' },
          {
            type: 'object',
            additionalProperties: false,
            required: ['previous_status', 'current_status', 'effective_invocation_enabled'],
            properties: {
              previous_status: {
                type: 'string',
                enum: PLATFORM_INTEGRATION_LIFECYCLE_ENUM
              },
              current_status: {
                type: 'string',
                enum: PLATFORM_INTEGRATION_LIFECYCLE_ENUM
              },
              effective_invocation_enabled: { type: 'boolean' }
            }
          }
        ]
      },
      PlatformIntegrationContractItem: {
        type: 'object',
        additionalProperties: false,
        required: [
          'integration_id',
          'contract_type',
          'contract_version',
          'schema_ref',
          'schema_checksum',
          'status',
          'is_backward_compatible',
          'created_at',
          'updated_at',
          'request_id'
        ],
        properties: {
          integration_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_ID_PATTERN
          },
          contract_type: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM
          },
          contract_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          },
          schema_ref: {
            type: 'string',
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          schema_checksum: {
            type: 'string',
            minLength: 64,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN
          },
          status: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM
          },
          is_backward_compatible: { type: 'boolean' },
          compatibility_notes: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 4096,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,4096}$'
          },
          created_by_user_id: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 64
          },
          updated_by_user_id: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 64
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
      PlatformIntegrationContractListResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'integration_id',
          'lifecycle_status',
          'contracts',
          'active_contracts',
          'request_id'
        ],
        properties: {
          integration_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_ID_PATTERN
          },
          lifecycle_status: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_LIFECYCLE_ENUM
          },
          contracts: {
            type: 'array',
            items: { $ref: '#/components/schemas/PlatformIntegrationContractItem' }
          },
          active_contracts: {
            type: 'array',
            items: { $ref: '#/components/schemas/PlatformIntegrationContractItem' }
          },
          request_id: { type: 'string' }
        }
      },
      CreatePlatformIntegrationContractRequest: {
        type: 'object',
        additionalProperties: false,
        required: [
          'contract_type',
          'contract_version',
          'schema_ref',
          'schema_checksum'
        ],
        properties: {
          contract_type: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM
          },
          contract_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          },
          schema_ref: {
            type: 'string',
            minLength: 1,
            maxLength: 512,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,512}$'
          },
          schema_checksum: {
            type: 'string',
            minLength: 64,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN
          },
          status: {
            type: 'string',
            enum: ['candidate', 'deprecated', 'retired'],
            default: 'candidate'
          },
          is_backward_compatible: {
            type: 'boolean',
            default: false
          },
          compatibility_notes: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 4096,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,4096}$'
          }
        }
      },
      EvaluatePlatformIntegrationContractCompatibilityRequest: {
        type: 'object',
        additionalProperties: false,
        required: [
          'contract_type',
          'baseline_version',
          'candidate_version'
        ],
        properties: {
          contract_type: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM
          },
          baseline_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          },
          candidate_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          },
          breaking_change_count: {
            type: 'integer',
            minimum: 0
          },
          diff_summary: {
            type: ['object', 'array', 'null'],
            additionalProperties: true
          }
        }
      },
      PlatformIntegrationContractCompatibilityCheckResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'integration_id',
          'contract_type',
          'baseline_version',
          'candidate_version',
          'evaluation_result',
          'breaking_change_count',
          'request_id',
          'checked_at'
        ],
        properties: {
          integration_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_ID_PATTERN
          },
          contract_type: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM
          },
          baseline_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          },
          candidate_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          },
          evaluation_result: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT_ENUM
          },
          breaking_change_count: {
            type: 'integer',
            minimum: 0
          },
          diff_summary: {
            type: ['object', 'array', 'null'],
            additionalProperties: true
          },
          request_id: { type: 'string' },
          checked_by_user_id: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 64
          },
          checked_at: {
            type: 'string',
            format: 'date-time'
          }
        }
      },
      CheckPlatformIntegrationContractConsistencyRequest: {
        type: 'object',
        additionalProperties: false,
        required: [
          'contract_type',
          'baseline_version',
          'candidate_version'
        ],
        properties: {
          contract_type: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM
          },
          baseline_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          },
          candidate_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          }
        }
      },
      PlatformIntegrationContractConsistencyCheckResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'integration_id',
          'contract_type',
          'baseline_version',
          'candidate_version',
          'check_result',
          'blocking',
          'failure_reason',
          'breaking_change_count',
          'diff_summary',
          'request_id',
          'checked_at'
        ],
        properties: {
          integration_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_ID_PATTERN
          },
          contract_type: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM
          },
          baseline_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          },
          candidate_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          },
          check_result: {
            type: 'string',
            enum: ['passed']
          },
          blocking: {
            type: 'boolean',
            enum: [false]
          },
          failure_reason: {
            type: 'string',
            nullable: true
          },
          breaking_change_count: {
            type: 'integer',
            minimum: 0
          },
          diff_summary: {
            type: ['object', 'array', 'null'],
            additionalProperties: true
          },
          request_id: { type: 'string' },
          checked_at: {
            type: 'string',
            format: 'date-time'
          }
        }
      },
      ActivatePlatformIntegrationContractRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['contract_type'],
        properties: {
          contract_type: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM
          },
          baseline_version: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          }
        }
      },
      ActivatePlatformIntegrationContractResponse: {
        allOf: [
          { $ref: '#/components/schemas/PlatformIntegrationContractItem' },
          {
            type: 'object',
            additionalProperties: false,
            required: ['previous_status', 'current_status'],
            properties: {
              previous_status: {
                type: 'string',
                enum: PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM
              },
              current_status: {
                type: 'string',
                enum: PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM
              }
            }
          }
        ]
      },
      PlatformIntegrationRecoveryQueueItem: {
        type: 'object',
        additionalProperties: false,
        required: [
          'recovery_id',
          'integration_id',
          'contract_type',
          'contract_version',
          'request_id',
          'attempt_count',
          'max_attempts',
          'status',
          'retryable',
          'payload_snapshot',
          'created_at',
          'updated_at'
        ],
        properties: {
          recovery_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_RECOVERY_ID_PATTERN
          },
          integration_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_ID_PATTERN
          },
          contract_type: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM
          },
          contract_version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_CONTRACT_VERSION_PATTERN
          },
          request_id: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          traceparent: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          idempotency_key: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          attempt_count: {
            type: 'integer',
            minimum: 0
          },
          max_attempts: {
            type: 'integer',
            minimum: 1,
            maximum: 5
          },
          next_retry_at: {
            type: 'string',
            format: 'date-time',
            nullable: true
          },
          last_attempt_at: {
            type: 'string',
            format: 'date-time',
            nullable: true
          },
          status: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM
          },
          failure_code: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          failure_detail: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 65535,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,65535}$'
          },
          last_http_status: {
            type: 'integer',
            minimum: 100,
            maximum: 599,
            nullable: true
          },
          retryable: { type: 'boolean' },
          payload_snapshot: {
            type: ['object', 'array'],
            additionalProperties: true
          },
          response_snapshot: {
            type: ['object', 'array', 'null'],
            additionalProperties: true
          },
          created_by_user_id: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 64
          },
          updated_by_user_id: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 64
          },
          created_at: {
            type: 'string',
            format: 'date-time'
          },
          updated_at: {
            type: 'string',
            format: 'date-time'
          }
        }
      },
      PlatformIntegrationRecoveryQueueListResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'integration_id',
          'lifecycle_status',
          'status',
          'limit',
          'queue',
          'request_id'
        ],
        properties: {
          integration_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_ID_PATTERN
          },
          lifecycle_status: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_LIFECYCLE_ENUM
          },
          status: {
            type: ['string', 'null'],
            enum: [...PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM, null]
          },
          limit: {
            type: 'integer',
            minimum: 1,
            maximum: 200
          },
          queue: {
            type: 'array',
            items: {
              $ref: '#/components/schemas/PlatformIntegrationRecoveryQueueItem'
            }
          },
          request_id: { type: 'string' }
        }
      },
      ReplayPlatformIntegrationRecoveryRequest: {
        type: 'object',
        additionalProperties: false,
        properties: {
          reason: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 256,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,256}$'
          }
        }
      },
      PlatformIntegrationRecoveryReplayResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'recovery',
          'previous_status',
          'current_status',
          'replayed',
          'request_id'
        ],
        properties: {
          recovery: {
            $ref: '#/components/schemas/PlatformIntegrationRecoveryQueueItem'
          },
          previous_status: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM
          },
          current_status: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM
          },
          replayed: { type: 'boolean' },
          request_id: { type: 'string' }
        }
      },
      ActivatePlatformIntegrationFreezeRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['freeze_reason'],
        properties: {
          freeze_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_FREEZE_ID_PATTERN
          },
          freeze_reason: {
            type: 'string',
            minLength: 1,
            maxLength: 256,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,256}$'
          }
        }
      },
      ReleasePlatformIntegrationFreezeRequest: {
        type: 'object',
        additionalProperties: false,
        properties: {
          rollback_reason: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 256,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,256}$'
          }
        }
      },
      PlatformIntegrationFreezeWindow: {
        type: 'object',
        additionalProperties: false,
        required: [
          'freeze_id',
          'status',
          'freeze_reason',
          'frozen_at',
          'request_id',
          'created_at',
          'updated_at'
        ],
        properties: {
          freeze_id: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: PLATFORM_INTEGRATION_FREEZE_ID_PATTERN
          },
          status: {
            type: 'string',
            enum: PLATFORM_INTEGRATION_FREEZE_STATUS_ENUM
          },
          freeze_reason: {
            type: 'string',
            minLength: 1,
            maxLength: 256,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,256}$'
          },
          rollback_reason: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 256,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,256}$'
          },
          frozen_at: {
            type: 'string',
            format: 'date-time'
          },
          released_at: {
            type: 'string',
            format: 'date-time',
            nullable: true
          },
          frozen_by_user_id: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 64
          },
          released_by_user_id: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 64
          },
          request_id: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          traceparent: {
            type: 'string',
            nullable: true,
            minLength: 1,
            maxLength: 128,
            pattern: '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]{1,128}$'
          },
          created_at: {
            type: 'string',
            format: 'date-time'
          },
          updated_at: {
            type: 'string',
            format: 'date-time'
          }
        }
      },
      PlatformIntegrationFreezeStatusResponse: {
        type: 'object',
        additionalProperties: false,
        required: [
          'frozen',
          'active_freeze',
          'latest_freeze',
          'request_id'
        ],
        properties: {
          frozen: { type: 'boolean' },
          active_freeze: {
            oneOf: [
              {
                $ref: '#/components/schemas/PlatformIntegrationFreezeWindow'
              },
              {
                type: 'null'
              }
            ]
          },
          latest_freeze: {
            oneOf: [
              {
                $ref: '#/components/schemas/PlatformIntegrationFreezeWindow'
              },
              {
                type: 'null'
              }
            ]
          },
          request_id: { type: 'string' }
        }
      },
      PlatformIntegrationFreezeReleaseResponse: {
        allOf: [
          { $ref: '#/components/schemas/PlatformIntegrationFreezeWindow' },
          {
            type: 'object',
            additionalProperties: false,
            required: ['previous_status', 'current_status', 'released'],
            properties: {
              previous_status: {
                type: 'string',
                enum: PLATFORM_INTEGRATION_FREEZE_STATUS_ENUM
              },
              current_status: {
                type: 'string',
                enum: PLATFORM_INTEGRATION_FREEZE_STATUS_ENUM
              },
              released: { type: 'boolean' }
            }
          }
        ]
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
      ReplaceTenantRolePermissionGrantsRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['permission_codes'],
        properties: {
          permission_codes: {
            type: 'array',
            maxItems: 64,
            description: '仅允许 tenant.* 最终授权权限点；服务端按大小写不敏感语义去重、排序并持久化，不接受权限树中间态节点。',
            example: [
              'tenant.member_admin.operate',
              'tenant.billing.view'
            ],
            items: {
              type: 'string',
              pattern: '^tenant\\.[A-Za-z0-9._-]+$'
            }
          }
        }
      },
      TenantRolePermissionGrantsReadResponse: {
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
            description: '仅返回最终授权权限点集合（叶子授权结果）；前端可据此恢复 checked 节点。',
            example: [
              'tenant.billing.operate',
              'tenant.member_admin.operate'
            ],
            items: {
              type: 'string',
              pattern: '^tenant\\.[A-Za-z0-9._-]+$'
            }
          },
          available_permission_codes: {
            type: 'array',
            description: '当前租户权限目录基线；用于前端根据目录重建 checked/half-checked 展示。',
            example: [
              'tenant.billing.operate',
              'tenant.billing.view',
              'tenant.member_admin.operate',
              'tenant.member_admin.view'
            ],
            items: {
              type: 'string',
              pattern: '^tenant\\.[A-Za-z0-9._-]+$'
            }
          },
          request_id: { type: 'string' }
        }
      },
      TenantRolePermissionGrantsWriteResponse: {
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
            description: '仅返回最终授权权限点集合（叶子授权结果）；前端可据此恢复 checked 节点。',
            example: [
              'tenant.billing.operate',
              'tenant.member_admin.operate'
            ],
            items: {
              type: 'string',
              pattern: '^tenant\\.[A-Za-z0-9._-]+$'
            }
          },
          available_permission_codes: {
            type: 'array',
            description: '当前租户权限目录基线；用于前端根据目录重建 checked/half-checked 展示。',
            example: [
              'tenant.billing.operate',
              'tenant.billing.view',
              'tenant.member_admin.operate',
              'tenant.member_admin.view'
            ],
            items: {
              type: 'string',
              pattern: '^tenant\\.[A-Za-z0-9._-]+$'
            }
          },
          affected_user_count: {
            type: 'integer',
            minimum: 0
          },
          request_id: { type: 'string' }
        }
      },
      ReplacePlatformRolePermissionGrantsRequest: {
        type: 'object',
        additionalProperties: false,
        required: ['permission_codes'],
        properties: {
          permission_codes: {
            type: 'array',
            maxItems: 64,
            description: '仅允许 platform.* 最终授权权限点；服务端按大小写不敏感语义去重、排序并持久化，不接受权限树中间态节点。',
            example: [
              'platform.member_admin.operate',
              'platform.billing.view'
            ],
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
            description: '仅返回最终授权权限点集合（叶子授权结果）；前端可据此恢复 checked 节点。',
            example: [
              'platform.billing.operate',
              'platform.member_admin.operate'
            ],
            items: {
              type: 'string',
              pattern: '^platform\\.[A-Za-z0-9._-]+$'
            }
          },
          available_permission_codes: {
            type: 'array',
            description: '当前平台权限目录基线；用于前端根据目录重建 checked/half-checked 展示。',
            example: [
              'platform.billing.operate',
              'platform.billing.view',
              'platform.member_admin.operate',
              'platform.member_admin.view',
              'platform.system_config.operate',
              'platform.system_config.view'
            ],
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
            description: '仅返回最终授权权限点集合（叶子授权结果）；前端可据此恢复 checked 节点。',
            example: [
              'platform.billing.operate',
              'platform.member_admin.operate'
            ],
            items: {
              type: 'string',
              pattern: '^platform\\.[A-Za-z0-9._-]+$'
            }
          },
          available_permission_codes: {
            type: 'array',
            description: '当前平台权限目录基线；用于前端根据目录重建 checked/half-checked 展示。',
            example: [
              'platform.billing.operate',
              'platform.billing.view',
              'platform.member_admin.operate',
              'platform.member_admin.view',
              'platform.system_config.operate',
              'platform.system_config.view'
            ],
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
        required: [
          'title',
          'status',
          'request_id',
          'traceparent',
          'error_code',
          'retryable'
        ],
        properties: {
          type: { type: 'string' },
          title: { type: 'string' },
          status: { type: 'integer' },
          detail: { type: 'string' },
          request_id: { type: 'string' },
          traceparent: { type: 'string', nullable: true },
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
