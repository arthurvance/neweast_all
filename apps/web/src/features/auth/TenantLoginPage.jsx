import {
  Button,
  Card,
  Flex,
  Form,
  Image,
  Input,
  Space,
  Tabs,
  Typography
} from 'antd';
import { TENANT_TECH_ILLUSTRATION_DATA_URI } from './login-illustrations';

export default function TenantLoginPage({
  screens,
  mode,
  onModeSwitch,
  phone,
  onPhoneChange,
  password,
  onPasswordChange,
  otpCode,
  onOtpCodeChange,
  fieldErrors,
  isSubmitting,
  isSendingOtp,
  otpCountdownSeconds,
  onSendOtp,
  onSubmit
}) {
  const visualMinHeight = '100vh';

  return (
    <Card
      bordered={false}
      styles={{ body: { padding: 0, height: '100%' } }}
      style={{
        position: 'relative',
        minHeight: visualMinHeight,
        width: '100%',
        borderRadius: 0,
        overflow: 'hidden'
      }}
    >
      <Flex style={{ width: '100%', height: '100%', minHeight: visualMinHeight }}>
        <Image
          preview={false}
          src={TENANT_TECH_ILLUSTRATION_DATA_URI}
          alt="组织登录科技感插图"
          width="100%"
          height="100%"
          style={{ width: '100%', height: '100%', objectFit: 'cover' }}
        />
      </Flex>
      <Flex
        style={{
          position: 'absolute',
          inset: 0,
          justifyContent: screens.lg ? 'flex-end' : 'center',
          alignItems: 'center',
          padding: screens.lg ? '0 8vw 0 0' : 12,
          background: screens.lg
            ? 'linear-gradient(270deg, rgba(250, 252, 255, 0.78) 0%, rgba(250, 252, 255, 0.34) 44%, rgba(250, 252, 255, 0) 76%)'
            : 'rgba(248, 251, 255, 0.45)'
        }}
      >
        <Flex
          style={{
            width: screens.lg ? 'min(420px, 42vw)' : '100%',
            maxWidth: screens.lg ? 420 : 560,
            transform: 'translateY(-40px)'
          }}
        >
          <Card
            styles={{ body: { padding: '40px 32px' } }}
            style={{
              width: '100%',
              maxWidth: 420,
              height: 480,
              borderRadius: 12,
              boxShadow: screens.lg ? '0 12px 32px rgba(0, 0, 0, 0.04)' : 'none',
              border: screens.lg ? '1px solid #EBF1F9' : 'none'
            }}
          >
            <Space direction="vertical" size={16} style={{ width: '100%' }}>
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                <Typography.Title level={2} data-testid="page-title" style={{ margin: 0 }}>
                  登录
                </Typography.Title>
              </Space>

              <Tabs
                activeKey={mode}
                onChange={(key) => onModeSwitch(key)}
                items={[
                  {
                    key: 'password',
                    label: <span data-testid="mode-password">密码登录</span>,
                    disabled: isSubmitting || isSendingOtp
                  },
                  {
                    key: 'otp',
                    label: <span data-testid="mode-otp">验证码登录</span>,
                    disabled: isSubmitting || isSendingOtp
                  }
                ]}
                style={{ marginBottom: -12 }}
              />

              <Form layout="vertical" requiredMark={false} onFinish={onSubmit}>
                <Form.Item
                  label="手机号"
                  validateStatus={fieldErrors.phone ? 'error' : ''}
                  help={fieldErrors.phone || null}
                >
                  <Input
                    size="large"
                    data-testid="input-phone"
                    value={phone}
                    onChange={(event) => onPhoneChange(event.target.value)}
                    placeholder="请输入 11 位手机号"
                    autoComplete="tel"
                    disabled={isSubmitting || isSendingOtp}
                  />
                </Form.Item>

                {mode === 'password' ? (
                  <Form.Item
                    label="密码"
                    validateStatus={fieldErrors.password ? 'error' : ''}
                    help={fieldErrors.password || null}
                  >
                    <Input.Password
                      size="large"
                      data-testid="input-password"
                      value={password}
                      onChange={(event) => onPasswordChange(event.target.value)}
                      placeholder="请输入密码"
                      autoComplete="current-password"
                      disabled={isSubmitting || isSendingOtp}
                    />
                  </Form.Item>
                ) : (
                  <Form.Item
                    label="验证码"
                    validateStatus={fieldErrors.otpCode ? 'error' : ''}
                    help={fieldErrors.otpCode || null}
                  >
                    <Space.Compact style={{ width: '100%' }}>
                      <Input
                        size="large"
                        data-testid="input-otp-code"
                        value={otpCode}
                        onChange={(event) => onOtpCodeChange(event.target.value)}
                        placeholder="请输入 6 位验证码"
                        autoComplete="one-time-code"
                        disabled={isSubmitting}
                      />
                      <Button
                        size="large"
                        data-testid="button-send-otp"
                        onClick={onSendOtp}
                        disabled={isSendingOtp || isSubmitting || otpCountdownSeconds > 0}
                        loading={isSendingOtp}
                      >
                        {otpCountdownSeconds > 0 ? `${otpCountdownSeconds}s 后重试` : '发送验证码'}
                      </Button>
                    </Space.Compact>
                  </Form.Item>
                )}

                <Form.Item style={{ marginBottom: 0 }}>
                  <Button
                    size="large"
                    data-testid="button-submit-login"
                    type="primary"
                    htmlType="submit"
                    loading={isSubmitting}
                    disabled={isSendingOtp}
                    block
                  >
                    {isSubmitting ? '提交中...' : '登录'}
                  </Button>
                </Form.Item>
              </Form>
            </Space>
          </Card>
        </Flex>
      </Flex>
    </Card>
  );
}
