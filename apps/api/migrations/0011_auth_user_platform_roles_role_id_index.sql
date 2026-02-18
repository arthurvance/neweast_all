ALTER TABLE auth_user_platform_roles
  ADD KEY idx_auth_user_platform_roles_role_id_user_id (role_id, user_id);
