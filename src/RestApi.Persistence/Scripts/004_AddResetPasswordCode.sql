USE [RestApi]

GO

ALTER TABLE [Users] DROP COLUMN IF EXISTS [ResetPasswordCode]

GO

ALTER TABLE [Users] ADD [ResetPasswordCode] CHAR(80) NULL DEFAULT NULL

GO

ALTER TABLE [Users] DROP COLUMN IF EXISTS [ResetPasswordExpiration]

GO

ALTER TABLE [Users] ADD [ResetPasswordExpiration] DATETIME2 NULL DEFAULT GETDATE()