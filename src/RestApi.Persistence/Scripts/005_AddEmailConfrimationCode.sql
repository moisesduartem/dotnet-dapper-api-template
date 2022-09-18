USE [RestApi]

GO

ALTER TABLE [Users] DROP COLUMN IF EXISTS [EmailConfirmationCode]

GO

ALTER TABLE [Users] ADD [EmailConfirmationCode] CHAR(80) NULL DEFAULT NULL