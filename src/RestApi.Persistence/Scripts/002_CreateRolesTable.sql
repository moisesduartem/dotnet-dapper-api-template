USE [RestApi]

GO

DROP TABLE IF EXISTS [Roles]

GO

CREATE TABLE [Roles] (
	[Id] UNIQUEIDENTIFIER DEFAULT NEWID(),
	[Name] VARCHAR(20) UNIQUE NOT NULL,
	[CreatedAt] DATETIME2 NOT NULL DEFAULT GETDATE(),
	[UpdatedAt] DATETIME2 NOT NULL DEFAULT GETDATE(),

	CONSTRAINT [PK_Roles] PRIMARY KEY ([Id])
)

GO

CREATE UNIQUE INDEX [IX_Roles_Name] ON [Roles]([Name])

GO