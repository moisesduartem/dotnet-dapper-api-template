USE [RestApi]

GO

DROP TABLE IF EXISTS [Users]

GO

CREATE TABLE [Users] (
	[Id] UNIQUEIDENTIFIER DEFAULT NEWID(),
	[FirstName] VARCHAR(25) NOT NULL,
	[LastName] VARCHAR(30) NOT NULL,
	[Email] VARCHAR(60) NOT NULL,
	[Birthdate] DATE NOT NULL,
	[PasswordHash] CHAR(84) NOT NULL,
	[EmailConfirmed] BIT DEFAULT 0,
	[IsActive] BIT DEFAULT 1,
	[CreatedAt] DATETIME2 NOT NULL DEFAULT GETDATE(),
	[UpdatedAt] DATETIME2 NOT NULL DEFAULT GETDATE(),

	CONSTRAINT [PK_Users] PRIMARY KEY ([Id])
)

GO

CREATE INDEX [IX_Users_Email] ON [Users]([Email])

GO