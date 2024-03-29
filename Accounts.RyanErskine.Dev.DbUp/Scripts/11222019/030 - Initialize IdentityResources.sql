﻿USE [IdentityServer]
GO

INSERT INTO dbo.IdentityResources
VALUES ('Unique identifier of the user.', 'Your user identifier', 0, 1, 'openid', 1, 1, '11-25-2019', 0, '11-25-2019')
INSERT INTO dbo.IdentityResources
VALUES ('Your user profile information (first name, last name, etc.)', 'User profile', 1, 1, 'profile', 0, 1, '11-25-2019', 0, '11-25-2019')
INSERT INTO dbo.IdentityResources
VALUES ('The role that a user has. Users can have multiple.', 'Role', 0, 1, 'role', 0, 1, '11-25-2019', 0, '11-25-2019')