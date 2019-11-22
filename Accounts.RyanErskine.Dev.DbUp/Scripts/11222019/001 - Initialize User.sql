USE [IdentityServer]
GO

IF NOT EXISTS(SELECT * FROM master.sys.server_principals where name = 'IdentityServerUser') BEGIN
    CREATE LOGIN [IdentityServerUser] WITH 
        PASSWORD=N'Th1sIsALocalOnlyP@ssword!', 
        DEFAULT_DATABASE=[master], 
        DEFAULT_LANGUAGE=[us_english], 
        CHECK_EXPIRATION=OFF, 
        CHECK_POLICY=ON
END

IF NOT EXISTS(SELECT * FROM sys.database_principals WHERE name = 'IdentityServerUser') AND EXISTS(SELECT * FROM master.sys.server_principals where name = 'IdentityServerUser')
BEGIN
    CREATE USER [IdentityServerUser] FOR LOGIN [IdentityServerUser] WITH DEFAULT_SCHEMA=[dbo]
    EXEC sp_addrolemember N'db_datareader', N'IdentityServerUser'
    EXEC sp_addrolemember N'db_datawriter', N'IdentityServerUser'
END