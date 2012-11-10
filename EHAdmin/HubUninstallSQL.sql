:r C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\Variables.sql             
GO 
--:Connect $(HUB_SERVER_NAME)                                                    
GO
SET NOCOUNT ON
IF SERVERPROPERTY('EngineEdition') <> 5 -- SQL Azure
  BEGIN 
    USE master;
    IF DB_ID('$(HUB_DATABASE)') IS NOT NULL
      BEGIN
        EXEC sp_executesql N'USE $(HUB_DATABASE);
        ALTER DATABASE $(HUB_DATABASE) SET SINGLE_USER WITH ROLLBACK IMMEDIATE;'
        DROP DATABASE $(HUB_DATABASE);     
      END
    
    IF ( SELECT c.value_in_use 
         FROM sys.configurations AS c
         JOIN select * from sys.databases 
          WHERE name = 'contained database authentication' ) = 1
      BEGIN
        EXEC sp_configure 'contained database authentication', 0;
        RECONFIGURE;
        RAISERROR('RECONFIGURE complete.',0,0);
      END
    ELSE
      BEGIN
        IF SUSER_SID( '$(SPOKE_ADMIN)' ) IS NOT NULL
          DROP LOGIN $(SPOKE_ADMIN);
        IF SUSER_SID( '$(SPOKE_BROKER)' ) IS NOT NULL
          DROP LOGIN $(SPOKE_BROKER);
        IF SUSER_SID( '$(HUB_ADMIN)' ) IS NOT NULL
          DROP LOGIN $(HUB_ADMIN);
        IF SUSER_SID( '$(HUB_ODBC_AGENT)' ) IS NOT NULL
          DROP LOGIN $(HUB_ODBC_AGENT);
      END
  END
ELSE
  THROW $(MESSAGE_OFFSET)00, 'Oops. Use "UninstallAzureHub.sql" for this SQL Azure hub.' ,1;
  