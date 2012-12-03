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
    
   -- no logins if contained - do not mess with the server setting - could break something else
   IF ( SELECT c.value_in_use 
         FROM sys.configurations AS c
         WHERE c.name = 'contained database authentication' ) = 0
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
  