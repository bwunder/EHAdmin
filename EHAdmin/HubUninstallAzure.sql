:setvar HUB_ADMIN_PASSWORD                     "si*%tPW#4RfHgd"                
GO
:r C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\Variables_Principals.sql  
:r C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\Variables_Schema.sql      
:r C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\Variables_SpokeSettings.sql
GO 
:Connect <SQLAZURE.instance.name> -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD)
GO
SET NOCOUNT ON
IF SERVERPROPERTY('EngineEdition') = 5 -- SQL Azure
  BEGIN
    IF USER_ID('$(SPOKE_ADMIN)') IS NOT NULL
      DROP USER $(SPOKE_ADMIN);
    IF USER_ID('$(SPOKE_BROKER)') IS NOT NULL
      DROP USER $(SPOKE_BROKER);
    IF USER_ID('$(HUB_ADMIN)') IS NOT NULL
      DROP USER $(HUB_ADMIN);
    IF USER_ID('$(HUB_ODBC_AGENT)') IS NOT NULL
      DROP USER $(HUB_ODBC_AGENT);
    IF USER_ID('$(HUB_ADMIN_ROLE)') IS NOT NULL
      DROP ROLE $(HUB_ADMIN_ROLE);
    IF USER_ID('$(SPOKE_ADMIN_ROLE)') IS NOT NULL
      DROP ROLE $(SPOKE_ADMIN_ROLE);
    IF OBJECT_ID('$(EHA_SCHEMA).HubActivity') IS NOT NULL
      DROP TABLE $(EHA_SCHEMA).HubActivity;
    IF OBJECT_ID('$(EHA_SCHEMA).NotificationActivity') IS NOT NULL
      DROP TABLE $(EHA_SCHEMA).NotificationActivity; 
    IF OBJECT_ID('$(EHA_SCHEMA).ReportActivity') IS NOT NULL
      DROP TABLE $(EHA_SCHEMA).ReportActivity;
    IF OBJECT_ID('$(EHA_SCHEMA).SpokeActivity') IS NOT NULL
      DROP TABLE $(EHA_SCHEMA).SpokeActivity; 
    IF OBJECT_ID('$(EHA_SCHEMA).NameValues') IS NOT NULL
      DROP TABLE $(EHA_SCHEMA).NameValues;
    IF OBJECT_ID('$(EHA_SCHEMA).NameValueActivity') IS NOT NULL
      DROP TABLE $(EHA_SCHEMA).NameValueActivity;
    IF OBJECT_ID('$(EHA_SCHEMA).Backups') IS NOT NULL
      DROP TABLE $(EHA_SCHEMA).Backups;
    IF OBJECT_ID('$(EHA_SCHEMA).BackupActivity') IS NOT NULL
      DROP TABLE $(EHA_SCHEMA).BackupActivity;
    IF OBJECT_ID('$(EHA_SCHEMA).Bookings') IS NOT NULL
      DROP TABLE $(EHA_SCHEMA).Bookings;
    IF SCHEMA_ID('$(EHA_SCHEMA)') IS NOT NULL
      DROP SCHEMA $(EHA_SCHEMA);
  END
ELSE -- abort bact to avoid failure of sqlcmd calls
  THROW $(MESSAGE_OFFSET)00, 'Oops. Use "UninstallSQLHub.sql" for this SQL Server hub.' ,1;
GO
:!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -dmaster -Q"DROP LOGIN $(HUB_ODBC_AGENT)"  
:!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -dmaster -Q"DROP LOGIN $(SPOKE_ADMIN)"     
:!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -dmaster -Q"DROP LOGIN $(SPOKE_BROKER)"    
:!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -dmaster -Q"DROP LOGIN $(HUB_ADMIN)"       
GO
