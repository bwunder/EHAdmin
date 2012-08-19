-- UNINSTALL spoke
-- the master Database Master Key must be manually dropped after this script is successfully executed if not needed
-- unfortunately, the decryption key or phrase is not required to drop a master key or certificate so its:
-- USE master; DROP MASTER KEY;

-- setvars from here are needed by spoke uninstall
:setvar HUB_LINKED_SERVER_NAME                 "Hub"                    -- "<[HUB_LINKED_SERVER_NAME],SYSNAME,Hub>"              
:setvar HUB_SERVER_NAME                        "BWUNDER-PC\ELEVEN"      -- "<[HUB_LINKED_SERVER_NAME],SYSNAME,BWUNDER-PC\ELEVEN>"
-- synonyms
:setvar BOOKINGS_SYNONYM                       "zBookings"             
:setvar BACKUPS_SYNONYM                        "zBackups"              
:setvar BACKUP_ACTIVITY_SYNONYM                "zBackupActivity"       
:setvar HUB_ACTIVITY_SYNONYM                   "zHubActivity"          
:setvar NAMEVALUES_SYNONYM                     "zNameValues"           
:setvar NAMEVALUE_ACTIVITY_SYNONYM             "zNameValueActivity"    
:setvar NOTIFICATION_ACTIVITY_SYNONYM          "zNotificationActivity" 
:setvar SPOKE_ACTIVITY_SYNONYM                 "zSpokeActivity"        
:setvar REPORT_ACTIVITY_SYNONYM                "zReportActivity"       
--- export file extensions                                              
:setvar MASTER_KEY_BACKUP_EXT                  ".keybak"               
:setvar PRIVATE_KEY_BACKUP_EXT                 ".prvbak"               
:setvar PUBLIC_KEY_BACKUP_EXT                  ".cerbak"               

-- setvars from here are needed by hub install
-- principals 
:setvar SPOKE_ADMIN                            "SpokeAdmin"            -- "<[SPOKE_ADMIN],SYSNAME,SpokeAdmin>"                   
:setvar SPOKE_ADMIN_PASSWORD                   "sj*%tFE#4RfHgf"        -- "<[SPOKE_ADMIN_PASSWORD],PASSPHRASE,sj*%tFE#4RfHgf>"   
:setvar SPOKE_BROKER                           "SpokeBroker"           -- "<[SPOKE_BROKER],SYSNAME,SpokeBroker>"                 
:setvar SPOKE_BROKER_PASSWORD                  "sk*%tFE#4RfHge"        -- "<[SPOKE_BROKER_PASSWORD],PASSPHRASE,sk*%tFE#4RfHge>"  
--databases
:setvar SPOKE_DATABASE                         "ehdb"                  -- "<[SPOKE_DATABASE],SYSNAME,ehdb>"                      
:setvar HUB_DATABASE                           "ehHub"                 
-- schema
:setvar EHA_SCHEMA                             "eha"                   
-- roles
:setvar HUB_ADMIN_ROLE                         "HubAdministrators"     
:setvar SPOKE_ADMIN_ROLE                       "SpokedAdministrators"  
:setvar SPOKE_BROKER_ROLE                      "SpokeBrokers"          
-- tables
:setvar BOOKINGS_TABLE                         "Bookings"              
:setvar BACKUPS_TABLE                          "Backups"               
:setvar BACKUP_ACTIVITY_TABLE                  "BackupActivity"        
:setvar HUB_ACTIVITY_TABLE                     "HubActivity"           -- created on hub only - use synonym at spoke             
:setvar NAMEVALUES_TABLE                       "NameValues"            
:setvar NAMEVALUE_ACTIVITY_TABLE               "NameValueActivity"     
:setvar NOTIFICATION_ACTIVITY_TABLE            "NotificationActivity"  
:setvar SPOKE_ACTIVITY_TABLE                   "SpokeActivity"         
:setvar REPORT_ACTIVITY_TABLE                  "ReportActivity"        
-- filetable
:setvar FILESTREAM_FILEGROUP                   "FilestreamFileGroup"   
:setvar FILESTREAM_FILE                        "FilestreamFile"        
:setvar FILETABLE_DIRECTORY                    "FiletableDirectory"    
:setvar RESTORES_FILETABLE                     "Restores"              
GO
SET NOCOUNT ON;
IF DB_ID('$(SPOKE_DATABASE)') IS NOT NULL 
  BEGIN
    EXEC sp_executesql N'USE $(SPOKE_DATABASE);
ALTER QUEUE $(EHA_SCHEMA).TargetQueue WITH ACTIVATION ( STATUS = OFF );
ALTER DATABASE $(SPOKE_DATABASE) SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
IF OBJECT_ID(''$(EHA_SCHEMA).$(RESTORES_FILETABLE)'', ''U'') IS NOT NULL
  DROP TABLE $(EHA_SCHEMA).$(RESTORES_FILETABLE);
IF FILE_IDEX(''$(FILESTREAM_FILE)'') IS NOT NULL
  ALTER DATABASE $(SPOKE_DATABASE) REMOVE FILE $(FILESTREAM_FILE);
IF FILE_ID(''$(FILETABLE_DIRECTORY)'') IS NOT NULL
  ALTER DATABASE $(SPOKE_DATABASE) REMOVE FILE $(FILETABLE_DIRECTORY);';
    -- meanwhile, back in master...
    DROP DATABASE $(SPOKE_DATABASE);

  END    
GO

IF EXISTS ( SELECT * 
            FROM sys.server_event_notifications
            WHERE name = 'DDLChangesSrv' )
  DROP EVENT NOTIFICATION DDLChangesSrv ON SERVER;

IF EXISTS (SELECT * FROM sys.server_audits
           WHERE name = 'ehaSchemaAudit' ) 
  BEGIN
    ALTER SERVER AUDIT ehaSchemaAudit 
    WITH (STATE = OFF);
    DROP SERVER AUDIT ehaSchemaAudit;
  END

DECLARE @Message_Id INT, @MaxId INT;
SET @Message_Id = 2147483600 -- MESSAGE_OFFSET
SET @MaxId = @Message_Id + 47 
WHILE @Message_Id < @MaxId
  BEGIN  
    IF EXISTS (SELECT * FROM sys.messages
               WHERE message_Id = @Message_Id)
      EXEC sp_dropmessage @Message_Id; 
    SET @Message_Id += 1;
  END

IF CERT_ID('TDECertificate') IS NOT NULL
  DROP CERTIFICATE TDECertificate;

-- only drop master's Master Key if it was added by InstallSpoke.sql !!!
--DROP MASTER KEY;

IF EXISTS ( SELECT * 
            FROM sys.linked_logins l
            JOIN sys.servers s
            ON l.server_id = s.server_id
            WHERE s.name  = N'$(HUB_LINKED_SERVER_NAME)' 
            AND l.remote_name = N'$(SPOKE_ADMIN)' )
  EXEC sp_droplinkedsrvlogin N'$(HUB_LINKED_SERVER_NAME)', '$(SPOKE_ADMIN)';
IF EXISTS ( SELECT * 
            FROM sys.linked_logins l
            JOIN sys.servers s
            ON l.server_id = s.server_id
            WHERE s.name = N'$(HUB_LINKED_SERVER_NAME)' 
            AND l.remote_name = N'$(SPOKE_BROKER)' )
  EXEC sp_droplinkedsrvlogin N'$(HUB_LINKED_SERVER_NAME)', '$(SPOKE_BROKER)';
IF EXISTS ( SELECT * 
            FROM sys.servers s
            WHERE s.name = N'$(HUB_LINKED_SERVER_NAME)' )
  EXEC sp_dropserver '$(HUB_LINKED_SERVER_NAME)';
GO
IF EXISTS ( SELECT * 
            FROM sys.linked_logins l
            JOIN sys.servers s
            ON l.server_id = s.server_id
            WHERE s.name = N'$(HUB_SERVER_NAME)' 
            AND l.remote_name = N'$(SPOKE_ADMIN)' )
  EXEC sp_droplinkedsrvlogin '$(HUB_SERVER_NAME)', '$(SPOKE_ADMIN)';
IF EXISTS ( SELECT * 
            FROM sys.linked_logins l
            JOIN sys.servers s
            ON l.server_id = s.server_id
            WHERE s.name = N'$(HUB_SERVER_NAME)'  
            AND l.remote_name = N'$(SPOKE_BROKER)' )
  EXEC sp_droplinkedsrvlogin  '$(HUB_SERVER_NAME)', '$(SPOKE_BROKER)';
IF EXISTS ( SELECT * 
            FROM sys.servers s
            WHERE s.name = N'$(HUB_SERVER_NAME)' 
            AND s.server_id > 0 ) -- do not drop the local server
  EXEC sp_dropserver '$(HUB_SERVER_NAME)';
-- should only be development where hub and spoke are on same slq instance 
IF DB_ID('$(HUB_DATABASE)') IS NULL               
  BEGIN
    DROP LOGIN $(SPOKE_ADMIN);
    DROP LOGIN $(SPOKE_BROKER);
  END
GO