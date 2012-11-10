--:setvar DROP_master_MASTER_KEY           "0"                                   
--:setvar EXPORT_PATH "E:\"
:r C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\Variables.sql             
GO
SET NOCOUNT ON
USE master;
IF DB_ID('$(SPOKE_DATABASE)') IS NOT NULL 
  BEGIN
    EXEC sp_executesql N'USE $(SPOKE_DATABASE);
IF EXISTS (SELECT * FROM sys.service_queues 
           WHERE name = ''TargetQueue''
           AND schema_id = SCHEMA_ID( ''$(EHA_SCHEMA)'' )
           AND is_activation_enabled = 1 ) 
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
SET @Message_Id = $(MESSAGE_OFFSET)00;
SET @MaxId = $(MESSAGE_OFFSET)47; 
WHILE @Message_Id < @MaxId
  BEGIN  
    IF EXISTS (SELECT * FROM sys.messages
               WHERE message_Id = @Message_Id)
      EXEC sp_dropmessage @Message_Id; 
    SET @Message_Id += 1;
  END

IF CERT_ID('TDECertificate') IS NOT NULL
  DROP CERTIFICATE TDECertificate;

-- only drop master's Master Key if extended property added by InstallSpoke.sql created key is found
IF EXISTS (SELECT * FROM sys.extended_properties Where name = N'Origin' and value = N'InstallSpoke') 
  DROP MASTER KEY;
ELSE
  RAISERROR('skipping DROP of master database Master Key',0,0);

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
:!! CMD.EXE /C DEL $(EXPORT_PATH)*.*bak /Q
GO