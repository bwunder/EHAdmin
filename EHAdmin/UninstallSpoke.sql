-- UNINSTALL spoke
-- uninstall for hub is drop database
SET NOCOUNT ON;

IF DB_ID('ehdb') IS NOT NULL
  EXEC sp_executesql N'use ehdb;
    ALTER DATABASE ehdb SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    IF FILE_IDEX(''ehdb_filestreams'') IS NOT NULL
      ALTER DATABASE ehdb REMOVE FILE ehdb_filestreams;
    IF OBJECT_ID(''eha.Restores'', ''U'') IS NOT NULL
    DROP TABLE eha.Restores;
  IF FILE_ID(''ehdb_filetables'') IS NOT NULL
    ALTER DATABASE ehdb REMOVE FILE ehdb_filetables;'

USE master;
IF DB_ID('ehdb') IS NOT NULL 
  DROP DATABASE ehdb;
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
            WHERE s.name = N'OffsiteLinkedServer' 
            AND l.remote_name = N'bwunder' )
  EXEC sp_droplinkedsrvlogin 'OffsiteLinkedServer', NULL;
IF EXISTS ( SELECT * 
            FROM sys.servers s
            WHERE s.name = N'OffsiteLinkedServer' )
  EXEC sp_dropserver 'OffsiteLinkedServer';
GO
:!!if exist X:\ DIR X:\*.* /N /Q /R /S
-- cleans out container's recycle bin but not real files!?
--:!!if exist X:\ DEL X:\*.* /Q /S 
-- dismount the truecrypt container if desired
--:!!if exist X:\ "E:\TrueCrypt\EHA\TrueCrypt.exe" /q /s /d X /f)\
GO