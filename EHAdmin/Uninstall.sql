-- UNINSTALL

-- cleans out container's recycle bin but not real files!?
--:!!if exist X:\ DEL X:\*.* /Q /S 
--:!!if exist X:\ DIR X:\*.* /N /Q /R /S
SET NOCOUNT ON;
USE ehdb;

IF NOT EXISTS (SELECT * FROM sys.server_audits 
                WHERE name = 'ehaSchemaAudit' ) 
  DROP SERVER AUDIT ehaSchemaAudit;
IF EXISTS ( SELECT * 
            FROM sys.server_event_notifications
            WHERE name = 'DDLChangesSrv' )
  DROP EVENT NOTIFICATION DDLChangesSrv ON SERVER;

ALTER DATABASE ehdb SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
IF FILE_ID('ehdb_filestreams') IS NOT NULL
  ALTER DATABASE ehdb REMOVE FILE ehdb_filestreams;
IF OBJECT_ID('eha.Restores', 'U') IS NOT NULL
  DROP TABLE eha.Restores;
IF FILE_ID('ehdb_filetables') IS NOT NULL
  ALTER DATABASE ehdb REMOVE FILE ehdb_filetables;

USE master;
DROP DATABASE ehdb;

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

DROP CERTIFICATE TDECertificate;
-- only drop master's Master Key if it was added by this script!
DROP MASTER KEY;

EXEC sp_droplinkedsrvlogin 'OffsiteLinkedServer', NULL;
EXEC sp_dropserver 'OffsiteLinkedServer';

-- dismount the truecrypt container if desired
--:!!if exist X:\ "I:\TrueCrypt.exe" /q /s /d X /f)\

