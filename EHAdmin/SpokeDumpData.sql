:setvar SPOKE_SERVER_NAME                       "."                            
:setvar EHDB_DMK_ENCRYPTION_PHRASE              "Memorize if U can!"           
:setvar PRIVATE_ENCRYPTION_PHRASE               "your personal secret"         
:r C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\Variables.sql             
GO 
:Connect $(SPOKE_SERVER_NAME)                                                  
GO
SET NOCOUNT ON;
-------------------------------------------------------------------------------
-- Cell Cryptography
-------------------------------------------------------------------------------
-- Table           
--      Column                     cryptobject                Authenticator/Salt           
-------------------------------------------------------------------------------
-- $(BOOKINGS_TABLE)         
--      Parameters NVARCHAR(4000)  audit symmetric key        KeyGuid NCHAR(36)
--      ErrorData NVARCHAR(4000)   portable symmetric key     Id NCHAR(36)
-- $(BACKUP_ACTIVITY_TABLE)  
--      BackupName NVARCHAR(448)   value key                  Id NCHAR(36
--      BackupNameBucket INT       checksum/random            Salted BackupName
--      UseHash BIT
--      BackupPath NVARCHAR(1024)  value key                  Salted BackupName 
--      Colophon INT               checksum/random            hashed from system value
--                         by Level: sys.message / key.key_guid / cert.thumbprint 
--      MAC NVARCHAR(128)          signing cert               book row checksum       
--      ErrorData NVARCHAR(4000)   portable signed key        Id NCHAR(36)
-- $(NAMEVALUE_ACTIVITY_TABLE)  
--      MAC NVARCHAR(128)          signing cert               book row checksum       
--      ErrorData NVARCHAR(4000)   portable signed key        Id NCHAR(36)
-- $(NAMEVALUES_TABLE)       
--      Name NVARCHAR(448)         value key                  Id as NCHAR                     
--      Value NVARCHAR(128)        value key                  Name 
--      NameBucket INT             checksum/hash/random       Salted Name 
--      ValueBucket INT            checksum/hash/random       Salted Value 
-- NAMEVALUETYPE USER-DEFINED TABLE TYPE   
--      Name NVARCHAR(448)         value key                  -->        <--- nothing! 
--      Value NVARCHAR(128)        value key                  Name     
-- $(OFFSITE_ACTIVITY_TABLE) 
--      MAC NVARCHAR(128)          signing cert               book row checksum 
--      ErrorData NVARCHAR(4000)   portable signed key        Id NCHAR(36)
-- $(REPORT_ACTIVITY_TABLE) 
--      MAC NVARCHAR(128)          signing cert               book row checksum       
--      ErrorData NVARCHAR(4000)   portable signed key        Id NCHAR(36)
-------------------------------------------------------------------------------
USE $(SPOKE_DATABASE);
OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
EXEC $(EHA_SCHEMA).OpenSession; 

SELECT '$(EHA_SCHEMA).$(BOOKINGS_TABLE)' AS TableName
SELECT Id
     , ServerName
     , ProcId
     , ObjectName
     , CAST( DECRYPTBYKEY( Parameters, 1, KeyGuid ) AS NVARCHAR(4000) ) AS [Parameters (decyphered)]
     , Status
     , CAST( DECRYPTBYKEY ( ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000) ) AS [ErrorData (decyphered)]
     , CreateUTCDT
     , CreateUser
FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
ORDER BY CreateUTCDT;

OPEN MASTER KEY DECRYPTION BY PASSWORD = '$(EHDB_DMK_ENCRYPTION_PHRASE)';

OPEN SYMMETRIC KEY $(NAME_SYMMETRIC_KEY)
DECRYPTION BY CERTIFICATE $(NAME_CERTIFICATE);

OPEN SYMMETRIC KEY $(VALUE_SYMMETRIC_KEY)
DECRYPTION BY CERTIFICATE $(VALUE_CERTIFICATE);

OPEN SYMMETRIC KEY $(FILE_SYMMETRIC_KEY)
DECRYPTION BY CERTIFICATE $(FILE_CERTIFICATE);

SELECT '$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)' AS TableName
SELECT Id
     , ServerName
     , DbName
     , NodeName
     , CAST(Node AS NVARCHAR(20) ) AS Node
     , CAST(DecryptByKey( BackupName ) AS NVARCHAR(448) ) AS [BackupName  (cast)] 
     , QUOTENAME(DecryptByKey( BackupName ) ) AS [BackupName (escaped)] 
     , FORMATMESSAGE ('%s', CAST( DecryptByKey( BackupName ) AS NVARCHAR(448) ) ) AS [BackupName (formatted)] 
     , BackupNameBucket
     , UseHash
     , CAST(DecryptByKey( BackupPath, 1, a.DbName) AS NVARCHAR(1024) ) AS [BackupPath (cast)]     
     , FORMATMESSAGE('%s', CAST( DecryptByKey( BackupPath, 1, a.DbName) AS NVARCHAR(1024) ) ) AS [BackupPath  (formatted)]     
     , QUOTENAME(DecryptByKey( BackupPath, 1, a.DbName) ) AS [BackupPath  (escaped)]     
     , BackupPhraseVersion                                  
     , KeyPhraseVersion                                  
     , Colophon                                  
     , Edition
     , (SELECT VERIFYSIGNEDBYCERT( CERT_ID( '$(AUTHENTICITY_CERTIFICATE)' )
                                 , CAST(CHECKSUM( b.Id
                                                , b.PROCID   
                                                , b.ObjectName
                                                , b.Parameters
                                                , b.KeyGuid
                                                , b.Status ) AS NVARCHAR(128) )
                                 , a.MAC )
        FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) AS b
        WHERE b.Id = a.Id )  AS [MAC Check]  
     , a.MAC                                  
     , a.Action                                  
     , a.Status                                  
     , a.CipherType                                  
     , CAST( DECRYPTBYKEY ( a.ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000) )  AS [ErrorInfo]
     , a.CreateUTCDT                                  
     , a.CreateUser                                  
FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) a 
ORDER BY CreateUTCDT;

SELECT '$(EHA_SCHEMA).$(NAMEVALUES_TABLE)' AS TableName
SELECT Id
     , ServerName
     , NameBucket
     , ValueBucket
     , Version
     , Name AS [Name (deciphered)]
     , DecryptedValue AS [Value (deciphered)]
     , CASE WHEN PATINDEX ( '%.Private', Name ) = 0 
            THEN 'not a private value'
            ELSE CAST( DECRYPTBYPASSPHRASE( '$(PRIVATE_ENCRYPTION_PHRASE)', DecryptedValue ) AS NVARCHAR(128))
            END AS [Private Value (deciphered)]
     , CreateUTCDT
     , CreateUser
FROM (SELECT CAST(DECRYPTBYKEY( Name, 1, CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(128) ) AS [Name]
           , CAST(DECRYPTBYKEY( Value
                              , 1
                              , CAST(DECRYPTBYKEY( Name
                                                 , 1
                                                 , CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(128) ) 
                              ) AS NVARCHAR(128) ) AS [DecryptedValue] 
           , Id, ServerName, NameBucket,ValueBucket, Version, CreateUTCDT, CreateUser
      FROM $(EHA_SCHEMA).$(NAMEVALUES_TABLE) ) AS derived 
ORDER BY CreateUTCDT;

SELECT '$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)' AS TableName
SELECT Id
     , ServerName
     , (SELECT VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                 , CAST(CHECKSUM( b.Id
                                                , b.PROCID   
                                                , b.ObjectName
                                                , b.Parameters
                                                , b.KeyGuid
                                                , b.Status ) AS NVARCHAR(128) )
                                 , n.MAC )
        FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) AS b
        WHERE b.Id = n.Id )  AS [MAC Check]                                 
     , MAC
     , Action
     , Status
     , CAST( DECRYPTBYKEY ( n.ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000) )  AS [ErrorData (deciphered)]
     , CreateUTCDT
     , CreateUser 
FROM $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) AS n
ORDER BY CreateUTCDT;

SELECT '$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)' AS TableName
SELECT n.ConversationHandle
     , n.ServerName
     , n.ConversationGroupId
     , n.MessageTypeName
     , CAST ( REPLACE( CAST( n.MessageBody AS NVARCHAR(MAX) ), '$#xOD;', '') AS XML )
     , n.HashIndex
     , n.Action
     , n.Status
     , CAST( DECRYPTBYKEY ( n.ErrorData
                          , 1
                          , CAST( n.ConversationHandle AS NVARCHAR(36) ) ) AS NVARCHAR(4000)) AS [ErrorInfo]
     , n.CreateUTCDT 
     , n.CreateUser 
FROM $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE) AS n

SELECT '$(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)' AS TableName
SELECT a.Id
     , a.ServerName
     , (SELECT VERIFYSIGNEDBYCERT( CERT_ID('(AUTHENTICITY_CERTIFICATE)')
                                 , CAST(CHECKSUM( b.Id
                                                , b.PROCID   
                                                , b.ObjectName
                                                , b.Parameters
                                                , b.KeyGuid
                                                , b.Status ) AS NVARCHAR(128) )
                                 , a.MAC )
        FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) AS b
        WHERE b.Id = a.Id )  AS [MAC Check]  
     , a.MAC
     , a.Action
     , a.Status
     , CAST( DECRYPTBYKEY ( a.ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000)) AS [ErrorInfo]
     , a.CreateUTCDT 
     , a.CreateUser 
FROM $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) a
ORDER BY a.CreateUTCDT;

SELECT '$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)' AS TableName
SELECT a.Id
     , a.ServerName
     , a.Action
     , a.Duration_ms
     , a.RowsReturned
     , (SELECT VERIFYSIGNEDBYCERT( CERT_ID('(AUTHENTICITY_CERTIFICATE)')
                                 , CAST(CHECKSUM( b.Id
                                                , b.PROCID   
                                                , b.ObjectName
                                                , b.Parameters
                                                , b.KeyGuid
                                                , b.Status ) AS NVARCHAR(128) )
                                 , a.MAC )
        FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) AS b
        WHERE b.Id = a.Id )  AS [MAC Check]  
     , a.MAC
     , a.Status
     , CAST( DECRYPTBYKEY ( a.ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000)) AS [ErrorInfo]
     , a.CreateUTCDT 
     , a.CreateUser 
FROM $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) AS a;

SELECT '$(EHA_SCHEMA).$(RESTORES_FILETABLE) FILETABLE' AS TableName
-- using row versioning so must use a hint here
SELECT stream_id
     , file_stream
     , name
     , path_locator
     , parent_path_locator
     , file_type
     , cached_file_size
     , creation_time
     , last_write_time
     , last_access_time
     , is_directory
     , is_offline
     , is_hidden
     , is_readonly
     , is_archive
     , is_system
     , is_temporary
FROM $(EHA_SCHEMA).$(RESTORES_FILETABLE) WITH (READCOMMITTEDLOCK);

CLOSE ALL SYMMETRIC KEYS;

SELECT *
FROM sys.dm_cdc_log_scan_sessions
WHERE log_record_count > 0
ORDER BY session_id;

SELECT [InitiatorQueue] AS [Initiator Queue Msg Count]
      , [sysxmitqueue] AS [Transmission Queue Msg Count]
      , [TargetQueue] AS [Target Queue Msg Count]
FROM (
      SELECT po.name AS name, p.rows
      FROM sys.objects AS o
      JOIN sys.partitions AS p 
      ON p.object_id = o.object_id
      JOIN sys.objects AS po 
      ON o.parent_object_id = po.object_id
      WHERE po.name = 'InitiatorQueue'
      AND SCHEMA_NAME(po.schema_id) = '$(EHA_SCHEMA)'
      AND p.index_id = 1
    UNION ALL 
      SELECT o.name AS name, p.rows
      FROM sys.objects AS o
      JOIN sys.partitions AS p 
      ON p.object_id = o.object_id
      WHERE o.name = 'sysxmitqueue'
    UNION ALL
      SELECT po.name AS name, p.rows
      FROM sys.objects AS o
      JOIN sys.partitions AS p 
      ON p.object_id = o.object_id
      JOIN sys.objects AS po 
      ON o.parent_object_id = po.object_id
      WHERE po.name = 'TargetQueue'
      AND SCHEMA_NAME(po.schema_id) = '$(EHA_SCHEMA)'
      AND p.index_id = 1 
                          ) AS SourceData
PIVOT (SUM(rows) 
FOR SourceData.name 
IN ( [InitiatorQueue]
    , [sysxmitqueue]
    , [TargetQueue] ) ) AS PivotTable;     

--Service Broker contents
SELECT e.conversation_handle
     , e.conversation_id
     , e.conversation_group_id
     , IIF( is_initiator=1
          , 'Initiator'
          , 'Target') AS [BrokerRole]
     , IIF( is_initiator=1
          , e.send_sequence
          , e.receive_sequence ) AS [sequence]
     , IIF ( q.is_receive_enabled = 1 AND q.is_enqueue_enabled = 1 
           , IIF ( q.is_activation_enabled = 1
                 , 'Enabled & Activated'
                 ,'ACTIVATION DISABLED' )
           ,'QUEUE DISABLED' ) AS Status
     , q.activation_procedure
     , c.name AS [service_contract]
     , s.name AS [service]
     , e.state_desc
     , e.far_service
     , object_name(q.object_id) AS [queue]
     , m.state AS [dm state]
     , m.last_activated_time
     , e.dialog_timer
FROM sys.service_queues AS q
JOIN sys.services AS s
ON s.service_queue_id = q.object_id
LEFT JOIN sys.dm_broker_queue_monitors AS m
ON m.queue_id = q.object_id
LEFT JOIN sys.conversation_endpoints AS e
ON e.service_id =  s.service_id
JOIN sys.service_contracts AS c
ON e.service_contract_id = c.service_contract_id
ORDER BY is_initiator desc; 

/*

select *, try_cast(message_body AS XML) 
from EventNotificationErrorsQueue

select *, try_cast(message_body AS XML) 
from eha.InitiatorQueue -- sender writes message here

select *, ISNULL( try_cast(message_body AS XML), try_cast(message_body AS NVARCHAR(MAX) ) ) 
from sys.transmission_queue  -- system object - sql server moves message here when it pulls it off the initiator

select *, ISNULL( try_cast(message_body AS XML), try_cast(message_body AS NVARCHAR(MAX) ) ) 
from eha.TargetQueue WITH(NOLOCK) -- then delivers it here when it can

select service_contract_name
     , message_type_name
     , DATALENGTH(message_body) as MessageSize 
from eha.TargetQueue

-- DMVs
select object_name(queue_id), * from sys.dm_broker_queue_monitors WHERE database_id = DB_ID();
select * from sys.dm_broker_activated_tasks
select * from sys.dm_broker_connections

select name
     , activation_procedure
     , [is_activation_enabled]
     , [is_receive_enabled]
     , [is_enqueue_enabled] 
from sys.service_queues;  
--WHERE name IN ( 'TargetQueue'
--              , 'InitiatorQueue');

*/


/*
-- to enable queue (so that [is_receive_enabled] = 1, [is_enqueue_enabled] = 1)
ALTER QUEUE eha.InitiatorQueue
WITH STATUS = ON
-or-
ALTER QUEUE eha.TargetQueue
WITH STATUS = ON

--  [is_activation_enabled] = 1
ALTER QUEUE eha.InitiatorQueue
WITH ACTIVATION (STATUS = ON);
-or-
ALTER QUEUE eha.TargetQueue
WITH ACTIVATION (STATUS = ON);

-- to debug the activation procedure, set queue activation OFF and step into procedure
ALTER QUEUE InitiatorQueue
WITH ACTIVATION (STATUS = OFF);
-or-
ALTER QUEUE eha.TargetQueue
WITH ACTIVATION (STATUS = OFF);

-- to start debug, using SSMS highlight following line hit F11 twice
[eha].[TargetActivation]
[eha].[InitiatorActivation]
*/

/* clearing the target queue
SELECT * FROM sys.conversation_endpoints

SELECT 'END CONVERSATION ''' + CAST(conversation_handle AS NVARCHAR(MAX)) + ''' WITH CLEANUP' 
FROM sys.conversation_endpoints
*/