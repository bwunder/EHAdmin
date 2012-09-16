:setvar PRIVATE_ENCRYPTION_PHRASE              "y0ur secreT goes here!" -- "<[PASSPHRASE_ENCRYPTION_PHRASE],VARCHAR,y0ur secreT goes here!>"              
-- key backups go here - restores from hub are located in FileTable subfolder under this location (so no UNC)
:setvar EXPORT_PATH                            "G:\"                    -- give Full Control to SQL Server service account                                
-- the life of the key is the life of the user's connection and it lives in tempdb just like any # temp object 
:setvar SESSION_SYMMETRIC_KEY                  "#SessionSymmetricKey"   -- "<[SESSION_SYMMETRIC_KEY],SYSNAME,#SessionSymmetricKey>"                       
:setvar SESSION_KEY_SOURCE                     "SessionKeySource"       -- "<[SESSION_KEY_SOURCE],NVARCHAR,SessionKeySource>"                             
:setvar SESSION_KEY_IDENTITY                   "SessionKeyIdentity"     -- "<[SESSION_KEY_IDENTITY],NVARCHAR,SessionKeyIdentity>"                         
:setvar SESSION_KEY_ENCRYPTION_PHRASE          "NOT checked 4 hardness" -- "<[SESSION_KEY_ENCRYPTION_PHRASE],PASSPHRASE,NOT checked 4 hardness>"          
-- master database encryption hierarchy (hierarchy for SPOKE_DATEBASE TDE certificate)  
:setvar master_DMK_ENCRYPTION_PHRASE           "Qu&6G f%3Fe2DUOL@yc?f"  -- "<[master_DMK_ENCRYPTION_PHRASE],PASSPHRASE*,Qu&6G f%3Fe2DUOL@yc?f>"           
:setvar master_DMK_BACKUP_PHRASE               "Vu&6Gf %3Fe3CVOR@xcf?"  -- "<[master_DMK_BACKUP_PHRASE],PASSPHRASE*,Vu&6Gf %3Fe3CVOR@xcf?>"               
:setvar TDE_CERTIFICATE                        "TDECertificate"         -- "<[TDE_CERTIFICATE] - for EHDB TDE,SYSNAME,TDECertificate>"                    
:setvar TDE_CERTIFICATE_ALGORITHM              "AES_256"                -- "<[TDE_CERTIFICATE_ALGORITHM],SYSNAME,AES_256>"                                
:setvar TDE_CERTIFICATE_BACKUP_PHRASE          "Wu&6Gf% 3Fe4VBNM@wc?f"  -- "<[TDE_CERTIFICATE_BACKUP_PHRASE],PASSPHRASE*,Wu&6Gf% 3Fe4VBNM@wc?f>"          
-- EHDB database encryption hierarchy
:setvar AUDIT_CERTIFICATE                      "AuditCertificate"       -- "<[AUDIT_CERTIFICATE],SYSNAME,AuditCertificate>"                               
:setvar AUDIT_CERTIFICATE_ENCRYPTION_PHRASE    "Au&6Gf% 3Fe14CQAN@wcf?" -- "<[AUDIT_CERTIFICATE_ENCRYPTION_PHRASE] ,PASSPHRASE*,Au&6Gf% 3Fe14CQAN@wcf?>"  
:setvar AUDIT_CERTIFICATE_BACKUP_PHRASE        "Bu&6Gf%3F e14VUAP@wc?f" -- "<[AUDIT_CERTIFICATE_BACKUP_PHRASE],PASSPHRASE,Bu&6Gf%3F e14VUAP@wc?f>"        
:setvar AUDIT_SYMMETRIC_KEY                    "AuditKey"               -- "<[AUDIT_SYMMETRIC_KEY],SYSNAME,AuditKey>"                                     
:setvar AUDIT_KEY_ENCRYPTION_ALGORITHM         "AES_256"                -- "<[AUDIT_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                           
:setvar AUTHENTICITY_CERTIFICATE               "AuthenticityCertificate"-- "<[AUTHENTICITY_CERTIFICATE],SYSNAME,AuthenticityCertificate>                  
:setvar AUTHENTICITY_CERTIFICATE_BACKUP_PHRASE "Ou&6Gf%3Fe11LO UD@wc?f" -- "<[AUTHENTICITY_CERTIFICATE_BACKUP_PHRASE],PASSPHRASE*,Ou&6Gf%3Fe11LO UD@wc?f>"
:setvar EHDB_DMK_BACKUP_PHRASE                 "Ru&6Gf%3F e6LOUD@wc?f"  -- "<[EHDB_DMK_BACKUP_PHRASE],PASSPHRASE*,Ru&6Gf%3F e6LOUD@wc?f>"                 
:setvar EHDB_DMK_ENCRYPTION_PHRASE             "Memorize this 1 4 sure!"-- "<[EHDB_DMK_ENCRYPTION_PHRASE],PASSPHRASE*,Memorize this 1 4 sure!>"           
:setvar ERROR_SYMMETRIC_KEY                    "ErrorKey"               -- "<[ERROR_SYMMETRIC_KEY],SYSNAME,ErrorKey>"                                     
:setvar ERROR_KEY_ENCRYPTION_ALGORITHM         "AES_256"                -- "<[ERROR_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                           
:setvar ERROR_KEY_ENCRYPTION_PHRASE            "Yu&6Gf %3Fe13FZRE@wc?f" -- "<[ERROR_KEY_ENCRYPYION_PHRASE],PASSPHRASE*,Yu&6Gf %3Fe13FZRE@wc?f>"           
:setvar ERROR_KEY_SOURCE                       "i$Db8d b vf989sb d&ubsG"-- "<[ERROR_KEY_SOURCE_PHRASE],PASSPHRASE*,i$Db8d b vf989sb d&ubsG>"              
:setvar ERROR_KEY_IDENTITY                     "t {bleS*&(d84vr4 67vfes"-- "<[ERROR_KEY_IDENTITY],PASSPHRASE*,t {bleS*&(d84vr4 67vfes>"                   
:setvar EVENT_CERTIFICATE                      "EventCertificate"       -- "<[EVENT_CERTIFICATE],SYSNAME,EventCertificate>                                
:setvar EVENT_CERTIFICATE_BACKUP_PHRASE        "oU7^gF5%fE!1lI ouD2WC/F"-- "<[EVENT_CERTIFICATE_BACKUP_PHRASE],PASSPHRASE*,oU7^gF5#fE!!l ouD2WC/F>"       
:setvar FILE_CERTIFICATE                       "FileCertificate"        -- "<[FILE_CERTIFICATE],SYSNAME,FileCertificate>                                  
:setvar FILE_CERTIFICATE_ENCRYPTION_PHRASE     "sd89f7ny*&NH 8E43BHFjh" -- "<[FILE_CERTIFICATE_ENCRYPTION_PHRASE],PASSPHRASE*,sd89f7ny*&NH 8E43BHFjh>"    
:setvar FILE_CERTIFICATE_BACKUP_PHRASE         "d QW87!DtsHF387w$32VFw" -- "<[FILE_CERTIFICATE_BACKUP_PHRASE],PHRASE*,d QW87!DtsHF387w$32VFw>"            
:setvar FILE_SYMMETRIC_KEY                     "FileKey"                -- "<[FILE_SYMMETRIC_KEY],SYSNAME,FileKey>"                                       
:setvar FILE_KEY_ENCRYPTION_ALGORITHM          "AES_256"                -- "<[FILE_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                            
:setvar NAME_CERTIFICATE                       "NameCertificate"        -- "<[OBJECT_CERTIFICATE],SYSNAME,NameCertificate>                                
:setvar NAME_CERTIFICATE_ENCRYPTION_PHRASE     "Fe9 ROIT@wc?fZu&6Gf%3"  -- "<[OBJECT_CERTIFICATE_ENCRYPTION_PHRASE],PASSPHRASE*,Fe9 ROIT@wc?fZu&6Gf%3>"   
:setvar NAME_CERTIFICATE_BACKUP_PHRASE         "Fe10L SUD@wcf?Lu&6Gf%3" -- "<[OBJECT_CERTIFICATE_BACKUP_PHRASE],PHRASE*,Fe10L SUD@wcf?Lu&6Gf%3>"          
:setvar NAME_SYMMETRIC_KEY                     "NameKey"                -- "<[NAME_SYMMETRIC_KEY],SYSNAME,ValueKey>"                                      
:setvar NAME_KEY_ENCRYPTION_ALGORITHM          "AES_256"                -- "<[NAME_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                            
:setvar OBJECT_CERTIFICATE                     "ObjectCertificate"      -- "<[OBJECT_CERTIFICATE],SYSNAME,ObjectCertificate>                              
:setvar OBJECT_CERTIFICATE_ENCRYPTION_PHRASE   "Lu&6Gf%3Fe9 ROIT@wc?f"  -- "<[OBJECT_CERTIFICATE_ENCRYPTION_PHRASE],PASSPHRASE*,Lu&6Gf%3Fe9 ROIT@wc?f>"   
:setvar OBJECT_CERTIFICATE_BACKUP_PHRASE       "Zu&6Gf%3Fe10L SUD@wcf?" -- "<[OBJECT_CERTIFICATE_BACKUP_PHRASE],PHRASE*,Zu&6Gf%3Fe10L SUD@wcf?>"          
:setvar SMK_BACKUP_PHRASE                      "Ku&6 Gf43Fe1 UIOE@zcf?" -- "<[SMK_BACKUP_PHRASE] Service Master Key,PASSPHRASE*,Ku&6 Gf43Fe1 UIOE@zcf?>"  
:setvar VALUE_CERTIFICATE                      "ValueCertificate"       -- "<[VALUE_CERTIFICATE],SYSNAME,ValueCertificate>"                               
:setvar VALUE_CERTIFICATE_BACKUP_PHRASE        "Mu&6Gf%3Fe 8VKUA@wcf?"  -- "<[VALUE_CERTIFICATE_BACKUP_PHRASE],PASSPHRASE,Mu&6Gf%3Fe 8VKUA@wcf?>"         
:setvar VALUE_SYMMETRIC_KEY                    "ValueKey"               -- "<[VALUE_SYMMETRIC_KEY],SYSNAME,ValueKey>"                                     
:setvar VALUE_KEY_ENCRYPTION_ALGORITHM         "AES_256"                -- "<[VALUE_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                           

:setvar HASHBYTES_ALGORITHM                    "SHA2_512"               -- "<[HASHBYTES_ALGORITHM],SYSNAME,SHA2_512>"                                     
-- this value times 100 is used as the floor for 50 messages from sys.messages
:setvar MESSAGE_OFFSET                         "21474836"               -- "<[MESSAGE_OFFSET] - between 500 and 21474836, INT,21474836>"                  
:setvar MIN_PHRASE_LENGTH                      "21"                     -- "<[MIN_PHRASE_LENGTH] - Min phrase length (max is 128),TINYINT,21>"            
-- for run-time schema validation - must be correct   
:setvar OBJECT_COUNT                           60                       -- "<[OBJECT_COUNT],INT,60>"                                                      
:setvar TABLE_COUNT                            8                        -- "<[TABLE_COUNT],INT,8>"                                                        
-- number of active traces allowed during a white listed proc's execution (if default trace enabled set to 1)
:setvar MAX_TRACE_COUNT                        1                        -- "<[VALUE_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                           
-- use the namebucket for the file name (1) or the clear text (0)
:setvar USE_HASH_FOR_FILENAME                  "1"                      -- "<[USE_HASH_FOR_FILENAME],BIT,0>"                                              
-- prefix for event notifications
:setvar EVENT_NOTIFICATION                     "DDLChanges"             -- "<[EVENT_NOTIFICATION],SYSNAME,DDLChanges>"                                    
-- uses DATASOURCE if SQL Azure SERVER_NAME if on-premise, virtual machine or private cloud 
:setvar HUB_DATASOURCE                         "Hub"                    -- "<[HUB_DATASOURCE],SYSNAME,Hub>"                                               
:setvar HUB_SERVER_NAME                        "BWUNDER-PC\ELEVEN"      -- "<[HUB_DATASOURCE],SYSNAME,Hub>"                                               
-- copy setvars below to UnistallSpoke.sql
:setvar HUB_LINKED_SERVER_NAME                 "Hub"                    -- "<[HUB_LINKED_SERVER_NAME],SYSNAME,Hub>"                                       
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
-- copy setvars below to InstallHub.sql
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
:setvar HUB_ACTIVITY_TABLE                     "HubActivity"           
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
USE $(SPOKE_DATABASE);

/* run a report 
EXEC $(EHA_SCHEMA).ReportRecentSpokeErrors;
EXEC $(EHA_SCHEMA).ReportRecentAdminActivity;
EXEC $(EHA_SCHEMA).ReportActivityHistory;

-- if query fails there is link problem to offsite 
SELECT * FROM $(SPOKE_DATABASE).$(EHA_SCHEMA).zBookings
*/

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
OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';

OPEN SYMMETRIC KEY $(AUDIT_SYMMETRIC_KEY)
DECRYPTION BY CERTIFICATE $(AUDIT_CERTIFICATE)
WITH PASSWORD = '$(AUDIT_CERTIFICATE_ENCRYPTION_PHRASE)';

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