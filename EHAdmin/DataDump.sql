--SET NOCOUNT ON;
USE ehdb;
/* run a report 
EXEC eha.ReportErrors;
EXEC eha.ReportServerSummary;
EXEC eha.ReportActivityHistory;

-- if query fails there is link problem to offsite 
select * from ehdb.eha.zBookings
*/

-------------------------------------------------------------------------------
-- Cell Cryptography
-------------------------------------------------------------------------------
-- Table           
--      Column             Method                     Authenticator/Salt           
-------------------------------------------------------------------------------
-- $(BOOKINGS_TABLE)         
--      Parameters         audit key signed cert      Id as NCHAR
--      ErrorData          portable signed key        Id as NCHAR
-- $(BACKUP_ACTIVITY_TABLE)  
--      BackupName         value key DMK cert         Id as NCHAR
--      BackupNameBucket   checksum/random            Salted BackupName
--      UseHash 
--      BackupPath         value key                  Salted BackupName 
--      Colophon           checksum/random            hashed from system value
--                         by Level: sys.message / key.key_guid / cert.thumbprint 
--      MAC                signed cert                sig of book row checksum 
--      ErrorData          portable signed key        Id as NCHAR
-- $(CONTAINER_ACTIVITY_TABLE)       
--      FileName           value key                  Id as NCHAR
--      FilePath           value key                  FileName                  
--      MAC                cert signed                book row checksum 
--      ErrorData          portable key               Id as NCHAR  
-- $(CONTAINERS_TABLE)       
--      Signature          cert signed                FileImage 
-- $(NAMEVALUE_ACTIVITY_TABLE)  
--      MAC                signed cert                sig of book row checksum 
--      ErrorData          portable signed key        Id as NCHAR
-- $(NAMEVALUES_TABLE)       
--      Name               value key                  Id as NCHAR                     
--      Value              value key                  Name 
--      NameBucket         checksum/hash/random yes   Salted Name 
--      ValueBucket        checksum/hash/random yes   Salted Value 
-- NAMEVALUETYPE USER-DEFINED TABLE TYPE   
--      Name               value key                  -->        <--- nothing! 
--      Value              value key                  Name     
-- $(OFFSITE_ACTIVITY_TABLE) 
--      MAC                signed by cert             sig of book row checksum 
--      ErrorData          portable signed key        Id as NCHAR  
-- $(REPORT_ACTIVITY_TABLE) 
--      MAC                signed cert          no    sig of book row checksum 
--      ErrorData          portable signed key        Id as NCHAR  
-------------------------------------------------------------------------------
OPEN SYMMETRIC KEY ErrorKey
DECRYPTION BY PASSWORD = 'Yu&6Gf %3Fe13FZRE@wc?f';

OPEN SYMMETRIC KEY AuditKey
DECRYPTION BY CERTIFICATE AuditCertificate
WITH PASSWORD = 'Au&6Gf% 3Fe14CQAN@wcf?';

SELECT 'eha.Bookings' AS TableName
SELECT * FROM eha.Bookings; 
SELECT Id
     , ServerName
     , ProcId
     , ObjectName
     , CAST( DECRYPTBYKEY( Parameters, 1, CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(4000) ) AS [Parameters (decyphered)]
     , Status
     , CAST( DECRYPTBYKEY ( ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000) ) AS [ErrorData (decyphered)]
     , CreateUTCDT
     , CreateUser
FROM eha.Bookings 
ORDER BY CreateUTCDT;

OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Memorize this 1 4 sure!';

OPEN SYMMETRIC KEY NameKey
DECRYPTION BY CERTIFICATE NameCertificate;

OPEN SYMMETRIC KEY ValueKey
DECRYPTION BY CERTIFICATE ValueCertificate;

OPEN SYMMETRIC KEY FileKey
DECRYPTION BY CERTIFICATE FileCertificate;

SELECT 'eha.NameValues' AS TableName
SELECT * FROM eha.NameValues;
SELECT Id
     , ServerName
     , NameBucket
     , ValueBucket
     , Version
     , Name AS [Name (deciphered)]
     , CASE WHEN PATINDEX ( '%.Private', Name ) = 0 
            THEN DecryptedValue
            ELSE CAST( DecryptByPassphrase( 'Private - not saved', DecryptedValue ) AS NVARCHAR(128))
            END AS [Value (deciphered)]
     , CreateUTCDT
     , CreateUser
FROM (SELECT CAST(DecryptByKey( Name, 1, CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(128) ) AS [Name]
           , CAST(DecryptByKey( Value
                              , 1
                              , CAST(DecryptByKey( Name
                                                 , 1
                                                 , CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(128) ) 
                              ) AS NVARCHAR(128) ) AS [DecryptedValue] 
           , Id, ServerName, NameBucket,ValueBucket, Version, CreateUTCDT, CreateUser
      FROM eha.NameValues ) AS derived 
ORDER BY CreateUTCDT;

SELECT 'eha.NameValueActivity' AS TableName
SELECT * FROM eha.NameValueActivity;
SELECT Id
     , ServerName
     , (SELECT VERIFYSIGNEDBYCERT( CERT_ID('AuthenticityCertificate') --$--(AUTHENTICITY_CERTIFICATE)')
                                 , CAST(CHECKSUM( b.Id
                                                , b.PROCID   
                                                , b.ObjectName
                                                , b.Parameters
                                                , b.Status ) AS NVARCHAR(128) )
                                 , n.MAC )
        FROM eha.Bookings AS b
        WHERE b.Id = n.Id )  AS [MAC Check]                                 
     , MAC
     , Action
     , Status
     , CAST( DECRYPTBYKEY ( n.ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000) )  AS [ErrorData (deciphered)]
     , CreateUTCDT
     , CreateUser 
FROM eha.NameValueActivity AS n
ORDER BY CreateUTCDT;

SELECT 'eha.BackupActivity' AS TableName
SELECT * FROM eha.BackupActivity;
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
     , (SELECT VERIFYSIGNEDBYCERT( CERT_ID('AuthenticityCertificate') --$--(AUTHENTICITY_CERTIFICATE)')
                                 , CAST(CHECKSUM( b.Id
                                                , b.PROCID   
                                                , b.ObjectName
                                                , b.Parameters
                                                , b.Status ) AS NVARCHAR(128) )
                                 , a.MAC )
        FROM eha.Bookings AS b
        WHERE b.Id = a.Id )  AS [MAC Check]  
     , a.MAC                                  
     , a.Action                                  
     , a.Status                                  
     , a.CipherType                                  
     , CAST( DECRYPTBYKEY ( a.ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000) )  AS [ErrorInfo]
     , a.CreateUTCDT                                  
     , a.CreateUser                                  
FROM eha.BackupActivity a 
ORDER BY CreateUTCDT;

SELECT 'eha.Containers' AS TableName
SELECT * FROM eha.Containers;
SELECT Id
     , ServerName
     , Tag
     , LEN(FileImage) AS [Size (Bytes)] 
     , VERIFYSIGNEDBYCERT( CERT_ID('AuthenticityCertificate')
                         , CAST(FileImage AS VARBINARY(8000) )
                         , Signature ) AS FileImageIsSigned
FROM eha.Containers;

SELECT 'eha.ContainerActivity' AS TableName
SELECT * FROM eha.ContainerActivity;
SELECT a.Id
     , a.ServerName
     , CAST(DecryptByKey( a.FileName, 1, CAST(a.Id AS NCHAR(36) ) ) AS NVARCHAR(448) ) AS [FileName (deciphered)] 
     , CAST(DecryptByKey( a.FilePath
                        , 1, CAST(DecryptByKey( a.FileName
                                              , 1, CAST(a.Id AS NCHAR(36) ) ) AS NVARCHAR(448) ) ) AS NVARCHAR(1024) ) AS [FilePath (deciphered)]     
     , a.SizeInBytes
     , (SELECT VERIFYSIGNEDBYCERT( CERT_ID('AuthenticityCertificate') --$--(AUTHENTICITY_CERTIFICATE)')
                                 , CAST(CHECKSUM( b.Id
                                                , b.PROCID   
                                                , b.ObjectName
                                                , b.Parameters
                                                , b.Status ) AS NVARCHAR(128) )
                                 , a.MAC )
        FROM eha.Bookings AS b
        WHERE b.Id = a.Id )  AS [MAC Check]  
     , a.MAC
     , a.Action 
     , a.Status 
     , CAST( DECRYPTBYKEY ( a.ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000)) AS [ErrorInfo]
     , a.CreateUTCDT 
     , a.CreateUser 
FROM eha.ContainerActivity AS a;

SELECT 'eha.NotificationActivity' AS TableName
SELECT * FROM eha.NotificationActivity;
SELECT Id
     , ServerName
     , ConversationHandle
     , ConversationGroupId
     , Message 
     , (SELECT VERIFYSIGNEDBYCERT( CERT_ID('AuthenticityCertificate') --$--(AUTHENTICITY_CERTIFICATE)')
                                 , CAST(CHECKSUM( b.Id
                                                , b.PROCID   
                                                , b.ObjectName
                                                , b.Parameters
                                                , b.Status ) AS NVARCHAR(128) )
                                 , a.MAC )
        FROM eha.Bookings AS b
        WHERE b.Id = a.Id )  AS [MAC Check]  
     , a.MAC
     , a.Action
     , a.Status
     , CAST( DECRYPTBYKEY ( a.ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000)) AS [ErrorInfo]
     , a.CreateUTCDT 
     , a.CreateUser 
FROM eha.NotificationActivity a

SELECT 'eha.OffsiteActivity' AS TableName
SELECT * FROM eha.OffsiteActivity;
SELECT a.Id
     , a.CaptureInstance
     , a.ServerName
     , a.Minlsn
     , a.MaxLsn
     , a.[RowCount]
     , (SELECT VERIFYSIGNEDBYCERT( CERT_ID('AuthenticityCertificate') --$--(AUTHENTICITY_CERTIFICATE)')
                                 , CAST(CHECKSUM( b.Id
                                                , b.PROCID   
                                                , b.ObjectName
                                                , b.Parameters
                                                , b.Status ) AS NVARCHAR(128) )
                                 , a.MAC )
        FROM eha.Bookings AS b
        WHERE b.Id = a.Id )  AS [MAC Check]  
     , a.MAC
     , a.Action
     , a.Status
     , CAST( DECRYPTBYKEY ( a.ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000)) AS [ErrorInfo]
     , a.CreateUTCDT 
     , a.CreateUser 
FROM eha.OffsiteActivity a
ORDER BY a.CreateUTCDT;

SELECT 'eha.ReportActivity' AS TableName
SELECT * FROM eha.ReportActivity;
SELECT a.Id
     , a.ServerName
     , a.ReportProcedure
     , a.Duration_ms
     , a.RowsReturned
     , (SELECT VERIFYSIGNEDBYCERT( CERT_ID('AuthenticityCertificate') --$--(AUTHENTICITY_CERTIFICATE)')
                                 , CAST(CHECKSUM( b.Id
                                                , b.PROCID   
                                                , b.ObjectName
                                                , b.Parameters
                                                , b.Status ) AS NVARCHAR(128) )
                                 , a.MAC )
        FROM eha.Bookings AS b
        WHERE b.Id = a.Id )  AS [MAC Check]  
     , a.MAC
     , a.Status
     , CAST( DECRYPTBYKEY ( a.ErrorData, 1, CAST(Id AS NCHAR(36)) ) AS NVARCHAR(4000)) AS [ErrorInfo]
     , a.CreateUTCDT 
     , a.CreateUser 
FROM eha.ReportActivity AS a;

---- filetable
--SELECT 'eha.Backups FILETABLE' AS TableName
--SELECT stream_id
--     , file_stream
--     , name
--     , path_locator
--     , parent_path_locator
--     , file_type
--     , cached_file_size
--     , creation_time
--     , last_write_time
--     , last_access_time
--     , is_directory
--     , is_offline
--     , is_hidden
--     , is_readonly
--     , is_archive
--     , is_system
--     , is_temporary
--FROM eha.Backups WITH (READCOMMITTEDLOCK);
SELECT 'eha.Restores FILETABLE' AS TableName
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
FROM eha.Restores WITH (READCOMMITTEDLOCK);

CLOSE ALL SYMMETRIC KEYS;
