/*
busted pkey when restarted on container activity
--The duplicate key value is (b48ef09a-1950-4c80-8a59-af8d50025d43, BILL764\RC0)
use ehdb;         
exec eha.SendOffsiteCDC;           

DECLARE @RecallId NCHAR(36);
SET @RecallId = (SELECT TOP (1) Id
                 FROM eha.zContainers);  
EXEC eha.RecallContainer @RecallId;

exec eha.SendOffsiteCDC;           
exec eha.BackupServiceMasterKey 'Zu&6Gf%3Fe10L SUD@wcf?',0,1 -- force new (blows past Colophon mismatch)
eha.BackupDatabaseMasterKey 'ehdb', 'Ru&6Gf%3F e6LOUD@wc?f', 'Lu&6Gf%3 Fe4DRUP@wcf?',1, DEFAULT
eha.BackupCertificate 'ValueCertificate','ehdb','Mu&6Gf%3Fe 8LOUD@wcf?',NULL,0,0
select formatmessage('%s',sys.fn_varbintohexstr(0x0123456789876543210))

OPEN SYMMETRIC KEY ErrorKey
DECRYPTION BY CERTIFICATE ErrorCertificate
WITH password = 'Au&6Gf% 3Fe14CQAN@wcf?';

OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Lu&6Gf%3 Fe4DRUP@wcf?';

OPEN SYMMETRIC KEY ValueKey
DECRYPTION BY CERTIFICATE ValueCertificate;
CLOSE ALL SYMMETRIC KEYS;
*/

IF 1=2
  SELECT '' AS [eha.BackupActivity], * FROM eha.BackupActivity;
  SELECT '' AS [eha.Bookings], * FROM eha.Bookings;
  SELECT '' AS [eha.Container], * FROM eha.Container;
  SELECT '' AS [eha.NameValueHistory], * FROM eha.NameValueHistory;
  SELECT '' AS [eha.NameValues], * FROM eha.NameValues;
  SELECT '' AS [eha.OffsiteHistory], * FROM eha.OffsiteHistory;
  SELECT '' AS [eha.ReportHistory], * FROM eha.ReportHistory;
  SELECT '' AS [eha.Restores], * FROM eha.Restores;
END

GO
-- DDL EVENT Notifications
-- fyi
IF 1=2
  BEGIN
    
    -- hacker check - any strange stuff in the DDL change queue
    SELECT CAST(message_body AS XML) AS [DDLChangesQueue],* FROM DDLChangesQueue
    -- a missing sequence number would be cause for concern
    SELECT conversation_handle
         , CASE WHEN MAX(message_sequence_number) + 1  > COUNT(*) 
                THEN 'missing sequence number'
                WHEN MAX(message_sequence_number) + 1  < COUNT(*) 
                THEN 'unexpected queue entry'
                ELSE 'queue is OK'
                END   
    FROM DDLChangesQueue
    GROUP BY conversation_handle;

    -- summary by event type in the queue
    SELECT q.EventType, q.LoginName, COUNT(*) as [count]
     , CASE WHEN r.member_principal_id IS NULL THEN 'FALSE' ELSE 'TRUE'  END AS IsAuthorized
    -- , *  -- exclude the GROUP BY to see all
    FROM ( SELECT ddl.event.value('EventType[1]', 'NVARCHAR(128)') AS EventType
                , ddl.event.value('LoginName[1]', 'NVARCHAR(128)') AS LoginName
           FROM (SELECT CAST(message_body AS XML) AS change FROM DDLChangesQueue) derived
           CROSS APPLY change.nodes('/EVENT_INSTANCE') AS ddl(event) ) q
    LEFT JOIN sys.database_role_members r
    ON USER_SID(r.member_principal_id) = SUSER_SID(q.LoginName)
    WHERE r.role_principal_id = USER_ID('EHAdmin')
    --AND r.member_principal_id IS NULL -- only violations
    GROUP BY q.LoginName, q.EventType, r.member_principal_id;
    
     -- as above but only not authorized
    SELECT *
    FROM ( SELECT ddl.event.value('LoginName[1]', 'NVARCHAR(128)') AS LoginName
           FROM (SELECT CAST(message_body AS XML) AS change FROM DDLChangesQueue) derived
           --FROM (SELECT EVENTDATA() AS ddl) AS this
           CROSS APPLY change.nodes('/EVENT_INSTANCE') AS ddl(event) ) q
    LEFT JOIN sys.database_role_members r
    ON USER_SID(r.member_principal_id) = SUSER_SID(q.LoginName)
    WHERE r.role_principal_id = USER_ID('EHAdmin') -- '(ROLE_NAME)'
    AND r.member_principal_id IS NULL;

    SELECT '' AS [sys.symmetric_keys], * FROM sys.symmetric_keys;
    SELECT '' AS [sys.key_encryptions], * from sys.key_encryptions;
    SELECT '' AS [sys.certificates], * FROM sys.certificates;
    SELECT '' AS [sys.crypt_properties], object_name(major_id), * FROM sys.crypt_properties;
    SELECT '' AS [Object Security Check] 
           , o.Name AS [Object Name]
           , o.type_desc
           , CASE WHEN IS_OBJECTSIGNED( 'OBJECT'
                                      , o.object_id
                                      , 'CERTIFICATE'
                                      , ct.thumbprint ) = 1 
                  THEN cp.crypt_type_desc ELSE 'not signed' END AS [crypt_type_desc]
           , CASE WHEN IS_OBJECTSIGNED( 'OBJECT'
                                      , o.object_id
                                      , 'CERTIFICATE'
                                      , ct.thumbprint ) = 1 
                  THEN ct.name ELSE 'not signed' END AS [Signer]       
           , OBJECTPROPERTY(o.object_id, 'IsEncrypted') AS [IsEncrypted]
    FROM sys.objects o 
    LEFT JOIN sys.crypt_properties cp
    ON o.object_id = cp.major_id
    --    AND crypt_type IN ('SPVC', 'SPVA')
    LEFT JOIN sys.certificates ct
    ON cp.thumbprint = ct.thumbprint 
    WHERE o.type NOT IN -- IN ('P', 'TF', 'TR', 'FN', 'U')
      ('C', 'D', 'F','IT', 'PG', 'PK' , 'RF' , 'S', 'TT', 'UQ')
    AND is_ms_shipped = 0
    AND schema_name(schema_id) <> 'cdc'
    AND o.name NOT IN ('DDLChangesQueue')--('eha.$(EVENT_NOTIFICATION_NAME)Queue') 
    ORDER BY [Object Name];
  END
GO 
SET NOCOUNT ON;
GO
-- Encryption Hierarchy Administration testing --
use ehdb;
SELECT 'User context:' AS [Current Connection]
     , ORIGINAL_LOGIN() AS [ORIGINAL_LOGIN()]
     , SYSTEM_USER AS [SYSTEM_USER]
     , SESSION_USER AS [SESSION_USER]
     , USER AS [USER]
     , IS_SRVROLEMEMBER('sysadmin') AS [IS_SRVROLEMEMBER('sysadmin')]
     , IS_MEMBER('EHAdmin') AS [IS_MEMBER('EHAdmin')]
     , USER_NAME(member_principal_id) AS [USER_NAME(member_principal_id)]
FROM sys.database_role_members
WHERE role_principal_id = USER_ID('EHAdmin');
GO

--------------
-- functions 
--------------
DECLARE @EncryptionPhrase NVARCHAR(128)
      , @BackupPhrase NVARCHAR(128)
      , @DbName NVARCHAR(128) 
      , @tvp1 NAMEVALUETYPE
      , @tvp2 NAMEVALUETYPE
      , @TestFileName NVARCHAR(128);
SET @EncryptionPhrase = '10 to 128 chars with 3 of 4 - (1) UPPER CASE, (2) lower case, (3) 1234567890, (4) !@$%^&*()+=-}]{[|\:;?/>.,< ';
SET @BackupPhrase = 'IUYTVc c8x^%*Ex^%Xs b9Bou ybo8VI&^CRUYt';
SET @DbName = DB_NAME();

INSERT @tvp1 (Name, Value) 
VALUES(eha.GetEHPhraseName('ehdb',DEFAULT,DEFAULT), @BackupPhrase);

SELECT '@tvp1' AS tvp, * FROM @tvp1

SELECT * FROM sys.openkeys where key_name = '##MS_DatabaseMasterKey##'

-- no signature unless the caller opens the master key
SELECT 'eha.CheckPhrase(@tvp1)' AS [tvp], * 
FROM eha.CheckPhrase(@tvp1) AS [eha.CheckPhrase(@EncryptionPhrase)];

OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Lu&6Gf%3 Fe4DRUP#wcf?';

SELECT * FROM sys.openkeys where key_name = '##MS_DatabaseMasterKey##'

-- identical to above but now key open
SELECT 'eha.CheckPhrase(@tvp1)' AS [tvp], * 
FROM eha.CheckPhrase(@tvp1) AS [eha.CheckPhrase(@EncryptionPhrase)];

INSERT @tvp2 (Name, Value) 
VALUES(eha.GetEHPhraseName(DEFAULT,DEFAULT,'BACKUP'), 'boi5%$dg^DrOp%20TaBlE%20CuStOmEr^*naob89*g');

SELECT '@tvp2' as tvp, * FROM @tvp2

SELECT 'eha.CheckPhrase(@tvp2)' as tvp, * 
FROM  eha.CheckPhrase(@tvp2) AS [eha.CheckPhrase(@tvp2)]

CLOSE MASTER KEY;

SET @TestFileName = eha.NewMasterKeyBackupName(@DbName);
SELECT eha.BackupPath(@DbName) AS [BackupPath(@DbName)]
     , eha.CheckFile(@TestFileName) AS [CheckFile(@TestFileName)]
     , eha.NewCertificateBackupName(@DbName, 'CertificateName') AS [NewCertificateBackupName(@DbName, 'CertificateName')];

GO
------------------------------
-- booking stored procedure
-- bits originated at the caller (@@PROCID)
-- are combined with bits generated 
-- in the called procedure (SCOPE_IDENTITY())
-- in the called proc, the result is signed
-- and the signature is returned to the caller
-- along with the ID. The caller repeats 
-- the combination using the original bits sent 
-- and the ID to verify the signature
-- the ID becomes the Id for any
-- history record written by the caller

--------------------------------
-- the messages that format the @Parameters value
DECLARE @Name VARCHAR(448)
      , @Value VARCHAR(128)
      , @Version SMALLINT
      , @Binary VARBINARY(8000)
      , @DbName NVARCHAR(128) 
      , @BackupPhrase NVARCHAR(128)  
      , @KeyPhrase NVARCHAR(128) 
      , @Id NCHAR(36); 
SET @Name = 'name for the value';
SET @Value = 'valueCAPS123$%^';      
SET @Version = 1;
SET @Binary = 0x1a2b3c;
SET @DbName = 'testdb';
SET @BackupPhrase = 'AiHJ*DSrtgd ^as7@3$5fRe#d^F^';
SET @KeyPhrase = 'X!7&2dckjq3vwh- t5 kTe#dFs'; 
SET @Id = NEWID();

SELECT FORMATMESSAGE(2147483601, @Name, 'value', 0);
SELECT FORMATMESSAGE(2147483602, @Id, 123);
SELECT FORMATMESSAGE(2147483603, 0x1a2b3c4d);

SELECT FORMATMESSAGE(2147483611, @BackupPhrase, 1);
SELECT FORMATMESSAGE(2147483612, @Id, 0);
SELECT FORMATMESSAGE(2147483613, @DbName, @BackupPhrase, @KeyPhrase, 0);
SELECT FORMATMESSAGE(2147483614, @DbName, @Id, 1);
SELECT FORMATMESSAGE(2147483615, @Name, @DbName, @BackupPhrase, @KeyPhrase, 1);
SELECT FORMATMESSAGE(2147483616, @Name, @DbName, @Id);
GO

use ehdb;
GO
DECLARE @Id NCHAR(36), @procid INT, @Ticket NVARCHAR(30), @DeniableAuthenticator VARBINARY(128), @Parameters VARBINARY(8000); 
OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Lu&6Gf%3 Fe4DRUP#wcf?';
OPEN SYMMETRIC KEY [ValueKey]
DECRYPTION BY CERTIFICATE [ValueCertificate];
SET @procid = 1234;
SET @Parameters = (SELECT EncryptByKey( Key_GUID('ValueKey')
                                      , FORMATMESSAGE(2147483602, 0x1a2b3c, 123)
                                      , 1
                                      , OBJECT_NAME(@@PROCID) ) ); 
-- no object_id 1234 in the db
EXEC eha.Book @procid, @Parameters, @DeniableAuthenticator OUTPUT, @Id OUTPUT; 
SELECT VerifySignedByCert( CERT_ID('NonRepudiationCertificate')
                         , CAST(@procid AS NVARCHAR(10)) + @Id
                         , @DeniableAuthenticator ) AS [VerifySignedByCert]; 

SET @procid =  object_id('eha.Book');
-- open transaction
BEGIN TRANSACTION;
EXEC eha.Book @procid, @Parameters, @DeniableAuthenticator OUTPUT, @Id OUTPUT; 
SELECT VerifySignedByCert( CERT_ID('NonRepudiationCertificate')
                         , CAST(@procid AS NVARCHAR(10)) + @Id
                         , @DeniableAuthenticator ) AS [VerifySignedByCert]; 
COMMIT TRANSACTION;
-- good reservation
EXEC eha.Book @procid, @Parameters, @DeniableAuthenticator OUTPUT, @Id OUTPUT; 
SELECT VerifySignedByCert( CERT_ID('NonRepudiationCertificate')
                         , CAST(@procid AS NVARCHAR(10)) + @Id
                         , @DeniableAuthenticator ) AS [VerifySignedByCert]; 

CLOSE ALL SYMMETRIC KEYS;

-- DMK not open 
EXEC eha.Book @procid, @Parameters, @DeniableAuthenticator OUTPUT, @Id OUTPUT; 
SELECT VerifySignedByCert( CERT_ID('NonRepudiationCertificate')
                         , CAST(@procid AS NVARCHAR(10)) + @Id
                         , @DeniableAuthenticator ) AS [VerifySignedByCert]; 

--other externally manipulated conditions to test
--active trace (start a trace and rerun the booking stored procedure section)
--non-EHAdmin member sysadmin (to test use EXECUTES AS - see end of script for details)
--less secure configurations
----DMK exposed via sp_control_dbmasterkey_password
----DMK encrypted by SMK

GO
--------------------------------
-- namevalue stored procedures
--------------------------------
OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Lu&6Gf%3 Fe4DRUP#wcf?';
OPEN SYMMETRIC KEY [ValueKey]
DECRYPTION BY CERTIFICATE [ValueCertificate];

DECLARE @tvp NAMEVALUETYPE
      , @tvp1 NAMEVALUETYPE
      , @tvp2 NAMEVALUETYPE
      , @IsValid BIT
      , @NameHash VARBINARY(20)
      , @Version SMALLINT;
INSERT @tvp ( Name
            , Value) 
VALUES( eha.NameForEHPhrase('keybacktest',DEFAULT,DEFAULT)
      , '10 to 128 chars 3 oF 4 - UPPER CASE, lower case, 1234567890, (4)!@$%^&*()+=-}]{[|\:;?/>.,<');
SELECT '' AS [@tvp], * FROM @tvp; 
SET @NameHash = (SELECT NameHash FROM @tvp);
SELECT 'matching NameValues' AS [eha.NameValues],  Name, @Version AS [Version], Value FROM eha.NameValues WHERE NameHash = @NameHash;
SELECT top (5) 'matching NameValueHistory' AS [eha.NameValues], h.* FROM eha.NameValueHistory h JOIN eha.NameValues n on h.Id = n.Id WHERE NameHash = @NameHash ORDER BY CreateDT DESC;
EXEC eha.ValidateNameValue @tvp, @Version, @IsValid OUTPUT ;
SELECT @IsVALID AS [@IsVALID];   
INSERT @tvp1 (Name, Value)
EXEC eha.SelectNameValue @NameHash, @Version;
SELECT '' AS [@tvp1], * FROM @tvp1;

EXEC eha.AddNameValue @tvp, @Version OUTPUT;
SELECT 'matching NameValues' AS [eha.NameValues],  Name, @Version AS [Version], Value FROM eha.NameValues WHERE NameHash = @NameHash;
SELECT top (5) 'matching NameValueHistory' AS [eha.NameValues], h.* FROM eha.NameValueHistory h JOIN eha.NameValues n on h.Id = n.Id WHERE NameHash = @NameHash ORDER BY CreateDT DESC;

EXEC eha.ValidateNameValue @tvp, @Version, @IsValid OUTPUT ;
SELECT @IsVALID AS [@IsVALID]
INSERT @tvp2 (Name, Value)
EXEC eha.SelectNameValue @NameHash, @Version;
SELECT '' AS [@tvp2], * FROM @tvp2;
EXEC eha.AddNameValue @tvp2, @Version OUTPUT;
SELECT @Version AS [Version], * FROM eha.NameValues WHERE NameHash = @NameHash;
SELECT top 5 * FROM eha.NameValueHistory ORDER BY ID DESC;
CLOSE ALL SYMMETRIC KEYS;
EXEC eha.EHErrorReport;

GO
--------------------------
-- reports
--------------------------
SELECT ORIGINAL_LOGIN() AS [ORIGINAL_LOGIN()]
     , SYSTEM_USER AS [SYSTEM_USER]
     , USER AS [USER]
     , IS_SRVROLEMEMBER('sysadmin') AS [IS_SRVROLEMEMBER('sysadmin')]
     , IS_MEMBER('EHAdmin') AS [IS_MEMBER('EHAdmin')]
     , USER_NAME(role_principal_id) AS [USER_NAME(role_principal_id)]
     , USER_NAME(member_principal_id) AS [USER_NAME(member_principal_id)]
FROM sys.database_role_members 
WHERE USER_NAME(role_principal_id) = 'EHAdmin';
GO
DECLARE @thumbprint VARBINARY(32)
SET @thumbprint =(SELECT Colophon
                  FROM eha.EHAdminHistory
                  WHERE EHNode = (SELECT MAX(EHNode)
                                  FROM eha.EHAdminHistory
                                  WHERE EHNode.GetAncestor(1) = (SELECT TOP(1) EHNode
                                                                 FROM eha.EHAdminHistory
                                                                 WHERE EHNodeName = 'Database Master Key'
                                                                 AND ServerName = @@SERVERNAME
                                                                 ORDER BY Id DESC)));

SELECT 'CertificateBackupsByThumbprint' AS [Report]
EXEC eha.CertificateBackupsByThumbprint @thumbprint;
GO
SELECT 'eha.EHServerSummaryReport' AS [Report]
EXEC eha.EHServerSummaryReport; 
GO
SELECT 'eha.EHActivityReport' AS [Report]
EXEC eha.EHActivityReport;
GO
SELECT 'eha.EHErrorReport' AS [Report]
EXEC eha.EHErrorReport;
GO
-------------------------
-- Encryption Hierarchy   
-------------------------

-----------------------
-- Service Master Key
-----------------------
-- the ehdbb initialization made a backup of the SMK
DECLARE @BackupPhraseName NVARCHAR(448)
      , @BackupPhraseVersion SMALLINT
      , @BackupPhrase NVARCHAR(128)
      , @tvp NAMEVALUETYPE
      , @Id INT;
OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Lu&6Gf%3 Fe4DRUP#wcf?';
SET @BackupPhraseName = eha.NameForEHPhrase(NULL,NULL,'BACKUP')
-- SET @BackupPhraseVersion = NULL
INSERT @tvp (Name, Value)
EXEC eha.SelectNameValue @BackupPhraseName, @BackupPhraseVersion;
SELECT @BackupPhrase = Value from @tvp;
CLOSE MASTER KEY;
------------------------------
-- Service Master Key Backup
------------------------------
-- notice the backup specific completion message
EXEC eha.BackupServiceMasterKey @BackupPhrase; 
-- repeat request is a no-op but logs the duplicate request
-- notice the generic "command(s) completed successfully" completion message
-- when you see that message in this application it means something failed, look in the tables for the problem.
EXEC eha.BackupServiceMasterKey @BackupPhrase; 
-- can override to force another SMK backup - but more duplicate backups = more risk that one might walk away
EXEC eha.BackupServiceMasterKey @BackupPhrase, 1; 
-- restore the latest version (remember we now have 2)
EXEC eha.RestoreServiceMasterKey;
-- restore the previous version
------------------------------
-- Service Master Key Restore
------------------------------
SET @Id = ( SELECT MIN(Id) FROM eha.EHAdminHistory 
            WHERE EHNode = HIERARCHYID::GetRoot()
            AND Action = 'BackupServiceMasterKey'
            AND Status = 'Complete' );
EXEC eha.RestoreServiceMasterKey @Id;
-- force a restore even though a duplicate
EXEC eha.RestoreServiceMasterKey @ForceReplace = 1;
EXEC eha.EHServerSummaryReport;
EXEC eha.EHErrorReport;
-- this shows that the code for all 3 modes works from the EH perspective but does not do much to reveal the
-- implications of restoring a different key definition in terms of application contention and other overhead  

------------------------
-- Database Master Key
-----------------------
IF DB_ID('keybacktest') IS NOT NULL
  BEGIN
    USE keybacktest;
    ALTER DATABASE keybacktest SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    USE master;
    DROP DATABASE keybacktest;
  END
GO
CREATE DATABASE keybacktest;
GO
USE keybacktest;
GO
  CREATE QUEUE keybacktestChangeQueue WITH RETENTION = ON;
GO
  CREATE SERVICE keybacktestChangeService
  ON QUEUE keybacktestChangeQueue ( [http://schemas.microsoft.com/SQL/Notifications/PostEventNotification] );
GO
  CREATE EVENT NOTIFICATION keybacktestChangeNotification ON DATABASE 
  FOR DDL_DATABASE_LEVEL_EVENTS TO SERVICE 'keybacktestChangeService', 'current database' ;
GO
-------------------------------
-- Database Master Key Backup
-------------------------------
DECLARE @BackupPhrase VARCHAR(128)
      , @KeyPhrase VARCHAR(128)
      , @DbName NVARCHAR(128);
-- db for keys and cetificate backup/restore testing
SET @DbName = DB_NAME();  
IF EXISTS ( SELECT * FROM sys.symmetric_keys sk 
            JOIN sys.key_encryptions ke 
            ON sk.symmetric_key_id = ke.key_id 
            WHERE sk.name = '##MS_DatabaseMasterKey##')
  DROP MASTER KEY;
SET @KeyPhrase = CAST(NEWID() AS NVARCHAR(128));

-- create a master key encrypted by the SMK and a phrase (the only way they can be CREATEd)
IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
  EXEC('CREATE MASTER KEY ENCRYPTION BY PASSWORD = ''' + @KeyPhrase + '''');

SELECT '' AS [Freshly Created DMK]
  , sk.name, ke.crypt_type, ke.crypt_type_desc 
FROM sys.symmetric_keys sk 
JOIN sys.key_encryptions ke 
ON sk.symmetric_key_id = ke.key_id 
WHERE sk.name = '##MS_DatabaseMasterKey##';

-- back it up with a new backup secret
SET @BackupPhrase = CAST(NEWID() AS NVARCHAR(128));
EXEC ehdb.eha.BackupDatabaseMasterKey @DbName, @BackupPhrase, @KeyPhrase;

-- remove Service Master Key Encryption from the master key
ALTER MASTER KEY DROP ENCRYPTION BY SERVICE MASTER KEY; 
EXEC('OPEN MASTER KEY DECRYPTION BY PASSWORD = ''' + @KeyPhrase + ''';');
EXEC('ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = ''' + @KeyPhrase + ''';');
CLOSE MASTER KEY; -- not required

SELECT '' AS [dropped SMK encryption]
  , sk.name, ke.crypt_type, ke.crypt_type_desc 
FROM sys.symmetric_keys sk 
JOIN sys.key_encryptions ke 
ON sk.symmetric_key_id = ke.key_id 
WHERE sk.name = '##MS_DatabaseMasterKey##';

-- back it up with the same backup secret
EXEC ehdb.eha.BackupDatabaseMasterKey @DbName , @BackupPhrase, @KeyPhrase;

-- add SMK encryption back using ALTER
EXEC('OPEN MASTER KEY DECRYPTION BY PASSWORD = ''' + @KeyPhrase + ''';')
SELECT 'yes' AS ['DMK open here even though opened in the called batch?'], * from sys.openkeys 
ALTER MASTER KEY ADD ENCRYPTION BY SERVICE MASTER KEY;
SET @KeyPhrase = CAST(NEWID() AS NVARCHAR(128));
EXEC('ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = ''' + @KeyPhrase + ''';');
CLOSE MASTER KEY;

SELECT '' AS [add SMK using alter]
  , sk.name, ke.crypt_type, ke.crypt_type_desc 
FROM sys.symmetric_keys sk 
JOIN sys.key_encryptions ke 
ON sk.symmetric_key_id = ke.key_id 
WHERE sk.name = '##MS_DatabaseMasterKey##';

USE ehdb;
-- back it up with a new backup secret
SET @BackupPhrase = CAST(NEWID() AS NVARCHAR(128));
EXEC eha.BackupDatabaseMasterKey @DbName, @BackupPhrase, @KeyPhrase;

-- duplicate backup with same secret fails
EXEC eha.BackupDatabaseMasterKey @DbName, @BackupPhrase, @KeyPhrase;

-- duplicate backup with new secret still fails
SET @BackupPhrase = CAST(NEWID() AS NVARCHAR(128));
EXEC eha.BackupDatabaseMasterKey @DbName, @BackupPhrase, @KeyPhrase;

-- force a new DMK backup even if it will be a duplicate 
SET @BackupPhrase = CAST(NEWID() AS NVARCHAR(128));
EXEC eha.BackupDatabaseMasterKey @DbName = @DbName
                               , @BackupPhrase = @BackupPhrase
                               , @KeyPhrase = @KeyPhrase
                               , @ForceNew = 1;

-------------------------------
-- Database Master Key Restore
-------------------------------
OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Lu&6Gf%3 Fe4DRUP#wcf?';
DECLARE @IdToRestore INT
      , @DbName NVARCHAR(128) ;
SET @DbName = 'keybacktest';      

-- restore the key version with no SMK enryption from backup
SET @IdToRestore = ( SELECT TOP (1) Id FROM eha.EHAdminHistory
                     WHERE EHNOdeName = 'Database Master Key'
                     AND DbName = @DbName
                     AND Action = 'BackupDatabaseMasterKey'
                     AND Status = 'Complete'
                     AND EncryptionBy = 'PW'  -- password
                     ORDER BY ID DESC );
EXEC eha.RestoreDatabaseMasterKey @DbName, @IdToRestore;

-- restore the key version with no SMK enryption from backup
SET @IdToRestore = ( SELECT TOP (1) Id FROM eha.EHAdminHistory
                     WHERE EHNOdeName = 'Database Master Key'
                     AND DbName = @DbName
                     AND Action = 'BackupDatabaseMasterKey'
                     AND Status = 'Complete'
                     AND EncryptionBy = 'SP'  -- SMK + Password
                     ORDER BY ID DESC );
EXEC eha.RestoreDatabaseMasterKey @DbName, @IdToRestore;

-- force replace although obviously not required here since we just restored it without
-- note that the supression of regeneration message is not seen here but is above
SET @IdToRestore = ( SELECT TOP (1) Id FROM eha.EHAdminHistory
                     WHERE EHNOdeName = 'Database Master Key'
                     AND DbName = @DbName
                     AND Action = 'BackupDatabaseMasterKey'
                     AND Status = 'Complete'
                     AND EncryptionBy = 'PW' -- Password
                     ORDER BY ID DESC );
EXEC eha.RestoreDatabaseMasterKey @DbName = @DbName, @IdToRestore = @IdToRestore, @ForceReplace = 1;

GO
--USE ehdb;
--OPEN MASTER KEY DECRYPTION BY PASSWORD = N'Qu&6G f%3Fe2LOUD#yc?f';
--SELECT CAST(DecryptByKeyAutoCert(CERT_ID( 'ValueCertificate' )
--                                        , NULL 
--                                        , Name
--                                        , 1
--                                        , CAST(Version AS NVARCHAR(10))) AS NVARCHAR(128)) AS Name
--     , CAST(DecryptByKeyAutoCert(CERT_ID( 'ValueCertificate' )
--                                        , NULL 
--                                        , Value
--                                        , 1
--                                        , CAST(Version AS NVARCHAR(10))) AS NVARCHAR(128)) AS Value
--FROM eha.NameValues;
--SELECT ObjectName
--     , CAST(DecryptByKeyAutoCert(CERT_ID( 'ValueCertificate' )
--                                        , NULL 
--                                        , Parameters
--                                        , 1
--                                        , ObjectName) AS NVARCHAR(MAX)) AS Parameters
--FROM eha.Bookings;
--CLOSE ALL SYMMETRIC KEYS;
GO

OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Lu&6Gf%3 Fe4DRUP#wcf?';
DECLARE @IdToRestore INT
      , @DbName NVARCHAR(128) ;
SET @DbName = 'keybacktest';      
-- restore the key version with no SMK enryption from backup
SET @IdToRestore = ( SELECT TOP (1) Id FROM eha.EHAdminHistory
                     WHERE EHNOdeName = 'Database Master Key'
                     AND DbName = @DbName
                     AND Action = 'BackupDatabaseMasterKey'
                     AND Status = 'Complete'
                     AND EncryptionBy = 'PW'  -- password
                     ORDER BY ID DESC );
EXEC eha.RestoreDatabaseMasterKey @DbName, @IdToRestore;

-- force replace although obviously not required here since we just restored it without
-- note that the supression of regeneration message is not seen here but is above
SET @IdToRestore = ( SELECT TOP (1) Id FROM eha.EHAdminHistory
                     WHERE EHNOdeName = 'Database Master Key'
                     AND DbName = @DbName
                     AND Action = 'BackupDatabaseMasterKey'
                     AND Status = 'Complete'
                     AND EncryptionBy = 'SP' -- SMK + Password
                     ORDER BY ID DESC );
EXEC eha.RestoreDatabaseMasterKey @DbName = @DbName, @IdToRestore = @IdToRestore, @ForceReplace = 1;
/*
    SELECT TOP (10) *
                  , eha.NameForEHPhrase(DbName,DEFAULT,'BACKUP')
                  , eha.NameForEHPhrase(DbName,DEFAULT,DEFAULT)                 
    FROM eha.EHAdminHistory
    WHERE EHNodeName = 'Database Master Key'
    AND DbNAme = 'keybacktest'
--    AND Action = 'BackupDatabaseMasterKey'
    AND Status = 'Complete'
--    AND Id = ISNULL(NULL, Id)
    ORDER BY Id DESC;  
*/
-- top 16 rows should show both restores
SELECT 'eha.EHActivityReport' AS [Report]
EXEC ehdb.ehs.EHActivityReport;
-- ad hoc history for the master key

SELECT * FROM ehdb.eha.Bookings 
ORDER BY ID DESC;

SELECT * FROM ehdb.eha.EHAdminHistory 
WHERE DbName = 'keybacktest'
AND EHNodeName = 'Database Master Key'
ORDER BY ID DESC;

SELECT * FROM ehdb.eha.NameValues 
WHERE Name like '%keybacktest%'
ORDER BY CREATEDT DESC

GO


-- drop & restore a DMK, without & then with dependent objects
IF DB_ID('keybacktest') IS NOT NULL
  BEGIN
    USE keybacktest;
    ALTER DATABASE keybacktest SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    USE master;
    DROP DATABASE keybacktest;
  END
GO
CREATE DATABASE keybacktest;
GO
USE keybacktest;
GO
IF OBJECT_ID('dbo.TestProc', 'P') IS NOT NULL
  DROP PROC dbo.TestProc       
GO
CREATE PROC dbo.TestProc       
AS
BEGIN
SELECT IS_OBJECTSIGNED( 'OBJECT'
                      , @@PROCID
                      , 'CERTIFICATE' 
                      , thumbprint ) AS [IS_OBJECTSIGNED]
FROM sys.certificates
WHERE name = 'TestCert';
END
GO
IF EXISTS (SELECT * 
           FROM sys.symmetric_keys
           WHERE name = '##MS_DatabaseMasterKey##')
  DROP MASTER KEY;
GO
USE ehdb;
-- restore the latest backup
EXEC eha.RestoreDatabaseMasterKey 'keybacktest';

CREATE CERTIFICATE TestCert
WITH SUBJECT = 'test backup/restore scenarios';
EXEC eha.BackupCertificate 'TestCert', 'keybacktest', 'GB3Uu9g-G*H';

ADD SIGNATURE TO dbo.TestProc 
BY CERTIFICATE TestCert;

DROP SIGNATURE FROM dbo.TestProc
BY CERTIFICATE TestCert;

DROP CERTIFICATE TestCert;

DROP MASTER KEY;

EXEC ehdb.eha.RestoreDatabaseMasterKey 'keybacktest';
EXEC ehdb.eha.RestoreCertificate 'TestCert', 'keybacktest';
ADD SIGNATURE TO dbo.TestProc 
BY CERTIFICATE TestCert;
DROP MASTER KEY; -- test that the hierarchy is in place to support the signed proc
SELECT * FROM eha.AdminHistory WHERE DbName = 'keybacktest' ORDER BY Id DESC -- backup and restore visible in history
EXEC ehdb.eha.RestoreCertificate 'TestCert', 'keybacktest'
-- Command(s) completed successfully.
SELECT * FROM ehdb.eha.CertificateBackupHistory WHERE DbName = 'keybacktest'
-- raisews ErrorNumber="2147483637"
--unnecessary restore attempt   
use ehdb;
EXEC eha.RestoreCertificate 'keybacktest', 'TestCert';
EXEC eha.RestoreDatabaseMasterKey 'keybacktest';
EXEC eha.RestoreServiceMasterKey;
-- returns system message: The old and new master keys are identical. No data re-encryption is required.
-- and keyback success message: keyback info - database keybacktest Master Key restore complete.
EXEC eha.EHActivity;
GO
DROP CERTIFICATE TestCert;
-- Command(s) completed successfully.
GO
DROP MASTER KEY
GO
EXEC ehdb.eha.RestoreCertificate 'TestCert', 'keybacktest'
GO
SELECT * FROM ehdb.eha.CertificateBackupHistory
WHERE DbName = 'keybacktest'
GO
-- sign a stored proc with the cert
ADD SIGNATURE TO dbo.TestProc 
BY CERTIFICATE TestCert;
GO
SELECT object_name(major_id), * from sys.crypt_properties 
-- a row for the signed object is returned
GO
ALTER PROC dbo.TestProc       
AS
BEGIN
-- add comment to show that signature is thrown on the floor when a procedure is changed in any way
SELECT IS_OBJECTSIGNED( 'OBJECT'
                      , @@PROCID
                      , 'CERTIFICATE' 
                      , thumbprint ) AS [IS_OBJECTSIGNED]
FROM sys.certificates
WHERE name = 'TestCert';
END
GO
SELECT OBJECT_NAME(major_id), * FROM sys.crypt_properties 
-- empty result set
GO
ALTER CERTIFICATE TestCert REMOVE PRIVATE KEY;
GO
ADD SIGNATURE TO dbo.TestProc 
BY CERTIFICATE TestCert;
-- Msg 15556 
GO
EXEC ehdb.eha.RestoreCertificate 'TestCert', 'keybacktest';
-- ErrorNumber="2147483637" 
GO
DROP CERTIFICATE TestCert;
-- Command(s) completed successfully.
GO
EXEC ehdb.eha.RestoreCertificate 'TestCert', 'keybacktest'
GO
ADD SIGNATURE TO dbo.TestProc BY CERTIFICATE TestCert;
-- Command(s) completed successfully.
GO
SELECT OBJECT_NAME(major_id), * FROM sys.crypt_properties 
-- a row
GO
DROP SIGNATURE FROM dbo.TestProc BY CERTIFICATE TestCert;
GO
SELECT OBJECT_NAME(major_id), * FROM sys.crypt_properties 
-- empty
GO
ALTER CERTIFICATE TestCert REMOVE PRIVATE KEY;
GO
ADD SIGNATURE TO dbo.TestProc BY CERTIFICATE TestCert;
-- Msg 15556, Level 16, State 1, Line 1
-- Cannot decrypt or encrypt using the specified certificate, either because it has no private key or because the password provided for the private key is incorrect.
GO
DECLARE @Value NVARCHAR(128)
      , @PrivateKeyPath NVARCHAR(256);
SET @PrivateKeyPath = (SELECT TOP(1) BackupPath + BackupName + '.prvbak' 
                       FROM ehdb.EHA.CertificateBackupHistory
                       WHERE CertificateName = 'TestCert'
                       AND DbName = 'keybacktest'
                       AND PrivateKeyEncryptionType = 'MK'
                       ORDER BY Id Desc); 
EXEC EHDB.eha.GetValueByName 'keybacktest_TestCert_CERTIFICATE_BACKUP_PHRASE', @Value OUTPUT;
EXEC('ALTER CERTIFICATE TestCert
      WITH PRIVATE KEY 
       ( FILE = ''' + @PrivateKeyPath + '''
       , DECRYPTION BY PASSWORD = ''' + @Value +''')');
GO
ADD SIGNATURE TO dbo.TestProc BY CERTIFICATE TestCert;
-- Command(s) completed successfully.
GO


/*
-----------------------------
-- User Security test setup
-----------------------------
-- use an otherwise unprivileged sysadmin for security testing

--after executing the script run these three statements and repeat
--anything involving the DMK will not work for this user
CREATE LOGIN [BILL764\SallyDuck] FROM WINDOWS;
EXEC sp_addsrvrolemember 'BILL764\SallyDuck', 'sysadmin';
EXECUTE AS LOGIN = 'BILL764\SallyDuck';
SELECT ORIGINAL_LOGIN(), SYSTEM_USER, SESSION_USER, USER;
SELECT USER_NAME(role_principal_id) AS role
     , USER_NAME(member_principal_id) AS member 
FROM sys.database_role_members;

-- run these 2 statements to add the sysadmin to the role and repeat  
-- everything should work for this user
CREATE USER [BILL764\SallyDuck] FROM LOGIN [BILL764\SallyDuck];
EXEC sp_addrolemember @rolename = 'EHAdmin'
                    , @membername = 'BILL764\SallyDuck';
SELECT ORIGINAL_LOGIN(), SYSTEM_USER, SESSION_USER, USER;
SELECT * from sys.database_principals WHERE TYPE = 'U';

-- cleanup test user
--To end the assumed identity after the test is complete execute
WHILE (SUSER_SNAME() = 'BILL764\SallyDuck')
  REVERT;
IF USER_ID('BILL764\SallyDuck') IS NOT NULL
  BEGIN
    EXEC sp_droprolemember @rolename = 'EHAdmin'
                        , @membername = 'BILL764\SallyDuck'
    -- I hear M$ is going to stop auto creating schemas
    IF SCHEMA_ID('BILL764\SallyDuck') IS NOT NULL
      DROP SCHEMA [BILL764\SallyDuck];
    DROP USER [BILL764\SallyDuck];
    IF SUSER_SNAME('BILL764\SallyDuck') IS NOT NULL
      DROP LOGIN [BILL764\SallyDuck];
  END
GO

*/

/*
-- recovery scenarios for missing TDE certificate with ehdb inaccessible
-- this is a special case where EH tools may be unavailable and shows generally 
-- how any encryption hierarchy backup can located in the library and manually restored
-- the SMK as well as Certificates and the DMK in the ehdb could be done similarly.  
-- 1. Restore the most recent backup of master. Any changes since the time of 
--    the backup will be lost so BEFORE you restore collect the current master
--    database configuration. After restore varify and recreate/modify config as needed.
--    The missing key and anything else that was in place at the time of the backup  
--    will be restored if it is in the backup. Once the restore is complete and any 
--    changes are re-applied, the recovery is complete. 
-- 2. Restore the most recent backup of the Certificate 
--    if the ehdb is accessible use it! (not very likely if TDE cert is gone, but possible 
--    if you have a existing non-DAC connection. If you disconnect/connect or restart the SQL Server, 33111 
--    errors will be seen and anything protected by the missing certificate will be inaccessible.
--    After 33111 errors occur on the TDE certificate the ehdb database cannot be opened.
--    Temporarily restore the most recent backup of the ehdb database to an alternate SQL instance.
--    The application will not be used on the alternate server, we just want to see the data so we can 
--    identify the right file name to restore.    
--    use the eha.CertificateBackupsByThumbprint stored procedure to identify the missing 
--    certificate identified only by thumprint in the 33111 message:
--      "Cannot find server Certificate with thumbprint Ox..." 
--    The parameter to feed to the procedure is the 0x... 32 bit binary value
--    fetch any required encryption password(s) from the secure offsite location if unable to 
--    create or access a ehdb file that can be used for this purpose  
--    browse to the folder where master.mdf is stored and find the backup for this thumbprint in the export folder
--    restore the certificate using CREATE CERTIFICATE (see example below) and all will be fine
-- build a statement that uses this general form:

CREATE CERTIFICATE TDECertificate 
FROM FILE = 'path to master.mdf + file name of public key backup.cerbak>'
WITH PRIVATE KEY (FILE = 'path to master.mdf + file name of private key backup.prvbak>'
DECRYPTION BY PASSWORD = 'value for name master_TDECertificate_BACKUP_PHRASE');

for example:
USE master;

CREATE CERTIFICATE TDECertificate 
FROM FILE = 'C:\Program Files\Microsoft SQL Server\MSSQL10_50.R2\MSSQL\DATA\BILL_VU$R2__master__TDECertificate__2011-06-17__22-12-44.cerbak'
WITH PRIVATE KEY (FILE = 'C:\Program Files\Microsoft SQL Server\MSSQL10_50.R2\MSSQL\DATA\BILL_VU$R2__master__TDECertificate__2011-06-17__22-12-44.prvbak',
DECRYPTION BY PASSWORD = '9!@#$%QWERTasdfg');
--
-- 3. 
--

*/
/*rollback
USE keybacktest;
DROP SIGNATURE FROM dbo.TestProc
BY CERTIFICATE TestCert;
DROP CERTIFICATE TestCert
DROP MASTER KEY;
--or--
USE keybacktest;
ALTER DATABASE keybacktest SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
USE master;
DROP DATABASE keybacktest;
IF SUSER_SID('BILL_VU\SallyDuck') IS NOT NULL
  DROP LOGIN [BILL_VU\SallyDuck] --'$(UNINVITED)'
*/
/*
create 2 ODBC DSNs
One (here R2ODBC) points to another local db
The other points to a SQL Azure instance (SQLAzureODBC

configure a linked server for each.
EXEC master.dbo.sp_addlinkedserver @server = N'SQLAzureODBC'
                                 , @srvproduct = N'Any'
                                 , @provider=N'MSDASQL'
                                 , @datasrc=N'SQLAzureODBC'

EXEC master.dbo.sp_addlinkedserver @server = N'R2ODBC'
                                 , @srvproduct = N'Any'
                                 , @provider=N'MSDASQL'
                                 , @datasrc=N'R2ODBC'

configure an alias to a table in each data source

CREATE SYNONYM [dbo].[StagedData] FOR [BILL764\R2].[staging].[dbo].[StagedData]
CREATE SYNONYM [dbo].[Course] FOR [SQLAzureODBC].[School].[dbo].[Course]

select top 10 * from dbo.StagedData
--http://blogs.msdn.com/b/sqlcat/archive/2011/03/08/linked-servers-to-sql-azure.aspx

-- after creating an ODBC DSN named SQLAzureODBC
EXEC master.dbo.sp_addlinkedserver @server = N'SQLAzureODBC'
                                 , @srvproduct = N'Any'
                                 , @provider=N'MSDASQL'
                                 , @datasrc=N'SQLAzureODBC'
GO

EXEC master.dbo.sp_addlinkedsrvlogin @rmtsrvname = N'SQLAzureODBC'
                                   , @useself = N'False'
                                   , @locallogin = NULL
                                   , @rmtuser = N'bwunder@vucjhke38b.database.windows.net'
                                   , @rmtpassword='****'
GO


*/ 

/*  Don Kiely - Protect Sensitive Data Using Encryption in SQL Server 2005 (word doc)
    This user defined function (udf) can be used to calculate the expected output 
    length for encrypted data (using EncryptByKey) based on the key, plaintext 
    length and if a hashed data/column is being used (optional parameter). 
    If you are using the results of the formula/udf to calculate the size of the 
    column for a table, I strongly suggest adding 1 or 2 blocks (i.e. 16 bytes) 
    to the expected size to account for possible future changes to algorithms of 
    choice or the stored format.
*
*     (c) 2005 Microsoft Corporation. All rights reserved. 
*
*************************************************************************/
-- @KeyName		:= name of the symmetric key.
-- @PTLen		:= length in bytes of the plain text
-- @UsesHash	:= if the optional MAC option of EncryptByKey is being using this value must be 1, 0 otherwise
--   returns the expected length in bytes of the ciphertext returned by EncryptByKey using @KeyName symnmetric key
-- and a plaintext of @PTLen bytes in length, either using the optional @MAC parameter or not.
DROP FUNCTION dbo.CalculateCipherLen
GO

select dbo.CalculateCipherLen('ValueKey',256,1)  = 324  -- NVARCHAR(128) 512
select dbo.CalculateCipherLen('ValueKey',896,1) = 964  -- NVARCHAR(448)  1024
select dbo.CalculateCipherLen('ValueKey',2048,1) = 2116  -- NVARCHAR(1024) 2432


CREATE FUNCTION dbo.CalculateCipherLen
 ( @KeyName sysname
 , @PTLen int
 , @UsesHash	int = 0 )
RETURNS int
as
BEGIN
	declare @KeyType	nvarchar(2)
	declare @RetVal		int
	declare @BLOCK		int
	declare @IS_BLOCK	int
	declare @HASHLEN	int
	
	-- Hash length that
	SET @HASHLEN	= 20
	SET @RetVal	= NULL
	
	-- Look for the symmetric key in the catalog 
	SELECT @KeyType	= key_algorithm FROM sys.symmetric_keys WHERE name = @KeyName
	
	-- If parameters are valid
	if( @KeyType is not null AND @PTLen > 0)
	BEGIN
		-- If hash is being used. NOTE: as we use this value to calculate the length, we only use 0 or 1
		if( @UsesHash <> 0 )
			SET @UsesHash = 1
	
		-- 64 bit block ciphers
		if( @KeyType = N'R2' OR @KeyType = N'D' OR @KeyType = N'D3' OR @KeyType = N'DX' )
		BEGIN
			SET @BLOCK = 8
			SET @IS_BLOCK = 1
		END
		-- 128 bit block ciphers
		else if( @KeyType = N'A1' OR @KeyType = N'A2' OR @KeyType = N'A3' )
		BEGIN
			SET @BLOCK = 16
			SET @IS_BLOCK = 1
		END
		-- Stream ciphers, today only RC4 is supported as a stream cipher
		else
		BEGIN
			SET @IS_BLOCK = 0
		END
	
		-- Calclulate the expected length. Notice that the formula is different for block ciphres & stream ciphers
		if( @IS_BLOCK = 1 )
		BEGIN
			SET @RetVal = ( FLOOR( (8 + @PTLen + (@UsesHash * @HASHLEN) )/@BLOCK)+1 ) * @BLOCK + 16 + @BLOCK + 4
		END
		else
		BEGIN
			SET @RetVal = @PTLen + (@UsesHash * @HASHLEN) + 36 + 4
		END
	
	END

	return @RetVal
END
GO



DISABLE TRIGGER ALL ON DATABASE

