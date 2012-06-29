:on error exit
-------------------------------------------------------------------------------
-- Encryption Hierarchy Administration Spoke  
-------------------------------------------------------------------------------
-- Pre-requisites 
--  1. SQL Server 2012 RTM (wants a SQL Agent)
--  2. Mount-able TrueCrypt virtual disk KEY_CONTAINER_FILE (see http://www.truecrypt.org)
--     easy to remove this requirement (use KEY_CONTAINER_PATH in place of
--     VHD_LETTER and remove mount/unmount SQLCMDs)  
--     systems where svc account is domain account can use FILESTREAM UNC 
--  3. hub database (InstallHub.sql) on SQL Server, SQL Azure or ?
--  4. Usable ODBC System DSN to hub database for use by LINK_SERVER_ODBC_DSN
-- Other Important Notes:
--  1 To protect the required secrets from compromise when entered in this script:
--      A. ONLY Use this script in an SSMS/SSDT query window that supports SQLCMD mode. 
--      B. ALWAYS replace the example template tokens with your secrets.  
--      C. NEVER save this script once the secrets have been entered. 
--  2. Give the SQL Server Database Engine's service account full control of the 
--     VHD Container's folder and the mounted virtual disk. Include 
--     password used as the CRYPTO_CONTAINER_ENCRYPTION_PHRASE sqlcmd variable.
--     example: Estimating a generous 1.5KB/key and 3KB/certificate and given the  
--     Minimum TrueCrypt NTFS volume size possible: 3792k, est > 2000 exports. The  
--     bigger the file, the longer to back up to a VARBINARY(MAX) column and send to
--     hub. Growing TrueCrypt VHD once in use by the SQL instance is not a possibility.
--  3. Database Master Key and certificate for TDE are added to master database of  
--     TDE capable SKUs. (Developer, Enterprise, DataCenter) 
--  4. A login on the remote SQL instance already exist for use in the ODBC DSN
--     run InstallHub.sql on the remote before running InstallSpoke.sql here 
--  5. enables CLR if not already enabled for recall from offsite processing 
--  6. 'max text repl size (B)' is set to -1 (size limited only by type)  
--  7. User database is created if specified database does not exist by name
--  8. Database Master Key is created in this user database if not found   
--  9. Adjust passphrase hardness policy in the CheckPhrase() function.
-- 10. Algorithm defaults are best practice or otherwise called out as preferred 
--     in current industry and privacy standards, e.g. NIST: FIPS 140-2, PCI-DSS, 
--     SAE16, etc. see: 
--     http://blogs.msdn.com/b/ace_team/archive/2007/09/07/aes-vs-3des-block-ciphers.aspx
-- 11. Enterprise, DataCenter, Developer or Evaluation Edition SQL Server 
--     required for TDE, Change Data Capture, SPARSE, FILESTREAM
-- 12. SQL Server 2012 required for FileTable, declarative assignment, 
--     THROW, FORMATMESSAGE usage, FORMAT,  SHA2_512 algorithm, ALTER ROLE-ADD MEMBER, 
--     AES SMK encryption, 
-- 13. (localdb)any will not work - FILESTREAM requires instance running as a service,
--     LinkedServer cannot use (localdb)any
-- 14. To build the script without TrueCrypt 
-- 15. This script is a work in progress...
-------------------------------------------------------------------------------
SET NOCOUNT ON;
GO
-- SQLCMD variable assignment is not exposed in trace output but the batch that runs SET NOCOUNT ON will be! 
-- in live environments use "WITH EXECUTE AS CALLER, ENCRYPTION"
-- in dev/test use "WITH EXECUTE AS CALLER" to enable debugging 
:setvar WITH_OPTIONS                           "WITH EXECUTE AS CALLER" --, ENCRYPTION"                                                                   
-- private passphrase - never saved! must be remembered!  
-- used for secret obfuscation, private encryption of CRYPTO_CONTAINER_ENCRYPTION_PHRASE, LINK_PASSWORD and the SESSION_SYMMETRIC_KEY   
:setvar PRIVATE_ENCRYPTION_PHRASE              "Private - never saved"  -- "<[PASSPHRASE_ENCRYPTION_PHRASE],VARCHAR,Private - never saved>"               
-- temp object keeps DDL the noise out of db catalog - the life of the key is the life of the user's connection just like any # temp object 
:setvar SESSION_SYMMETRIC_KEY                  "#SessionSymmetricKey"   -- "<[SESSION_SYMMETRIC_KEY],SYSNAME,#SessionSymmetricKey>"                       
:setvar SESSION_KEY_SOURCE                     "SessionKeySource"       -- "<[SESSION_KEY_SOURCE],NVARCHAR,SessionKeySource>"                             
:setvar SESSION_KEY_IDENTITY                   "SessionKeyIdentity"     -- "<[SESSION_KEY_IDENTITY],NVARCHAR,SessionKeyIdentity>"                         
:setvar SESSION_KEY_ENCRYPTION_PHRASE          "not sent 2 CheckPhrase" -- "<[SESSION_KEY_ENCRYPTION_PHRASE],PASSPHRASE,not sent 2 CheckPhrase>"          
-- Crypto-container name and location (restored containers go to a FileTable in this folder)
:setvar KEY_CONTAINER_PATH                     "G:\TrueCrypt\EHA\"      -- give Full Control to SQL Server service account                                
:setvar KEY_CONTAINER_FILE                     "Container.eha"          -- truecrypt container already created at or copied to above path                 
:setvar TRUECRYPT_EXE                          "G:\TrueCrypt\TrueCrypt.exe"  -- no need to install, just supply correct path to exe                       
:setvar VHD_LETTER                             "X"                      -- drive letter inside encrypted container used by exports                        
-- phrase used to create container needed to mount VHD - will be save in NameValues
:setvar TRUECRYPT_CONTAINER_ENCRYPTION_PHRASE  "Yu&6Gf%3Fe12KOU X@wcf?" -- "<[TRUECRYPT_CONTAINER_ENCRYPTION_PHRASE],SYSNAME,Yu&6Gf%3Fe12KOU X@wcf?>"     
-- master database encryption hierarchy (certificate is needed for TDE)  
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
:setvar CONTAINER_CERTIFICATE                  "ContainerCertificate"   -- "<[CONTAINER_CERTIFICATE] - sign a BLOB,SYSNAME,ContainerCertificate>          
:setvar CONTAINER_CERTIFICATE_BACKUP_PHRASE    "8u&6Rf%3Fe54?L SUD@wcf" -- "<[OBJECT_CERTIFICATE_BACKUP_PHRASE],PHRASE*,8u&6Rf%3Fe54?L SUD@wcf>"          
:setvar EHDB_DMK_BACKUP_PHRASE                 "Ru&6Gf%3F e6LOUD@wc?f"  -- "<[EHDB_DMK_BACKUP_PHRASE],PASSPHRASE*,Ru&6Gf%3F e6LOUD@wc?f>"                 
:setvar EHDB_DMK_ENCRYPTION_PHRASE             "Memorize this 1 4 sure!"-- "<[EHDB_DMK_ENCRYPTION_PHRASE],PASSPHRASE*,Memorize this 1 4 sure!>"           
:setvar ERROR_SYMMETRIC_KEY                    "ErrorKey"               -- "<[ERROR_SYMMETRIC_KEY],SYSNAME,ErrorKey>"                                     
:setvar ERROR_KEY_ENCRYPTION_ALGORITHM         "AES_256"                -- "<[ERROR_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                           
:setvar ERROR_KEY_ENCRYPTION_PHRASE            "Yu&6Gf %3Fe13FZRE@wc?f" -- "<[ERROR_KEY_ENCRYPYION_PHRASE],PASSPHRASE*,Yu&6Gf %3Fe13FZRE@wc?f>"           
:setvar ERROR_KEY_SOURCE                       "i$Db8d b vf989sb d&ubsG"-- "<[ERROR_KEY_SOURCE_PHRASE],PASSPHRASE*,i$Db8d b vf989sb d&ubsG>"              
:setvar ERROR_KEY_IDENTITY                     "t {bleS*&(d84vr4 67vfes"-- "<[ERROR_KEY_IDENTITY],PASSPHRASE*,t {bleS*&(d84vr4 67vfes>"                   
:setvar EVENT_CERTIFICATE                      "EventCertificate"       -- "<[EVENT_CERTIFICATE],SYSNAME,EventCertificate>                                
:setvar EVENT_CERTIFICATE_BACKUP_PHRASE        "oU7^gF5%fE!1lI ouD2WC/F"-- "<[EVENT_CERTIFICATE_BACKUP_PHRASE],PASSPHRASE*,oU7^gF5#fE!!l ouD2WC/F>"       
:setvar EVENT_NOTIFICATION                     "DDLChanges"             -- "<[EVENT_NOTIFICATION],SYSNAME,DDLChanges>"
:setvar FILE_CERTIFICATE                       "FileCertificate"        -- "<[FILE_CERTIFICATE],SYSNAME,FileCertificate>                                  
:setvar FILE_CERTIFICATE_ENCRYPTION_PHRASE     "sd89f7ny*&NH 8E43BHFjh" -- "<[FILE_CERTIFICATE_ENCRYPTION_PHRASE],PASSPHRASE*,sd89f7ny*&NH 8E43BHFjh>"    
:setvar FILE_CERTIFICATE_BACKUP_PHRASE         "d QW87!DtsHF387w$32VFw" -- "<[FILE_CERTIFICATE_BACKUP_PHRASE],PHRASE*,d QW87!DtsHF387w$32VFw>"            
:setvar FILE_SYMMETRIC_KEY                     "FileKey"                -- "<[FILE_SYMMETRIC_KEY],SYSNAME,FileKey>"                                       
:setvar FILE_KEY_ENCRYPTION_ALGORITHM          "AES_256"                -- "<[FILE_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                            
:setvar HASHBYTES_ALGORITHM                    "SHA2_512"               -- "<[HASHBYTES_ALGORITHM],SYSNAME,SHA2_512>"                                     
:setvar MESSAGE_OFFSET                         "21474836"               -- "<[MESSAGE_OFFSET] - between 500 and 21474836, INT,21474836>"                  
:setvar MIN_PHRASE_LENGTH                      "21"                     -- "<[MIN_PHRASE_LENGTH] - Min phrase length (max is 128),TINYINT,21>"            
:setvar NAME_CERTIFICATE                       "NameCertificate"        -- "<[OBJECT_CERTIFICATE],SYSNAME,NameCertificate>                                
:setvar NAME_CERTIFICATE_ENCRYPTION_PHRASE     "Fe9 ROIT@wc?fZu&6Gf%3"  -- "<[OBJECT_CERTIFICATE_ENCRYPTION_PHRASE],PASSPHRASE*,Fe9 ROIT@wc?fZu&6Gf%3>"   
:setvar NAME_CERTIFICATE_BACKUP_PHRASE         "Fe10L SUD@wcf?Lu&6Gf%3" -- "<[OBJECT_CERTIFICATE_BACKUP_PHRASE],PHRASE*,Fe10L SUD@wcf?Lu&6Gf%3>"          
:setvar NAME_SYMMETRIC_KEY                     "NameKey"                -- "<[NAME_SYMMETRIC_KEY],SYSNAME,ValueKey>"                                      
:setvar NAME_KEY_ENCRYPTION_ALGORITHM          "AES_256"                -- "<[NAME_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                            
:setvar OBJECT_CERTIFICATE                     "ObjectCertificate"      -- "<[OBJECT_CERTIFICATE],SYSNAME,ObjectCertificate>                              
:setvar OBJECT_CERTIFICATE_ENCRYPTION_PHRASE   "Lu&6Gf%3Fe9 ROIT@wc?f"  -- "<[OBJECT_CERTIFICATE_ENCRYPTION_PHRASE],PASSPHRASE*,Lu&6Gf%3Fe9 ROIT@wc?f>"   
:setvar OBJECT_CERTIFICATE_BACKUP_PHRASE       "Zu&6Gf%3Fe10L SUD@wcf?" -- "<[OBJECT_CERTIFICATE_BACKUP_PHRASE],PHRASE*,Zu&6Gf%3Fe10L SUD@wcf?>"          
:setvar SMK_BACKUP_PHRASE                      "Ku&6 Gf43Fe1 UIOE@zcf?" -- "<[SMK_BACKUP_PHRASE] Service Master Key,PASSPHRASE*,Ku&6 Gf43Fe1 UIOE@zcf?>"  
:setvar USE_HASH_FOR_FILENAME                  "1"                      -- "<[USE_HASH_FOR_FILENAME],BIT,0>"                                              
:setvar VALUE_CERTIFICATE                      "ValueCertificate"       -- "<[VALUE_CERTIFICATE],SYSNAME,ValueCertificate>"                               
:setvar VALUE_CERTIFICATE_BACKUP_PHRASE        "Mu&6Gf%3Fe 8VKUA@wcf?"  -- "<[VALUE_CERTIFICATE_BACKUP_PHRASE],PASSPHRASE,Mu&6Gf%3Fe 8VKUA@wcf?>"         
:setvar VALUE_SYMMETRIC_KEY                    "ValueKey"               -- "<[VALUE_SYMMETRIC_KEY],SYSNAME,ValueKey>"                                     
:setvar VALUE_KEY_ENCRYPTION_ALGORITHM         "AES_256"                -- "<[VALUE_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                           
-- ODBC DSN  to offsite backup, if the DSN works the offsite processing should as well. 
:setvar LINK_SERVER_ODBC_DSN                   "testHub"                -- "<[LINK_SERVER_ODBC_DSN],SYSNAME,testHub>"                                     
:setvar LINK_SERVER                            "HubLinkedServer"        -- "<[LINK_SERVER],SYSNAME,HubLinkedServer>"                                      
:setvar LINK_EHDB                              "ehdbHub"                -- "<[LINKED_EHDB],SYSNAME,ehdbHub>"                                              
:setvar LINK_USER                              "bwunder"                -- "<[LINK_USER],SYSNAME,bwunder>"                                                
:setvar LINK_PASSWORD                          "si*%tFE#4RfHgf"         -- "<[LINK_PASSWORD],SYSNAME,si*%tFE#4RfHgf>"                                     
-- DATABASE SCHEMA 
-- Spoke only
:setvar EHADMIN_ROLE                           "EHAdminRole"           
:setvar EHDB                                   "ehdb"                  
:setvar FILESTREAM_FILEGROUP                   "FILESTREAMS"           
:setvar FILESTREAM_FILE                        "ehdb_filestreams"      
:setvar FILETABLE_BACKUPS                      "Backups"               
:setvar FILETABLE_DIRECTORY                    "ehdb_filetables"       
:setvar RESTORE_FILETABLE                      "Restores"              
-- common to hub and spoke
:setvar EHA_SCHEMA                             "eha"                   
:setvar BOOKINGS_TABLE                         "Bookings"              
:setvar BACKUP_ACTIVITY_TABLE                  "BackupActivity"        
:setvar CONTAINERS_TABLE                       "Containers"            
:setvar CONTAINER_ACTIVITY_TABLE               "ContainerActivity"     
:setvar NOTIFICATION_ACTIVITY_TABLE            "NotificationActivity"  
:setvar NAMEVALUES_TABLE                       "NameValues"            
:setvar NAMEVALUE_ACTIVITY_TABLE               "NameValueActivity"     
:setvar OFFSITE_ACTIVITY_TABLE                 "OffsiteActivity"       
:setvar REPORT_ACTIVITY_TABLE                  "ReportActivity"        
-- local synonym for hub tables
:setvar LINK_BOOKINGS_SYNONYM                  "zBookings"             
:setvar LINK_BACKUP_ACTIVITY_SYNONYM           "zBackupActivity"       
:setvar LINK_CONTAINERS_SYNONYM                "zContainers"           
:setvar LINK_CONTAINER_ACTIVITY_SYNONYM        "zContainerActivity"    
:setvar LINK_NAMEVALUES_SYNONYM                "zNameValues"           
:setvar LINK_NAMEVALUE_ACTIVITY_SYNONYM        "zNameValueActivity"    
:setvar LINK_NOTIFICATION_ACTIVITY_SYNONYM     "zNotificationActivity" 
:setvar LINK_OFFSITE_ACTIVITY_SYNONYM          "zOffsiteActivity"      
:setvar LINK_REPORT_ACTIVITY_SYNONYM           "zReportActivity"       
-- compared to catalog in OpenSession to verify unchanged since install
:setvar OBJECT_COUNT                           "62"                    -- schema object count from sys.objects
:setvar TABLE_COUNT                            "10"                    -- schema synonym count from sys.synoyms
--- export file extensions                                              
:setvar MASTER_KEY_BACKUP_EXT                  ".keybak"               
:setvar PRIVATE_KEY_BACKUP_EXT                 ".prvbak"               
:setvar PUBLIC_KEY_BACKUP_EXT                  ".cerbak"               
:setvar ALLOW_TRACE_COUNT                      1                       
GO  

-- created ODBC DSN using ODBCad32.exe or application
IF NOT EXISTS (SELECT * FROM sys.servers
               WHERE NAME = N'$(LINK_SERVER)' )
  EXEC master.dbo.sp_addlinkedserver @server = N'$(LINK_SERVER)'
                                   , @srvproduct = N'Any'
                                   , @provider=N'MSDASQL'
                                   , @datasrc=N'$(LINK_SERVER_ODBC_DSN)'; 
GO
IF NOT EXISTS (SELECT * 
               FROM sys.linked_logins l
               JOIN sys.servers s
               ON l.server_id = s.server_id
               WHERE s.name = N'$(LINK_SERVER)' 
               AND l.remote_name = N'$(LINK_USER)')
  EXEC master.dbo.sp_addlinkedsrvlogin @rmtsrvname = N'$(LINK_SERVER)'
                                     , @useself = N'False'
                                     , @locallogin = NULL -- all comers
                                     , @rmtuser = N'$(LINK_USER)'
                                     , @rmtpassword='$(LINK_PASSWORD)';
GO
-- if truecrypt cannot dismount any existing drive $(VHD_LETTER) the script will stop
:!!if exist $(VHD_LETTER):\) "$(TRUECRYPT_EXE)" /q /s /d X /f)\           
GO
:!!$(TRUECRYPT_EXE) /v $(KEY_CONTAINER_PATH)$(KEY_CONTAINER_FILE) /l$(VHD_LETTER) /p "$(TRUECRYPT_CONTAINER_ENCRYPTION_PHRASE)" /q /s /m
GO
USE master;
GO
IF LEFT('$(EHDB)',1) = '$'
  RAISERROR('Enable the SSMS Query menu item "SQLCMD Mode" option before executing this script.',16,1);
GO
IF NOT EXISTS( SELECT * 
               FROM sys.server_principals 
               WHERE name = ORIGINAL_LOGIN() 
               AND type = 'U'
               AND IS_SRVROLEMEMBER('sysadmin') = 1 )
  RAISERROR('A Windows authenticated member of the sysadmin fixed server role must execute this script.',16, 1);
GO      
IF ISNULL(PARSENAME ( CONVERT(NVARCHAR(128), SERVERPROPERTY('ProductVersion')) , 4 ), 0) < 11
  RAISERROR('SQL Server 2012 or later is required.',16, 1);
GO
-- self-signed certificates are easier prey for authentication relay exploits (aka man in the middle)
IF (SELECT UPPER(encrypt_option) FROM sys.dm_exec_connections WHERE session_id = @@spid) = 'FALSE'
  RAISERROR('Consider a self signed certificate if SSL is unavailable. Unencrypted connections risk data exposure on the wire.  see http://msdn.microsoft.com/en-us/library/ms191192.aspx' ,0 ,0);
GO
-- Configure filestream at install or in SQL Configuration Manger
-- Enable the configuration using sp_configure 'filestream access level', 2; RECONFIGURE;
IF NOT EXISTS ( SELECT * FROM sys.configurations 
                WHERE name = 'filestream access level'
                AND value = 2)
  RAISERROR('FILESTREAM for Transact-SQL and Win32 streaming access must be configured and enabled.',16, 1);
GO
RAISERROR('Verify that no key-logging device or software has captured your PASSPHRASEs  see http://wskills.blogspot.com/2007/01/how-to-find-fight-keyloggers.html and http://msdn.microsoft.com/en-us/library/ff648641.aspx',0,0);
GO
IF NOT ($(MESSAGE_OFFSET) BETWEEN 500 AND 21474836)
  RAISERROR('MESSAGE_OFFSET must be between 500 and 21474836.',16, 1);
GO
--  only TDE capable - e.g. Developer, Enterprise, and Data Center SKUs
IF PATINDEX('%[Developer,Enterprise]%', CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128) ) ) > 0 
  BEGIN
    -- Certificate in master for TDE encrypted by master DMK (which is encrypted by the SMK (DPAPI)) 
    IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE symmetric_key_id = 101)
      CREATE MASTER KEY ENCRYPTION BY PASSWORD = '$(master_DMK_ENCRYPTION_PHRASE)'
    ELSE 
      OPEN MASTER KEY DECRYPTION BY PASSWORD = '$(master_DMK_ENCRYPTION_PHRASE)';
    IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = '$(TDE_CERTIFICATE)')
      CREATE CERTIFICATE $(TDE_CERTIFICATE) WITH SUBJECT = '$(EHDB) TDE DEK';
  END
GO
IF (SELECT value FROM sys.configurations
    WHERE name = 'clr enabled') <> 1
  BEGIN
    EXEC sp_configure 'clr enabled', 1;
    RECONFIGURE;
  END
GO
IF (SELECT value FROM sys.configurations 
    WHERE name = 'max text repl size (B)') <> -1
AND PATINDEX( '%[Developer,Enterprise]%'
            , CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128) ) ) <> 0
  BEGIN
    EXEC sp_configure 'max text repl size (B)', -1;
    RECONFIGURE;            
    RAISERROR('The "max text repl size (B)" configuration option is set to -1',0,0);
  END
GO
IF DB_ID('$(EHDB)') IS NULL
  CREATE DATABASE $(EHDB); 
GO
USE $(EHDB);
GO
IF DB_NAME() <> '$(EHDB)' 
  RAISERROR('Database $(EHDB) not found. Script aborted.',16, 1);
GO
-- no need to persist EHAdmin objects in the plan cache, Auto close will clear the db from 
-- sys.dm_exec_query_stats also some risk that leaving an idle database 
-- online presents a better learning opportunity for the uninvited - this db should be idle most of 
-- the time so no need to leave the compiled queries In Cache until they age out. The procedure cache is
-- cleared when the db closes (when last user disconnects). AUTO_CLOSE will also provide a failsafe 
-- to assure the master key is closed if it somehow is left open leaving the session vulnerable 
-- if hijacked in an elevation of authority attack 
-- setting the UI to auto disconnect from the database after each execution is also worth considering
-- In a busy database AUTO_CLOSE offers no real advantage, just creates an ocassional very slow connection to open. 
ALTER DATABASE $(EHDB) SET AUTO_CLOSE ON;    
GO
-- intended for use only by mad scientists at M$ labs and the catatonically insane me thinks
ALTER DATABASE $(EHDB) SET TRUSTWORTHY OFF;    
GO
-- prevents elevation of authority attacks by users connected to other databases within the SQL Server 
ALTER DATABASE $(EHDB) SET DB_CHAINING OFF; 
GO
-- provides the ability to review state after the fact using point-in-time restore
ALTER DATABASE $(EHDB) SET RECOVERY FULL;  
GO
--FILETABLE does not like SNAPSHOT - must use WITH (READCOMMITTED LOCKS_ hint to query
ALTER DATABASE $(EHDB) SET READ_COMMITTED_SNAPSHOT ON;
GO
-- allow only db_owner dbcreator, sysadmin fixed server role members 
-- this assure there can be no valid role members because the only valid
-- databased scoped identity is always going to be 'dbo' - BUT just because
-- a user is dbo does not mean they have the phrase needed to open the DMK
ALTER DATABASE $(EHDB) SET RESTRICTED_USER; 
GO
-- move dbo to sa so no conflicts when current user added to role
-- sa should also be disabled, and may also be renamed 
-- SQL authentication should also be disabled.
IF (SELECT owner_sid FROM sys.databases where name = DB_NAME()) <> 0x01
  BEGIN
    DECLARE @Name NVARCHAR(128), @ChangeDbOwnerDDL NVARCHAR(128);
    SET @Name = (SELECT name FROM sys.server_principals WHERE sid = 0x01);
    SET @ChangeDbOwnerDDL = 'ALTER AUTHORIZATION ON DATABASE::$(EHDB) TO ' + @Name;
    IF @Name = 'sa'
      RAISERROR('Consider renaming login [sa].  see http://blogs.msdn.com/b/data_otaku/archive/2011/06/22/secure-the-authentication-process.aspx', 0, 0);
    IF (SELECT is_disabled FROM sys.server_principals WHERE sid = 0x01) = 0
      RAISERROR('Consider disabling login [%s]  see http://lmgtfy.com/?q=brute+force+sa+password+attack',0 ,0 , @Name); 
    IF SERVERPROPERTY('IsIntegratedSecurityOnly') <> 1
      RAISERROR('Consider using only Windows Integrated Security.  see http://www.microsoft.com/technet/security/advisory/973811.mspx', 0, 0);
    -- could already be claims based in use, cannot detect from here
    IF ( SELECT UPPER(auth_scheme)  FROM sys.dm_exec_connections 
         WHERE session_id = @@spid ) <> 'KERBEROS'
      RAISERROR('Consider using "KERBEROS" or claims based authentication.  see http://blogs.msdn.com/b/sql_protocols/archive/2006/12/02/understanding-kerberos-and-ntlm-authentication-in-sql-server-connections.aspx',0,0);
    -- without CC column level GRANT overrides table level DENY, other way around with CC
    -- also enabled login auditing and hardens security in memory
    IF ( SELECT value FROM sys.configurations
         WHERE name = 'common criteria compliance enabled' ) <> 1
      RAISERROR('Consider enabling Common Criteria (CC) compliance, even if you do not enable the CC Trace.  see http://msdn.microsoft.com/en-us/library/bb326650(v=SQL.110).aspx', 0, 0);
    EXEC sp_executesql @ChangeDbOwnerDDL; 
  END
GO
IF NOT EXISTS ( SELECT * 
                FROM sys.database_principals 
                WHERE name = ORIGINAL_LOGIN() ) 
  BEGIN
    DECLARE @CreateUserDDL NVARCHAR(128);
    SET @CreateUserDDL = 'CREATE USER [' + ORIGINAL_LOGIN() + '] FROM LOGIN [' + ORIGINAL_LOGIN() + '];'
    EXEC sp_executesql @CreateUserDDL;
  END 
GO 
IF NOT EXISTS ( SELECT *
                FROM sys.database_principals
                WHERE name = '$(EHADMIN_ROLE)' )  
  BEGIN
    DECLARE @CreateRoleDDL NVARCHAR(128);
    SET @CreateRoleDDL = 'CREATE ROLE $(EHADMIN_ROLE) AUTHORIZATION [' + ORIGINAL_LOGIN() + '];' 
    EXEC sp_executesql @CreateRoleDDL;
  END
GO
IF IS_MEMBER('$(EHADMIN_ROLE)') <> 1
  BEGIN
    DECLARE @AddToRoleDDL NVARCHAR(128);
    SET @AddToRoleDDL = 'ALTER ROLE $(EHADMIN_ROLE) ADD MEMBER [' + ORIGINAL_LOGIN() + ']';
    --2008/5/0 --SET @AddToRoleDDL = 'EXEC sp_addrolemember ''$(EHADMIN_ROLE)'',[' + ORIGINAL_LOGIN() + ']';
    EXEC sp_executesql @AddToRoleDDL;
  END  
GO
-- see security comments in sp_control_dbmasterkey_password documention 
-- it is when you must pass the secret to a procedure/function that they can sneak through
-- in-line crypto-functions will always obfuscate in the SQL Trace
IF NOT EXISTS (SELECT * 
               FROM sys.symmetric_keys 
               WHERE symmetric_key_id = 101)
  CREATE MASTER KEY ENCRYPTION BY PASSWORD = '$(EHDB_DMK_ENCRYPTION_PHRASE)';
GO
-- remove SMK encryption of the DMK - phrase encryption only
OPEN MASTER KEY DECRYPTION BY PASSWORD = '$(EHDB_DMK_ENCRYPTION_PHRASE)'
GO
ALTER MASTER KEY DROP ENCRYPTION BY SERVICE MASTER KEY; 
GO
ALTER MASTER KEY REGENERATE 
WITH ENCRYPTION BY PASSWORD = '$(EHDB_DMK_ENCRYPTION_PHRASE)';
GO
OPEN MASTER KEY 
DECRYPTION BY PASSWORD = '$(EHDB_DMK_ENCRYPTION_PHRASE)';
GO
IF NOT EXISTS (SELECT * FROM sys.certificates 
               WHERE name = '$(FILE_CERTIFICATE)')
  CREATE CERTIFICATE $(FILE_CERTIFICATE) 
  WITH SUBJECT = 'File System literal Column Encryption';
GO
IF NOT EXISTS (SELECT * 
               FROM sys.symmetric_keys 
               WHERE name = '$(FILE_SYMMETRIC_KEY)')
	CREATE SYMMETRIC KEY $(FILE_SYMMETRIC_KEY) 
	WITH ALGORITHM = $(FILE_KEY_ENCRYPTION_ALGORITHM) 
	ENCRYPTION BY CERTIFICATE $(FILE_CERTIFICATE);
GO
IF NOT EXISTS (SELECT * FROM sys.certificates 
               WHERE name = '$(NAME_CERTIFICATE)')
  CREATE CERTIFICATE $(NAME_CERTIFICATE) 
  WITH SUBJECT = 'Name Column Encryption';
GO
IF NOT EXISTS (SELECT * 
               FROM sys.symmetric_keys 
               WHERE name = '$(NAME_SYMMETRIC_KEY)')
	CREATE SYMMETRIC KEY $(NAME_SYMMETRIC_KEY) 
	WITH ALGORITHM = $(NAME_KEY_ENCRYPTION_ALGORITHM) 
	ENCRYPTION BY CERTIFICATE $(NAME_CERTIFICATE);
GO
IF NOT EXISTS (SELECT * FROM sys.certificates 
               WHERE name = '$(VALUE_CERTIFICATE)')
  CREATE CERTIFICATE $(VALUE_CERTIFICATE) 
  WITH SUBJECT = 'Value Column Encryption';
GO
IF NOT EXISTS (SELECT * 
               FROM sys.symmetric_keys 
               WHERE name = '$(VALUE_SYMMETRIC_KEY)')
	CREATE SYMMETRIC KEY $(VALUE_SYMMETRIC_KEY) 
	WITH ALGORITHM = $(VALUE_KEY_ENCRYPTION_ALGORITHM) 
	ENCRYPTION BY CERTIFICATE $(VALUE_CERTIFICATE);
GO
-- signed cert is not a dependant of the DMK - only the one(s) responsible for change
-- should to be allowed to open this certificate or view its secrets 
IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = '$(OBJECT_CERTIFICATE)')
  CREATE CERTIFICATE $(OBJECT_CERTIFICATE)
	ENCRYPTION BY PASSWORD = N'$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)'
  WITH SUBJECT = N'Encryption Hieararchy Administrator db object Signing';
GO
-- with no password on the cert and the DMK not encrypted by the SMK, the DMK must be open to use
-- only the data owner(s) should be allowed to open this certificate , i.e. have the DMK PASSPHRASE
IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = '$(AUTHENTICITY_CERTIFICATE)')
  CREATE CERTIFICATE $(AUTHENTICITY_CERTIFICATE) 
  WITH SUBJECT = 'Encryption Hieararchy Administrator Booking Gauntlet T-shirt';
GO
-- with no password on the cert and the DMK not encrypted by the SMK, the DMK must be open to use
-- only the data owner(s) should be allowed to open this certificate , i.e. have the DMK PASSPHRASE
IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = '$(EVENT_CERTIFICATE)')
  CREATE CERTIFICATE $(EVENT_CERTIFICATE) 
  WITH SUBJECT = 'Signature of EventData applied at activation';
GO
-- error cert is independant from DMK and portable 
-- create same key on any SQL Server 2005/2008/2012 by providing name, source and identity
-- not as secure becasue if anyone gets name, source and identity they can see the cipher text in clear text
-- not quite as bad as a shared password but close, very important to rotate encryption password often
IF NOT EXISTS (SELECT * 
               FROM sys.symmetric_keys 
               WHERE name = '$(ERROR_SYMMETRIC_KEY)')
	CREATE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY) 
    WITH ALGORITHM = $(ERROR_KEY_ENCRYPTION_ALGORITHM)
     , KEY_SOURCE = '$(ERROR_KEY_SOURCE)'
     , IDENTITY_VALUE =  '$(ERROR_KEY_IDENTITY)'
	ENCRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
GO
-- audit certificate is independent FROM DMK 
IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = '$(AUDIT_CERTIFICATE)')
  CREATE CERTIFICATE $(AUDIT_CERTIFICATE) 
	ENCRYPTION BY PASSWORD = '$(AUDIT_CERTIFICATE_ENCRYPTION_PHRASE)'
  WITH SUBJECT = 'Encryption Hierarchy Administrator Audit Trail';
GO
-- audit key is sticky to the database 
IF NOT EXISTS (SELECT * 
               FROM sys.symmetric_keys 
               WHERE name = '$(AUDIT_SYMMETRIC_KEY)')
	CREATE SYMMETRIC KEY $(AUDIT_SYMMETRIC_KEY) 
	WITH ALGORITHM = $(AUDIT_KEY_ENCRYPTION_ALGORITHM) 
	ENCRYPTION BY CERTIFICATE $(AUDIT_CERTIFICATE);
GO
IF SCHEMA_ID('$(EHA_SCHEMA)') IS NULL
  BEGIN
    EXEC sp_executesql N'CREATE SCHEMA [$(EHA_SCHEMA)] AUTHORIZATION [$(EHADMIN_ROLE)]';
    -- with Common Criteria enabled this overrides any column level GRANT too 
    DENY DELETE, UPDATE ON SCHEMA::$(EHA_SCHEMA) TO PUBLIC;
  END
GO
IF OBJECT_ID('$(EHA_SCHEMA).$(BOOKINGS_TABLE)') IS NULL
  BEGIN
	   CREATE TABLE $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
		    ( Id UNIQUEIDENTIFIER NOT NULL ROWGUIDCOL
              CONSTRAINT dft_$(BOOKINGS_TABLE)__Id
              DEFAULT NEWSEQUENTIALID()
        , ServerName NVARCHAR(128) NOT NULL
		      CONSTRAINT dft_$(BOOKINGS_TABLE)__ServerName
		      DEFAULT (@@SERVERNAME)
		    , ProcId INT NULL
		    , ObjectName NVARCHAR (128) NULL
		    , Parameters VARBINARY (8000) NOT NULL
        , KeyGuid NCHAR(36) NOT NULL
        , Status VARCHAR (30) NOT NULL
          CONSTRAINT ck_$(BOOKINGS_TABLE)__Status 
          CHECK (Status IN ( 'audit'
                           , 'authority'
                           , 'cert'
                           , 'config'
                           , 'insert'
                           , 'keys'
                           , 'DMK'
                           , 'messages'
                           , 'objects'
                           , 'OK'
                           , 'probe'
                           , 'bridge'
                           , 'sign'
                           , 'whitelist'))
        , ErrorData VARBINARY(8000) SPARSE NULL
		    , CreateUTCDT DATETIME NOT NULL
		      CONSTRAINT dft_$(BOOKINGS_TABLE)__CreateUTCDT
		      DEFAULT (SYSUTCDATETIME())
		    , CreateUser NVARCHAR(128) NOT NULL
		      CONSTRAINT dft_$(BOOKINGS_TABLE)__CreateUser
		      DEFAULT (ORIGINAL_LOGIN())  
		    , CONSTRAINT pkc_$(BOOKINGS_TABLE)__Id__ServerName
		      PRIMARY KEY (Id, ServerName) );
    ADD SIGNATURE TO $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
  END
GO
IF NOT EXISTS (SELECT * FROM sys.indexes where name = 'ixn_$(BOOKINGS_TABLE)__KeyGuid__ServerName')
  CREATE NONCLUSTERED INDEX ixn_$(BOOKINGS_TABLE)__KeyGuid__ServerName
  ON $(EHA_SCHEMA).$(BOOKINGS_TABLE) ( KeyGuid, ServerName );
GO
IF NOT EXISTS (SELECT * FROM sys.indexes where name = 'ixn_$(BOOKINGS_TABLE)__CreateUTCDT__ServerName')
  CREATE NONCLUSTERED INDEX ixn_$(BOOKINGS_TABLE)__CreateUTCDT__ServerName
  ON $(EHA_SCHEMA).$(BOOKINGS_TABLE) ( CreateUTCDT, ServerName );
GO
IF NOT EXISTS (SELECT * FROM sys.indexes where name = 'ixn_$(BOOKINGS_TABLE)__ObjectName__ServerName')
  CREATE NONCLUSTERED INDEX ixn_$(BOOKINGS_TABLE)__ObjectName__ServerName
  ON $(EHA_SCHEMA).$(BOOKINGS_TABLE) ( ObjectName, ServerName);
GO
-- every backup and restore logs to BACKUP_ACTIVITY_TABLE upon completion
IF OBJECT_ID('$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)') IS NULL
  BEGIN
	   CREATE TABLE $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
		    ( Id UNIQUEIDENTIFIER NOT NULL ROWGUIDCOL
		    , ServerName NVARCHAR(128) NOT NULL 
		      CONSTRAINT dft_$(BACKUP_ACTIVITY_TABLE)__ServerName
		      DEFAULT (@@SERVERNAME)
		    , DbName NVARCHAR(128) NOT NULL
        , Node HIERARCHYID NULL 
        , Level AS Node.GetLevel() PERSISTED 
		    , NodeName NVARCHAR (128) NOT NULL
		    , BackupName VARBINARY(8000) NOT NULL -- CalculateCipherLen('ValueKey',896,1)=964-- NVARCHAR(448)
		    , BackupNameBucket INT NOT NULL 
        , UseHash BIT NOT NULL          
		    , BackupPath VARBINARY(8000) NOT NULL -- CalculateCipherLen('ValueKey',2048,1)=2116-- NVARCHAR(1024)
		    , BackupPhraseVersion SMALLINT NOT NULL
		    , KeyPhraseVersion SMALLINT NULL
        , Colophon INT NOT NULL  -- checksum of the hash of key guids and cert thumbprints- not presumed unique
        , Edition SMALLINT NOT NULL  -- the number of backups made for the current Colophon       
		      CONSTRAINT dft_$(BACKUP_ACTIVITY_TABLE)__Version 
		      DEFAULT (1)
            , MAC VARBINARY (128) NOT NULL
		    , Action VARCHAR (30) NOT NULL
		    , Status VARCHAR (30) NOT NULL
          CONSTRAINT ck_$(BACKUP_ACTIVITY_TABLE)__Status 
          CHECK (Status IN ( 'Complete'
							, 'Error'
							, 'Instead'
							, 'Offsite' ) ) 
        , CipherType CHAR (2) NOT NULL
          CONSTRAINT ck_$(BACKUP_ACTIVITY_TABLE)__CipherType 
          CHECK (CipherType IN ( 'A1'   -- AES 128 
								, 'A2'   -- AES 192
								, 'A3'   -- AES 256 (all Denali DPAPI?)
								, 'AK'   -- asymmetric key
								, 'D3'   -- Triple DES (all Katmai & Yukon DPAPI?)
								, 'DT'   -- Triple DES 3KEY
								, 'NA'   -- EKM or private key has been dropped
								, 'MK'   -- database master key
								, 'PW'   -- passphrase
								, 'SK'   -- symmetric key
								, 'SM'   -- service master key
								, 'SP'   -- service master key AND passphrase
								, '' ) ) -- undetermined
	      , ErrorData VARBINARY(8000) SPARSE NULL
		    , CreateUTCDT DATETIME NOT NULL
		      CONSTRAINT dft_$(BACKUP_ACTIVITY_TABLE)__CreateUTCDT
		      DEFAULT (SYSUTCDATETIME())
		    , CreateUser NVARCHAR(128) NOT NULL
		      CONSTRAINT dft_$(BACKUP_ACTIVITY_TABLE)__CreateUser
		      DEFAULT (ORIGINAL_LOGIN())   
		    , CONSTRAINT pk_$(BACKUP_ACTIVITY_TABLE)__Id__ServerName
		      PRIMARY KEY ( Id, ServerName )
		    , CONSTRAINT fk_$(BACKUP_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
			    FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );
    ADD SIGNATURE TO $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
    CREATE NONCLUSTERED INDEX ixn_$(BACKUP_ACTIVITY_TABLE)__NodeName__ServerName
    ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)(NodeName, ServerName) INCLUDE (DbName, Action, Status); 
    CREATE NONCLUSTERED INDEX ixn_$(BACKUP_ACTIVITY_TABLE)__MAC__ServerName
    ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)(MAC, ServerName); 
    CREATE NONCLUSTERED INDEX ixn_$(BACKUP_ACTIVITY_TABLE)__Node__ServerName      -- this gives a warning but no real risk of even 5 byte HIERARCHYIDs here
    ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)(Node, ServerName);                  -- 38 bits for 6 level 100,000 nodes acc'd BOL (~5 bytes), only 4 level here
    CREATE NONCLUSTERED INDEX ixn_$(BACKUP_ACTIVITY_TABLE)__Level__Node__ServerName -- breadth-first index - same warning as depth first index
    ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)(Level, Node, ServerName);             
    CREATE NONCLUSTERED INDEX ixn_$(BACKUP_ACTIVITY_TABLE)__Colophon__Edition__ServerName
    ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) (Colophon, Edition, ServerName); 
    CREATE NONCLUSTERED INDEX ixn_$(BACKUP_ACTIVITY_TABLE)__BackupNameBucket__ServerName
    ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) (BackupNameBucket, ServerName); 
  END
GO
-- will usually have only 1 row that holds an image of the TrueCrypt container 
-- can also be used to store the blank container and backups from other servers (if they go to the same EHHubDb)
IF OBJECT_ID('$(EHA_SCHEMA).$(CONTAINERS_TABLE)', 'U') IS NULL
  BEGIN
    CREATE TABLE $(EHA_SCHEMA).$(CONTAINERS_TABLE)
      ( Id UNIQUEIDENTIFIER ROWGUIDCOL NOT NULL
      , ServerName NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(CONTAINERS_TABLE)__ServerName
		    DEFAULT (@@SERVERNAME)
      , Tag NVARCHAR(128) NOT NULL                             
        CONSTRAINT dft_$(CONTAINERS_TABLE)__Name
        DEFAULT ( 'DEFAULT' )
      , FileImage VARBINARY(MAX) NOT NULL 
      , Signature VARBINARY(8000) NOT NULL
      , CONSTRAINT pkc_$(CONTAINERS_TABLE)_Id__ServerName
        PRIMARY KEY (Id, ServerName) 
      , CONSTRAINT ukn_$(CONTAINERS_TABLE)_Tag__ServerName
        UNIQUE ( Tag, ServerName )                             
      , CONSTRAINT fk_$(CONTAINERS_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
		    FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)(Id, ServerName) );
    ADD SIGNATURE TO $(EHA_SCHEMA).$(CONTAINERS_TABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
  END    
GO
-- every filesystem backup to database and restore to filesystem of the truecrypt container gets a row upon completion  
IF OBJECT_ID('$(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE)', 'U') IS NULL
  BEGIN
    CREATE TABLE $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE)
      ( Id UNIQUEIDENTIFIER ROWGUIDCOL NOT NULL 
      , ServerName NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(CONTAINER_ACTIVITY_TABLE)__ServerName
		    DEFAULT (@@SERVERNAME)
      , FileName VARBINARY(8000)  
      , FilePath VARBINARY(8000) 
      , SizeInBytes BIGINT NOT NULL -- enough for uninvited to identify the local file? 
      , MAC VARBINARY (128) NOT NULL
		  , Action VARCHAR (30) NOT NULL
        CONSTRAINT ck_$(CONTAINER_ACTIVITY_TABLE)__Action 
        CHECK (Action IN ( 'BackupContainer'  -- Archive scope is complete schema 
                         , 'RestoreContainer' ) )
		  , Status VARCHAR (30) NOT NULL
        CONSTRAINT ck_$(CONTAINER_ACTIVITY_TABLE)__Status 
        CHECK (Status IN ( 'Complete'
                         , 'Error' ) )
      , ErrorData VARBINARY(8000) SPARSE NULL
		  , CreateUTCDT DATETIME NOT NULL
		    CONSTRAINT dft_$(CONTAINER_ACTIVITY_TABLE)__CreateUTCDT
		    DEFAULT (SYSUTCDATETIME())
		  , CreateUser NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(CONTAINER_ACTIVITY_TABLE)__CreateUser
		    DEFAULT (ORIGINAL_LOGIN())  
      , CONSTRAINT pkc_$(CONTAINER_ACTIVITY_TABLE)_Id__ServerName
        PRIMARY KEY (Id, ServerName) 
      , CONSTRAINT fk_$(CONTAINER_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
		    FOREIGN KEY ( Id, ServerName) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );
    ADD SIGNATURE TO $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
  END
GO
--every secret goes in NAMEVALUES_TABLE
IF OBJECT_ID('$(EHA_SCHEMA).$(NAMEVALUES_TABLE)') IS NULL
  BEGIN
    CREATE TABLE $(EHA_SCHEMA).$(NAMEVALUES_TABLE) 
	    ( Id UNIQUEIDENTIFIER NOT NULL ROWGUIDCOL
      , ServerName NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(NAMEVALUES_TABLE)__ServerName
		    DEFAULT (@@SERVERNAME)
	    , NameBucket INT NOT NULL 
      , ValueBucket INT NOT NULL
	    , Version SMALLINT NOT NULL 
		    CONSTRAINT dft_$(NAMEVALUES_TABLE)__Version 
		    DEFAULT (1)
	    , Name VARBINARY (8000) NOT NULL  
	    , Value VARBINARY (8000) NOT NULL --CalculateCipherLen 
	    , CreateUTCDT DATETIME NOT NULL
		    CONSTRAINT dft_$(NAMEVALUES_TABLE)__CreateUTCDT
		    DEFAULT (SYSUTCDATETIME())
	    , CreateUser NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(NAMEVALUES_TABLE)__CreateUser
		    DEFAULT (ORIGINAL_LOGIN())  
	    , CONSTRAINT pk_$(NAMEVALUES_TABLE)__Id__ServerName
		    PRIMARY KEY (Id, ServerName)
	    , CONSTRAINT uk_$(NAMEVALUES_TABLE)__ValueBucket__ServerName
		    UNIQUE (ValueBucket, ServerName) -- no password reuse
	    , CONSTRAINT uk_$(NAMEVALUES_TABLE)__NameBucket__Version__ServerName
		    UNIQUE ( NameBucket, Version, ServerName ) 
	    , CONSTRAINT fk_$(NAMEVALUES_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
		    FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );
    ADD SIGNATURE TO $(EHA_SCHEMA).$(NAMEVALUES_TABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
  END
GO 
-- used to pass encrypted name/value to avoid SQLTrace detection
IF TYPE_ID('NAMEVALUETYPE') IS NULL
  CREATE TYPE NAMEVALUETYPE AS TABLE
	  ( Name VARBINARY(8000) NOT NULL
	  , Value VARBINARY(8000) NOT NULL ); 	 
GO
-- every procedure that writes to or reads from NAMEVALUES_TABLE gets a row upon completion
IF OBJECT_ID('$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)') IS NULL
  BEGIN
	  CREATE TABLE $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
		  ( Id UNIQUEIDENTIFIER NOT NULL ROWGUIDCOL 
      , ServerName NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(NAMEVALUE_ACTIVITY_TABLE)__ServerName
		    DEFAULT (@@SERVERNAME)
      , MAC VARBINARY(128) NOT NULL
		  , Action VARCHAR (128) NOT NULL
		  , Status VARCHAR (30) NOT NULL
            CONSTRAINT ck_$(NAMEVALUE_ACTIVITY_TABLE)__Status 
            CHECK (Status IN ( 'Complete'
                             , 'Error'
                             , 'Instead'
                             , 'Invalid'
                             , 'Valid' ) )
		  , ErrorData VARBINARY(8000) SPARSE NULL 
		  , CreateUTCDT DATETIME NOT NULL
		    CONSTRAINT dft_$(NAMEVALUE_ACTIVITY_TABLE)__CreateUTCDT
		    DEFAULT (SYSUTCDATETIME())
		  , CreateUser NVARCHAR(128)
		    CONSTRAINT dft_$(NAMEVALUE_ACTIVITY_TABLE)__CreateUser
		    DEFAULT (ORIGINAL_LOGIN())  
		  , CONSTRAINT pk_$(NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName
		    PRIMARY KEY (Id, ServerName)
		  , CONSTRAINT fk_$(NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
		    FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );
    ADD SIGNATURE TO $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
  END
GO
-- the send offsite is automated by SQLAgent (if available) and Change Data Capture (preferred) or Change Tracking (if CDC not available) 
-- the recall and restore to FileTable always happen together but each gets its own log record and to different logging tables 
IF OBJECT_ID('$(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)') IS NULL
  BEGIN
    CREATE TABLE $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
      ( Id UNIQUEIDENTIFIER NOT NULL
      , CaptureInstance NVARCHAR(128) NOT NULL
        CONSTRAINT ck_$(OFFSITE_ACTIVITY_TABLE)__CaptureInstance 
        CHECK (CaptureInstance IN ( '$(EHA_SCHEMA)_$(BOOKINGS_TABLE)'
                                  , '$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE)' 
                                  , '$(EHA_SCHEMA)_$(CONTAINERS_TABLE)' 
                                  , '$(EHA_SCHEMA)_$(CONTAINER_ACTIVITY_TABLE)' 
                                  , '$(EHA_SCHEMA)_$(NAMEVALUES_TABLE)' 
                                  , '$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)' 
                                  , '$(EHA_SCHEMA)_$(NOTIFICATION_ACTIVITY_TABLE)' 
                                  , '$(EHA_SCHEMA)_$(OFFSITE_ACTIVITY_TABLE)' 
                                  , '$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE)' 
                                  , 'unknown') )
      , ServerName NVARCHAR(128) NOT NULL 
	      CONSTRAINT dft_$(OFFSITE_ACTIVITY_TABLE)__ServerName
	      DEFAULT (@@SERVERNAME)
      , MinLsn BINARY(10) NOT NULL
      , MaxLsn BINARY(10) NOT NULL
      , [RowCount] INT NULL
      , MAC VARBINARY(128) NOT NULL
      , Action VARCHAR(30)
        CONSTRAINT ck_$(OFFSITE_ACTIVITY_TABLE)__Action 
        CHECK ( Action IN ( 'SendOffsiteCDC'
                          , 'SendOffSiteTC' 
                          , 'RecallContainer' ) )
      , Status VARCHAR(30)
        CONSTRAINT ck_$(OFFSITE_ACTIVITY_TABLE)__Status 
        CHECK ( Status IN ( 'Complete'
                          , 'Error' ) )
      , ErrorData VARBINARY(8000) SPARSE NULL
      , CreateUTCDT DATETIME
        CONSTRAINT dft_$(OFFSITE_ACTIVITY_TABLE)__CreateUTCDT
		    DEFAULT (SYSUTCDATETIME())
	    , CreateUser NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(OFFSITE_ACTIVITY_TABLE)__CreateUser
		    DEFAULT ( ORIGINAL_LOGIN() ) 
      , CONSTRAINT pk_$(OFFSITE_ACTIVITY_TABLE)__Id__CaptureInstance_ServerName
        PRIMARY KEY (Id, CaptureInstance, ServerName ) 
      , CONSTRAINT fk_$(OFFSITE_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
        FOREIGN KEY ( Id, ServerName ) 
        REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );   
    ADD SIGNATURE TO $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';

  END 
GO
-- event notifications are persisted to this table by the activation proc
IF OBJECT_ID('$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)') IS NULL
  BEGIN
    CREATE TABLE $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)
      ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR(128) NOT NULL 
	      CONSTRAINT dft_$(NOTIFICATION_ACTIVITY_TABLE)__ServerName
	      DEFAULT (@@SERVERNAME)
      , ConversationHandle UNIQUEIDENTIFIER NOT NULL
      , ConversationGroupId UNIQUEIDENTIFIER NOT NULL
      , Message VARBINARY(MAX) NOT NULL
      , Signature VARBINARY(8000) NOT NULL
      , MAC VARBINARY(128) NOT NULL
      , Action VARCHAR(30)
      , Status VARCHAR(30)
        CONSTRAINT ck_$(NOTIFICATION_ACTIVITY_TABLE)__Status 
        CHECK ( Status IN ( 'Complete'
                          , 'Error' ) )
      , ErrorData VARBINARY(8000) SPARSE NULL
      , CreateUTCDT DATETIME
        CONSTRAINT dft_$(NOTIFICATION_ACTIVITY_TABLE)__CreateUTCDT
		    DEFAULT (SYSUTCDATETIME())
	    , CreateUser NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(NOTIFICATION_ACTIVITY_TABLE)__CreateUser
		    DEFAULT ( ORIGINAL_LOGIN() ) 
      , CONSTRAINT pk_$(NOTIFICATION_ACTIVITY_TABLE)__Id__ServerName
        PRIMARY KEY (Id, ServerName ) 
      , CONSTRAINT uk_$(NOTIFICATION_ACTIVITY_TABLE)__Id__ConversationHandle_ConversationGroupId_ServerName
        UNIQUE (Id, ConversationHandle, ConversationGroupId, ServerName ) 
      , CONSTRAINT fk_$(NOTIFICATION_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
        FOREIGN KEY ( Id, ServerName ) 
        REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );   
    ADD SIGNATURE TO $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
  END 
GO
-- every report gets a row upon completion
IF OBJECT_ID('$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)') IS NULL
  BEGIN
    CREATE TABLE $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
      ( Id UNIQUEIDENTIFIER NOT NULL ROWGUIDCOL 
      , ServerName NVARCHAR(128) NOT NULL 
	      CONSTRAINT dft_$(REPORT_ACTIVITY_TABLE)__ServerName
	      DEFAULT (@@SERVERNAME)
      , ReportProcedure NVARCHAR(128) NOT NULL
      , Duration_ms INT NULL 
      , RowsReturned INT NULL 
      , MAC VARBINARY(128) NOT NULL
	    , Status VARCHAR (30) NOT NULL
        CONSTRAINT ck_$(REPORT_ACTIVITY_TABLE)__Status 
        CHECK (Status IN ( 'Complete'
                          , 'Error' ) )
	    , ErrorData VARBINARY(8000) SPARSE NULL
	    , CreateUTCDT DATETIME NOT NULL
		    CONSTRAINT dft_$(REPORT_ACTIVITY_TABLE)__CreateUTCDT
		    DEFAULT (SYSUTCDATETIME())
	    , CreateUser NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(REPORT_ACTIVITY_TABLE)__CreateUser
		    DEFAULT (ORIGINAL_LOGIN())   
	    , CONSTRAINT pk_$(REPORT_ACTIVITY_TABLE)__Id__ServerName
		    PRIMARY KEY (Id, ServerName)
      , CONSTRAINT fk_$(REPORT_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
        FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );
    ADD SIGNATURE TO $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';

    CREATE NONCLUSTERED INDEX ixn_$(REPORT_ACTIVITY_TABLE)__CreateUTCDT__ServerName
    ON $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)(CreateUTCDT, ServerName); 
  END
GO
------------------------------ 
-- SQL 2012 FileTable (RTM) 
------------------------------
-- one filegroup for FILESTREAM and/or FILETABLE 
-- 
-- steps to a filetable
-- 0. FILESTREAM is enabled at the instance level (SQL Confg. Mgr.by Windows Admin)
-- 1. Add FILESTREAM File Group
  IF NOT EXISTS ( SELECT * FROM sys.filegroups
                  WHERE name = '$(FILESTREAM_FILEGROUP)' )
    ALTER DATABASE $(EHDB)
    ADD FILEGROUP $(FILESTREAM_FILEGROUP) 
    CONTAINS FILESTREAM;
  GO
-- 2. Add a folder (SQL calls it a file but is a visible folder in Windows Explorer.) 
--    for restores along side the export container...  
  IF NOT EXISTS ( SELECT * FROM sys.database_files
                  WHERE name = '$(FILETABLE_DIRECTORY)' )
      ALTER DATABASE $(EHDB)
      ADD FILE 
      (
          NAME = '$(FILETABLE_DIRECTORY)',
          FILENAME = '$(KEY_CONTAINER_PATH)$(FILETABLE_DIRECTORY)'
      )
      TO FILEGROUP $(FILESTREAM_FILEGROUP);
GO
-- 3. Specify the level of non-transactional file system access 
-- 4. Specify a Directory for FileTables at the Database Level
  IF NOT EXISTS ( SELECT * 
                  FROM sys.database_filestream_options
                  WHERE database_id = DB_ID()
                  AND directory_name = '$(FILETABLE_DIRECTORY)' 
                  AND non_transacted_access = 2) 
    ALTER DATABASE $(EHDB)
    SET FILESTREAM ( NON_TRANSACTED_ACCESS = FULL               
                   , DIRECTORY_NAME = '$(FILETABLE_DIRECTORY)' );
GO
  -- 5. Add a FileTable for recall/restores
  --    need enough free space here to hold container recalled from hub 
  IF NOT EXISTS ( SELECT * 
                  FROM sys.filetables
                  WHERE directory_name = '$(FILETABLE_DIRECTORY)'
                  AND OBJECT_ID('$(EHA_SCHEMA).$(RESTORE_FILETABLE)') IS NULL) 
  BEGIN
    CREATE TABLE $(EHA_SCHEMA).$(RESTORE_FILETABLE) AS FileTable;
    ADD SIGNATURE TO $(EHA_SCHEMA).$(RESTORE_FILETABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
  END
GO
-----------------------------------------------------------------
-- Offsite 
-- change data capture if available else change tracking
-----------------------------------------------------------------
CREATE SYNONYM [$(EHA_SCHEMA)].[$(LINK_BOOKINGS_SYNONYM)] 
  FOR [$(LINK_SERVER)].[$(LINK_EHDB)].[$(EHA_SCHEMA)].[$(BOOKINGS_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(LINK_BACKUP_ACTIVITY_SYNONYM)] 
  FOR [$(LINK_SERVER)].[$(LINK_EHDB)].[$(EHA_SCHEMA)].[$(BACKUP_ACTIVITY_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(LINK_CONTAINERS_SYNONYM)] 
  FOR [$(LINK_SERVER)].[$(LINK_EHDB)].[$(EHA_SCHEMA)].[$(CONTAINERS_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(LINK_CONTAINER_ACTIVITY_SYNONYM)] 
  FOR [$(LINK_SERVER)].[$(LINK_EHDB)].[$(EHA_SCHEMA)].[$(CONTAINER_ACTIVITY_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(LINK_NAMEVALUES_SYNONYM)] 
  FOR [$(LINK_SERVER)].[$(LINK_EHDB)].[$(EHA_SCHEMA)].[$(NAMEVALUES_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(LINK_NAMEVALUE_ACTIVITY_SYNONYM)] 
  FOR [$(LINK_SERVER)].[$(LINK_EHDB)].[$(EHA_SCHEMA)].[$(NAMEVALUE_ACTIVITY_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(LINK_NOTIFICATION_ACTIVITY_SYNONYM)] 
  FOR [$(LINK_SERVER)].[$(LINK_EHDB)].[$(EHA_SCHEMA)].[$(NOTIFICATION_ACTIVITY_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(LINK_OFFSITE_ACTIVITY_SYNONYM)] 
  FOR [$(LINK_SERVER)].[$(LINK_EHDB)].[$(EHA_SCHEMA)].[$(OFFSITE_ACTIVITY_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(LINK_REPORT_ACTIVITY_SYNONYM)] 
  FOR [$(LINK_SERVER)].[$(LINK_EHDB)].[$(EHA_SCHEMA)].[$(REPORT_ACTIVITY_TABLE)]
GO
IF PATINDEX('%[Developer,Enterprise]%', CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128) ) ) > 0 
  BEGIN
    IF ( SELECT is_cdc_enabled FROM sys.databases
         WHERE name = DB_NAME() ) = 0  
      EXEC sys.sp_cdc_enable_db;
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(BOOKINGS_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(BOOKINGS_TABLE)' 
                                 , @role_name = '$(EHADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(BACKUP_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(BACKUP_ACTIVITY_TABLE)' 
                                 , @role_name = '$(EHADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(CONTAINERS_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(CONTAINERS_TABLE)' 
                                 , @role_name = '$(EHADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(CONTAINER_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(CONTAINER_ACTIVITY_TABLE)' 
                                 , @role_name = '$(EHADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(NAMEVALUES_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(NAMEVALUES_TABLE)' 
                                 , @role_name = '$(EHADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(NAMEVALUE_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(NAMEVALUE_ACTIVITY_TABLE)' 
                                 , @role_name = '$(EHADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(NOTIFICATION_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(NOTIFICATION_ACTIVITY_TABLE)' 
                                 , @role_name = '$(EHADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(OFFSITE_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(OFFSITE_ACTIVITY_TABLE)' 
                                 , @role_name = '$(EHADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(REPORT_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(REPORT_ACTIVITY_TABLE)' 
                                 , @role_name = '$(EHADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
  END
ELSE -- change tracking 
  BEGIN
    ALTER DATABASE $(EHDB)
    SET CHANGE_TRACKING = ON
    (AUTO_CLEANUP = OFF);
    ALTER TABLE $(EHA_SCHEMA).$(BOOKINGS_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = ON);
    ALTER TABLE $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = ON);
    ALTER TABLE $(EHA_SCHEMA).$(CONTAINERS_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = ON);
    ALTER TABLE $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = ON);
    ALTER TABLE $(EHA_SCHEMA).$(NAMEVALUES_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = ON);
    ALTER TABLE $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = ON);
    ALTER TABLE $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = ON);
    ALTER TABLE $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = ON);
    ALTER TABLE $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = ON);
  END 
GO
--salt name
EXEC sp_addmessage $(MESSAGE_OFFSET)01, 1, '%s.%s.%s.%s.Salt', 'us_english','FALSE' ,'replace' -- $(EHA_SCHEMA).AddSalt
-- error EVENTDATA
EXEC sp_addmessage $(MESSAGE_OFFSET)02, 1, 'Error: %d, %d, %d Obj: %s, line: %d, msg: %s', 'us_english','FALSE' ,'replace' -- $(EHA_SCHEMA).AddSalt
-- completion messages
EXEC sp_addmessage $(MESSAGE_OFFSET)10, 1, '%s has been saved.(v.%d) The private passphrase is never saved.', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)11, 1, '%s %s %s %s %s complete.', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)12, 16, '%s %s %s %s %s failed with return_code %d.', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)13, 16, '%s %s %s %s %s failed with reason %s.', 'us_english','FALSE' ,'replace'
-- T-SQL 
EXEC sp_addmessage $(MESSAGE_OFFSET)20, 1, 'OPEN MASTER KEY DECRYPTION BY PASSWORD = ''%s'';', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)21, 1, '$(EHA_SCHEMA).AddSalt( ''%s'', ''%s'', ''%s'', ''%s'', %s )', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)22, 1, 'SELECT @CipherType = key_algorithm, @Colophon = %s FROM %s.sys.symmetric_keys WHERE name = ''%s'';', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)23, 1, 'SELECT @CipherType = pvt_key_encryption_type, @Colophon = %s FROM %s.sys.certificates WHERE name = ''%s'';', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)25, 1, 'USE master; BACKUP SERVICE MASTER KEY TO FILE = ''%s%s%s'' ENCRYPTION BY PASSWORD = ''%s''', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)26, 1, 'USE %s;%sBACKUP MASTER KEY TO FILE = ''%s%s%s'' ENCRYPTION BY PASSWORD = ''%s'';%s', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)27, 1, 'USE %s;%sBACKUP CERTIFICATE %s TO FILE = ''%s%s%s'' %s;%s', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)28, 1, 'WITH PRIVATE KEY ( FILE = ''%s%s%s'', ENCRYPTION BY PASSWORD = ''%s'' %s )', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)29, 1, ', DECRYPTION BY PASSWORD = ''%s''', 'us_english','FALSE' ,'replace'
-- authentication and authorization problems 
EXEC sp_addmessage $(MESSAGE_OFFSET)30, 16, 'Object or Signature missing.', 'us_english', 'FALSE', 'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)31, 16, 'Active transaction detected.', 'us_english', 'FALSE', 'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)32, 16, 'Active data relay detected.', 'us_english', 'FALSE', 'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)33, 16, 'Booking failure - reason: %s', 'us_english', 'TRUE', 'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)34, 16, 'Authentication failure - ProcId: %d, BookingId: = [%s]', 'us_english', 'FALSE', 'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)35, 16, 'Invalid "%s" reason: %s', 'us_english', 'FALSE', 'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)36, 16, 'Authorization failure DbName: $(EHDB) Schema:$(EHA_SCHEMA): User %s  Action:%s', 'us_english', 'TRUE' , 'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)37, 16, 'ANSI_PADDING must be ON for SQL Server encryption.', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)38, 16, 'Request for duplicate encryption hierarchy node Backup must use @ForceNew = 1 (%s %s)', 'us_english','FALSE' ,'replace'
GO
-- DEK encrypted by cert in master db shares no dependency with the phrase encrypted DMK    
IF PATINDEX('%[Developer,Enterprise]%', CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128) ) ) > 0
  BEGIN
    DECLARE @TDEDDL NVARCHAR(1024);
    SET @TDEDDL = 'IF NOT EXISTS ( SELECT *' + SPACE(1) 
                +                 'FROM sys.dm_database_encryption_keys' + SPACE(1) 
                +                 'WHERE database_id = DB_ID()' + SPACE(1)
                +                 'AND DB_NAME() = ''$(EHDB)'' )' + SPACE(1) 
                +   'BEGIN' + SPACE(1) 
                +     'CREATE DATABASE ENCRYPTION KEY' + SPACE(1)
                +     'WITH ALGORITHM = $(TDE_CERTIFICATE_ALGORITHM)' + SPACE(1)
                +     'ENCRYPTION BY SERVER CERTIFICATE $(TDE_CERTIFICATE);' + SPACE(1)
                +     'ALTER DATABASE $(EHDB)' + SPACE(1)
                +     'SET ENCRYPTION ON;'
                +   'END' + SPACE(1)
    EXEC sp_executesql @TDEDDL;
  END
GO
IF OBJECT_ID ('$(EHA_SCHEMA).OpenSession') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).OpenSession
GO
-------------------------------------------------------------------------------
-- bwunder at yahoo dot com
-- Desc: isolation of session key phrase 
-- used to encrypt variables in flight - the GUID is @Parameter @authenticator 
-- so is stored on BOOKINGS_TABLE should audit record need to be viewed later
-- The $(WITH OPTIONS) must include ENCRYPTION in the live environment and the 
-- live environment's phrase must not be used in any other SDLC environments. 
-- All procs in the Book procedure's whitelist call this procedure.  
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).OpenSession
$(WITH_OPTIONS)
AS
BEGIN
  BEGIN TRY
    IF (SELECT IIF ( COUNT(s.entity_id) = $(OBJECT_COUNT) - $(TABLE_COUNT), 1, 0 ) 
        FROM sys.certificates c
        CROSS APPLY sys.fn_check_object_signatures ( 'certificate'
	    	                                          , c.thumbprint) s
        WHERE c.name = '$(OBJECT_CERTIFICATE)'
        AND c.pvt_key_encryption_type = 'PW'
        AND OBJECT_SCHEMA_NAME (s.entity_id) = '$(EHA_SCHEMA)'
        AND s.is_signed = 1 
        AND s.is_signature_valid = 1
        AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'CERTIFICATE', c.thumbprint) = 1
        AND EXISTS ( SELECT * FROM sys.database_role_members 
                      WHERE [role_principal_id] = USER_ID('$(EHADMIN_ROLE)')
                      AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                      AND SYSTEM_USER = ORIGINAL_LOGIN() ) ) = 1
      BEGIN
        -- valid schema+user always gets an open audit key for booking
        OPEN SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)]
        DECRYPTION BY CERTIFICATE [$(AUDIT_CERTIFICATE)]
        WITH PASSWORD = '$(AUDIT_CERTIFICATE_ENCRYPTION_PHRASE)';

        -- start session only if proc called from command line
        IF KEY_GUID('$(SESSION_SYMMETRIC_KEY)') IS NULL
        AND @@NESTLEVEL = 1        
          CREATE SYMMETRIC KEY $(SESSION_SYMMETRIC_KEY)
          WITH ALGORITHM = AES_256
              , KEY_SOURCE = 'Encryption Hierarchy Adminstration'
              -- let sql gen IDENTITY_VALUE else will try to serialize sessions on name
          ENCRYPTION BY PASSWORD = '$(SESSION_KEY_ENCRYPTION_PHRASE)';

        -- no failure message now, just don't open key if does not exist  
        IF KEY_GUID('$(SESSION_SYMMETRIC_KEY)') IS NOT NULL
          OPEN SYMMETRIC KEY $(SESSION_SYMMETRIC_KEY)
          DECRYPTION BY PASSWORD = '$(SESSION_KEY_ENCRYPTION_PHRASE)';
      END
  END TRY
  BEGIN CATCH  
    IF PATINDEX ( '%ENCRYPTION%', '$(WITH_OPTIONS)') = 0
        THROW;
    ELSE
      RAISERROR( 'unable to begin...', 20, 1 ) WITH LOG;
  END CATCH    
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).OpenSession 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).Book') IS NOT NULL
  DROP PROCEDURE $(EHA_SCHEMA).Book
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: authentication gauntlet    
--    ASSERT: the caller has opened the Database Master Key  
--    by rule the 0 row colophon is a checksum of sys.messages after install
--    add configuration filtering as appropriate. Be precise.
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).Book 
  ( @ProcId INT 
  , @Parameters VARBINARY(8000)
  , @Id NCHAR(36) OUTPUT
  , @MAC VARBINARY(128) OUTPUT )
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @Thumbprint VARBINARY(32)
      , @Reason NVARCHAR(30)
      , @ErrorData VARBINARY(8000);
DECLARE @output TABLE (Id NCHAR(36), CkSum NVARCHAR(128) );
  BEGIN TRY
    SET @Reason = 'objects';
    SET @Thumbprint = ( SELECT thumbprint
                        FROM sys.certificates 
                        WHERE name = '$(OBJECT_CERTIFICATE)' )
    -- a different angle than OpenSession
    IF (SELECT IS_OBJECTSIGNED( 'OBJECT', @@PROCID, 'CERTIFICATE', @Thumbprint )                                        
        FROM sys.objects o
        OUTER APPLY sys.fn_check_object_signatures ('CERTIFICATE', @Thumbprint) s
        WHERE o.object_id = s.entity_id
        AND o.schema_id = SCHEMA_ID( '$(EHA_SCHEMA)' ) 
        AND (o.parent_object_id = 0 OR o.type = 'TR')       
        HAVING COUNT(*) = $(OBJECT_COUNT)
        AND SUM ( ISNULL( s.is_signature_valid, 0 ) ) = $(OBJECT_COUNT) - $(TABLE_COUNT)  
        AND SUM ( IIF( o.type = 'SN', 1, 0 ) ) = $(TABLE_COUNT)
        AND SUM ( IIF( o.type = 'TR', 1, 0 ) ) = $(TABLE_COUNT) - 1 ) <> 1
      RAISERROR($(MESSAGE_OFFSET)30,16,1);
    SET @Reason = 'messages';
    -- text of any of our sys.messages is changed from the same value computed at install 
    -- in and stored in the colophon of the 0 row or the 0 row does not exist
    IF ( SELECT CHECKSUM_AGG( BINARY_CHECKSUM(text) )  
          FROM sys.messages
          WHERE message_id between $(MESSAGE_OFFSET)00 AND $(MESSAGE_OFFSET)50 ) 
         <>
        ( SELECT Colophon
          FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)  
          WHERE Id = '00000000-0000-0000-0000-000000000000' ) 
      RAISERROR($(MESSAGE_OFFSET)30,16,1);
    SET @Reason = 'probe';
    IF XACT_STATE() <> 0
      RAISERROR($(MESSAGE_OFFSET)31,16,1);
    SET @Reason = 'bridge'; -- a check for unexpected data exposures 
    IF EXISTS ( SELECT * 
                FROM sys.event_notifications
                WHERE name <> '$(EVENT_NOTIFICATION)Db' )
    OR EXISTS ( SELECT * 
                FROM sys.server_event_notifications 
                WHERE name NOT IN ( '$(EVENT_NOTIFICATION)Srv', 'SQLClueDDLEventNotification' ) )
    OR EXISTS (SELECT * FROM sys.server_triggers
               WHERE is_ms_shipped = 0) 
    -- all secrets should be obfuscated in any trace events but better safe than sorry
    -- the automagic obfuscation proved inadequate in masking secrets when passed as 
    -- clear text in user defined stored procedure parameters, thus secrets are encrypted 
    -- at the command line and passed only as encrypted parameters. The install script 
    -- produced more than 192,000 trace events with TextData that were scrutinized for 
    -- secret leaks. None were identified. 
    -- Extended Events too are obfuscated automajically, but better safe than sorry
    -- white list valid config but avoid wildcards - BE SPECIFIC
    OR ( SELECT COUNT(*) FROM sys.traces 
         WHERE is_default <> 1 ) > $(ALLOW_TRACE_COUNT)-- should also check for known vulnerable events    
    OR EXISTS (SELECT * FROM sys.dm_xe_sessions
               WHERE name NOT IN ( 'system_health'
                                 , 'sp_server_diagnostics session' 
                                 , 'ehaSchemaAudit$A'
                                 , 'ehaSchemaAudit$B' ) )
    OR EXISTS (SELECT * FROM sys.database_audit_specifications
               WHERE name <> 'ehaSchemaAuditDbSpecs' )
    OR EXISTS (SELECT * FROM sys.server_audits
               WHERE name <> 'ehaSchemaAudit' )
    OR EXISTS (SELECT * FROM msdb.dbo.sysalerts )  
    OR EXISTS (SELECT * FROM sys.assemblies 
               WHERE name NOT IN ( 'Microsoft.SqlServer.Types' ) )          
      RAISERROR($(MESSAGE_OFFSET)32, 16, 1);
    SET @Reason = 'authority';
    -- role membership is not explicitly recognized when everyone is dbo... 
    -- sysadmin is always dbo so dbo will cover both 
    -- assert db principal, server principle and windows user all have same name
    IF NOT EXISTS ( SELECT * FROM sys.database_role_members 
                    WHERE [role_principal_id] = USER_ID('$(EHADMIN_ROLE)')
                    AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                    AND SYSTEM_USER = ORIGINAL_LOGIN() 
                    AND SESSION_USER = 'dbo' )	
    -- why here? cdc never uses Book does it? --AND USER_NAME() <> 'cdc'                  
      RAISERROR($(MESSAGE_OFFSET)35, 16, 1, 'USER', @Reason);
    SET @Reason = 'DMK';
    IF EXISTS (SELECT * FROM sys.master_key_passwords)
    OR EXISTS (SELECT * 
               FROM sys.symmetric_keys sk 
               JOIN sys.key_encryptions ke 
               ON sk.symmetric_key_id = ke.key_id 
               WHERE sk.name = '##MS_DatabaseMasterKey##'
               AND ke.crypt_type <> 'ESKP' )
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'MASTER KEY', @Reason);
    SET @Reason = 'cert'
    IF (SELECT pvt_key_encryption_type 
        FROM sys.certificates
        WHERE name = '$(AUDIT_CERTIFICATE)') <> 'PW'
    OR (SELECT pvt_key_encryption_type 
        FROM sys.certificates
        WHERE name = '$(AUTHENTICITY_CERTIFICATE)') <> 'MK'
    OR (SELECT pvt_key_encryption_type 
        FROM sys.certificates
        WHERE name = '$(FILE_CERTIFICATE)') <> 'MK'
    OR (SELECT pvt_key_encryption_type 
        FROM sys.certificates
        WHERE name = '$(NAME_CERTIFICATE)') <> 'MK'
    OR (SELECT pvt_key_encryption_type 
        FROM sys.certificates
        WHERE name = '$(VALUE_CERTIFICATE)') <> 'MK'
    OR NOT EXISTS (SELECT * 
                   FROM sys.symmetric_keys sk 
                   JOIN sys.key_encryptions ke 
                   ON sk.symmetric_key_id = ke.key_id 
                   WHERE sk.name = '$(ERROR_SYMMETRIC_KEY)'
                   AND ke.crypt_type = 'ESKP' ) -- Encryption by Password
       RAISERROR($(MESSAGE_OFFSET)35,16,1,'cert', @Reason);
    SET @Reason = 'whitelist'; 
    IF ( OBJECT_NAME(@ProcId) NOT IN ( 'AddNameValue'
                                     , 'BackupCertificate' 
                                     , 'BackupContainer' 
                                     , 'BackupDatabaseMasterKey' 
                                     , 'BackupServiceMasterKey' 
                                     , 'CertificateBackupsByThumbprint' 
                                     , 'GetPortableSymmetricKey'
                                     , 'GetPrivateValue'
                                     , 'MakeSalt' 
                                     , 'RecallContainer' 
                                     , 'ReportActivityHistory' 
                                     , 'ReportErrors' 
                                     , 'ReportServerSummary'
                                     , 'RestoreCertificate' 
                                     , 'RestoreContainer' 
                                     , 'RestoreDatabaseMasterKey' 
                                     , 'RestoreServiceMasterKey' 
                                     , 'SavePortableSymmetricKey'
                                     , 'SavePrivateValue'
                                     , 'SendOffsiteCDC' 
                                     , 'SendOffsiteTC' 
                                     , 'SelectNameValue' 
                                     , 'ValidateNameValue' 
                                     , '$(EVENT_NOTIFICATION)Activation'
                                     , 'trg_$(BOOKINGS_TABLE)'
                                     , 'trg_$(CONTAINERS_TABLE)'
                                     , 'trg_$(CONTAINER_ACTIVITY_TABLE)'
                                     , 'trg_$(NAMEVALUES_TABLE)'
                                     , 'trg_$(NAMEVALUE_ACTIVITY_TABLE)'
                                     , 'trg_$(BACKUP_ACTIVITY_TABLE)'
                                     , 'trg_$(NOTIFICATION_ACTIVITY_TABLE)'
                                     , 'trg_$(OFFSITE_ACTIVITY_TABLE)'
                                     , 'trg_$(REPORT_ACTIVITY_TABLE)' ) )
    OR OBJECT_SCHEMA_NAME(@ProcId) <> '$(EHA_SCHEMA)'           
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'@ProcId', @Reason);    
    SET @Reason = 'config';
    IF SESSIONPROPERTY('ANSI_PADDING') <> 1
    OR EXISTS ( SELECT * FROM sys.databases
                WHERE database_id = DB_ID()
                AND (  is_trustworthy_on = 1
                    OR is_db_chaining_on = 1
                    OR is_ansi_padding_on = 1) )                   
          RAISERROR($(MESSAGE_OFFSET)37,16,1);
    SET @Reason = 'insert';
    BEGIN TRANSACTION
      INSERT INTO $(EHA_SCHEMA).$(BOOKINGS_TABLE) WITH(TABLOCK, HOLDLOCK)
        ( ProcId
        , ObjectName
        , Parameters
        , KeyGuid
        , Status )
      OUTPUT INSERTED.Id
           , CHECKSUM ( INSERTED.Id
                      , INSERTED.ProcId
                      , INSERTED.ObjectName
                      , INSERTED.Parameters
                      , INSERTED.KeyGuid
                      , INSERTED.Status ) INTO @output
      SELECT @ProcId   
           , OBJECT_NAME(@ProcId)
           , @Parameters
           , CAST( KEY_GUID( '$(SESSION_SYMMETRIC_KEY)' ) AS NCHAR(36) )
           , 'OK';
      SET @Reason = 'keys';
      -- First need for DMK - use DMK encrypted authenticity certificate to make the MAC 
      -- it remains open until the first of the @MAC is saved by caller or the session ends
      IF NOT EXISTS ( SELECT * FROM sys.openkeys
                      WHERE key_name = '##MS_DatabaseMasterKey##'
                      AND database_name = DB_NAME() )
        OPEN MASTER KEY DECRYPTION BY PASSWORD = '$(EHDB_DMK_ENCRYPTION_PHRASE)';
      -- open data column keys
      IF NOT EXISTS ( SELECT * FROM sys.openkeys
                      WHERE key_name = '$(FILE_SYMMETRIC_KEY)'
                      AND database_name = DB_NAME() )
        OPEN SYMMETRIC KEY [$(FILE_SYMMETRIC_KEY)]
        DECRYPTION BY CERTIFICATE [$(FILE_CERTIFICATE)];
      IF NOT EXISTS (SELECT * FROM sys.openkeys
                     WHERE key_name = '$(NAME_SYMMETRIC_KEY)')
        OPEN SYMMETRIC KEY [$(NAME_SYMMETRIC_KEY)]
        DECRYPTION BY CERTIFICATE [$(NAME_CERTIFICATE)];
      IF NOT EXISTS (SELECT * FROM sys.openkeys
                     WHERE key_name = '$(VALUE_SYMMETRIC_KEY)')
        OPEN SYMMETRIC KEY [$(VALUE_SYMMETRIC_KEY)]
        DECRYPTION BY CERTIFICATE [$(VALUE_CERTIFICATE)];
      SET @Reason = 'sign';
    COMMIT TRANSACTION;      
    SELECT @Id = Id 
          , @MAC =  SignByCert ( CERT_ID( '$(AUTHENTICITY_CERTIFICATE)' ), CkSum )
    FROM @output; 
  END TRY
  BEGIN CATCH
    IF ERROR_NUMBER() <> $(MESSAGE_OFFSET)31
    AND XACT_STATE() <> 0
      ROLLBACK TRANSACTION;
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    -- handle insert or signing excptns without a dup key ( an incomplete booking )
    INSERT INTO $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
      ( ProcId
      , ObjectName
      , Parameters
      , KeyGuid
      , Status
      , ErrorData )
    SELECT @ProcId
         , OBJECT_NAME(@ProcId)
         , @Parameters
         , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
         , ISNULL(@Reason,'Error') 
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                              , ERROR_NUMBER()
                              , ERROR_SEVERITY()
                              , ERROR_STATE()
                              , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                              , ERROR_LINE()
                              , ERROR_MESSAGE() ) AS ErrorInfo ) as derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).Book 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).$(EVENT_NOTIFICATION)Activation') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).$(EVENT_NOTIFICATION)Activation
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: process notifications from eha queue
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).$(EVENT_NOTIFICATION)Activation 
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @ConversationHandle UNIQUEIDENTIFIER
      , @ConversationGroupId UNIQUEIDENTIFIER
      , @ConversationGroup NVARCHAR(50)
      , @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128)
      , @MessageBody VARBINARY(MAX)
      , @MessageTypeName NVARCHAR(128)
      , @Parameters VARBINARY(8000)
      , @ReturnCode INT
      , @ServiceName NVARCHAR(128)
      , @tvp NAMEVALUETYPE
      , @Version INT ; -- AddNameValue output parameter
SET NOCOUNT ON;
  BEGIN TRY
    EXEC $(EHA_SCHEMA).OpenSession;
 	  SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , N''
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
      WAITFOR ( GET CONVERSATION GROUP @ConversationGroupId 
                FROM $(EHA_SCHEMA).$(EVENT_NOTIFICATION)Queue )
          , TIMEOUT 6000; -- a minute - the session keys are open for this
      IF @ConversationGroupId IS NOT NULL
        BEGIN
          RECEIVE TOP(1)
              @ConversationHandle = [conversation_handle]
            , @ServiceName = [service_name]
            , @MessageTypeName = [message_type_name]
            , @MessageBody = [message_body]
          FROM $(EHA_SCHEMA).$(EVENT_NOTIFICATION)Queue
          WHERE conversation_group_id = @ConversationGroupId;
          IF @@ROWCOUNT = 1 
            BEGIN  
              -- only want to work with Events
              IF @MessageTypeName = 'http://schemas.microsoft.com/SQL/Notifications/EventNotification'
              AND @ServiceName = '$(EVENT_NOTIFICATION)Service'
                BEGIN
                  -- DISABLE DDL TRIGGER gets the special treatment (ENABLE is benign if already enabled)
                  IF ( CAST( @MessageBody AS XML ).value('(/EVENT_INSTANCE/EventType)[1]','NVARCHAR(128)') = 'AUDIT_DATABASE_OBJECT_MANAGEMENT_EVENT')           
                    ENABLE TRIGGER ALL ON DATABASE;
                  INSERT  $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)
                    ( Id
                    , ConversationGroupId 
                    , ConversationHandle
                    , Message
                    , Signature
                    , MAC
                    , Action
                    , Status )
                  VALUES ( @Id
                         , @ConversationGroupId 
                         , @ConversationHandle
                         , @MessageBody
                         , SIGNBYCERT( KEY_ID( '$(EVENT_CERTIFICATE)' )
                                     , @MessageBody )
                         , @MAC
                         , OBJECT_NAME(@@PROCID)
                         , 'Complete' );
                END
              ELSE
                IF @ServiceName = '$(EVENT_NOTIFICATION)Service'  
                  RAISERROR('Invalid message type "%s" found in the [$(EHA_SCHEMA).$(EVENT_NOTIFICATION)Queue]',16,1,@MessageTypeName);
                ELSE
                  RAISERROR('Invalid use of [$(EHA_SCHEMA).$(EVENT_NOTIFICATION)Queue] by service "%s"',16,1,@ServiceName);
            END -- there is a dialog item to process
        END -- conversation group exists
      CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @@TRANCOUNT > 0
      ROLLBACK TRANSACTION
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT  $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)
      ( Id
      , ConversationGroupId 
      , ConversationHandle
      , Message
      , Signature
      , MAC
      , Action
      , Status 
      , ErrorData)
    SELECT @Id
         , ISNULL( @ConversationGroupId, 0x0 ) 
         , ISNULL( @ConversationHandle, 0x0 )
         , ISNULL( @MessageBody, 0x0 )
         , ISNULL( SIGNBYCERT( KEY_ID( '$(EVENT_CERTIFICATE)' )
                             , CAST( @MessageBody AS XML ).value ( '(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]','nvarchar(max)' ) )
                  , 0x0 )     
         , ISNULL( @MAC, 0x0 )
         , OBJECT_NAME( @@PROCID )
         , 'Complete'
         , ENCRYPTBYKEY( KEY_GUID( '$(ERROR_SYMMETRIC_KEY)' )
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                              , ERROR_NUMBER()
                              , ERROR_SEVERITY()
                              , ERROR_STATE()
                              , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                              , ERROR_LINE()
                              , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).$(EVENT_NOTIFICATION)Activation 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
------------------------------------------------------
-- Fire up an Event Notification Changes Queue 
------------------------------------------------------ 
IF NOT EXISTS ( SELECT * FROM sys.service_queues 
                WHERE name = '$(EVENT_NOTIFICATION)Queue'
                AND schema_id = SCHEMA_ID( '$(EHA_SCHEMA)' ) ) 
  CREATE QUEUE $(EHA_SCHEMA).$(EVENT_NOTIFICATION)Queue 
  WITH RETENTION = ON
     , ACTIVATION ( STATUS = ON
                  , PROCEDURE_NAME = $(EHA_SCHEMA).$(EVENT_NOTIFICATION)Activation
                  , MAX_QUEUE_READERS = 1
                  , EXECUTE AS SELF ) ;
GO
-- role canniot own a service so this one is left for dbo
IF NOT EXISTS ( SELECT * FROM sys.services 
                WHERE name = '$(EVENT_NOTIFICATION)Service' )
  CREATE SERVICE $(EVENT_NOTIFICATION)Service
  ON QUEUE $(EHA_SCHEMA).$(EVENT_NOTIFICATION)Queue 
    ( [http://schemas.microsoft.com/SQL/Notifications/PostEventNotification] );
GO
IF NOT EXISTS (SELECT * FROM sys.routes WHERE Address = 'LOCAL')
  CREATE ROUTE $(EVENT_NOTIFICATION)Route
  AUTHORIZATION $(EHADMIN_ROLE) 
  WITH SERVICE_NAME = '$(EVENT_NOTIFICATION)Service'
     , ADDRESS = 'LOCAL';
GO
IF NOT EXISTS (SELECT * FROM sys.event_notifications WHERE name = '$(EVENT_NOTIFICATION)Db')
  CREATE EVENT NOTIFICATION $(EVENT_NOTIFICATION)Db 
  ON DATABASE 
  FOR DDL_DATABASE_LEVEL_EVENTS 
  TO SERVICE '$(EVENT_NOTIFICATION)Service', 'current database' ;
GO
IF NOT EXISTS (SELECT * FROM sys.server_event_notifications WHERE name = '$(EVENT_NOTIFICATION)Srv')
  CREATE EVENT NOTIFICATION $(EVENT_NOTIFICATION)Srv 
  ON SERVER 
  FOR AUDIT_DATABASE_OBJECT_MANAGEMENT_EVENT 
  TO SERVICE '$(EVENT_NOTIFICATION)Service', 'current database' ;
GO
----------
-- Audit
----------
USE master ;
GO
-- Create the server audit at the location of the TrueCrypt container
IF NOT EXISTS (SELECT * FROM sys.server_audits 
                WHERE name = '$(EHA_SCHEMA)SchemaAudit' ) 
  CREATE SERVER AUDIT $(EHA_SCHEMA)SchemaAudit
      TO FILE ( FILEPATH = '$(KEY_CONTAINER_PATH)' ) ;
GO
ALTER SERVER AUDIT $(EHA_SCHEMA)SchemaAudit 
WITH (STATE = ON) ;
GO
USE $(EHDB);
GO
IF NOT EXISTS (SELECT * FROM sys.database_audit_specifications 
                WHERE name = '$(EHA_SCHEMA)SchemaAuditDbSpecs' ) 
  CREATE DATABASE AUDIT SPECIFICATION $(EHA_SCHEMA)SchemaAuditDbSpecs
  FOR SERVER AUDIT $(EHA_SCHEMA)SchemaAudit
  ADD ( DATABASE_OBJECT_CHANGE_GROUP )
  WITH (STATE = ON);
GO
------------------
-- DML Triggers
------------------
-- Instead trigger is added to each tables to log and deny all updates and deletes 
-- the triggers using the booking system (call Book) 
IF OBJECT_ID('$(EHA_SCHEMA).trg_$(BOOKINGS_TABLE)') IS NOT NULL
  DROP TRIGGER $(EHA_SCHEMA).trg_$(BOOKINGS_TABLE)
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: make note of all update and delete attempts 
--  ASSERT: the caller has opened the Database Master Key  
-------------------------------------------------------------------------------
CREATE TRIGGER $(EHA_SCHEMA).trg_$(BOOKINGS_TABLE) 
ON  $(EHA_SCHEMA).$(BOOKINGS_TABLE)
$(WITH_OPTIONS)
INSTEAD OF UPDATE, DELETE
AS 
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST( CHECKSUM( Id
                                                          , @@PROCID   
                                                          , ObjectName
                                                          , 0x0 -- @Parameters
                                                          , KeyGuid
                                                          , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT INTO $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
      ( Id
      , ProcId
      , ObjectName
      , Parameters
      , Status )
    SELECT @Id
           , d.ProcId   
           , OBJECT_NAME(d.ProcId)
           , d.Parameters
           , 'Instead' + SPACE(1) 
           + CASE WHEN i.Id IS NULL 
                  THEN 'DELETE' 
                  ELSE 'UPDATE' END
    FROM deleted d
    LEFT JOIN inserted i
    ON d.Id = i.Id;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT INTO $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
      ( ProcId
      , ObjectName
      , Parameters
      , Status 
      , ErrorData)
    SELECT ISNULL(d.ProcId,0)   
         , ISNULL(OBJECT_NAME(d.ProcId),'')
         , ISNULL(CAST(d.Id AS VARBINARY(8000)),0x0)
         , 'Error'    
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM deleted d
    OUTER APPLY (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                     , ERROR_NUMBER()
                                     , ERROR_SEVERITY()
                                     , ERROR_STATE()
                                     , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                     , ERROR_LINE()
                                     , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).trg_$(BOOKINGS_TABLE) 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID('$(EHA_SCHEMA).trg_$(BACKUP_ACTIVITY_TABLE)') IS NOT NULL
 DROP TRIGGER $(EHA_SCHEMA).trg_$(BACKUP_ACTIVITY_TABLE)
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: make note of all update and delete attempts 
-------------------------------------------------------------------------------
CREATE TRIGGER $(EHA_SCHEMA).trg_$(BACKUP_ACTIVITY_TABLE) 
ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
$(WITH_OPTIONS)
INSTEAD OF UPDATE, DELETE
AS 
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST( CHECKSUM( Id
                                                          , @@PROCID   
                                                          , ObjectName
                                                          , 0x0 -- @Parameters
                                                          , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
      ( Id
      , DbName
      , Node
      , NodeName
      , BackupName
      , BackupNameBucket
      , UseHash
      , BackupPath
      , BackupPhraseVersion
      , KeyPhraseVersion
      , Colophon
      , Edition
      , MAC
      , Action
      , Status
      , CipherType )
    SELECT @Id
         , ISNULL( i.DbName, d.DbName )
         , ISNULL( i.Node, d.Node )
         , ISNULL( i.NodeName, d.NodeName )
         , ISNULL( i.BackupName, d.BackupName )
         , ISNULL( i.BackupNameBucket, d.BackupNameBucket )              
         , ISNULL( i.UseHash, d.UseHash )
         , ISNULL( i.BackupPath, d.BackupPath ) 
         , ISNULL( i.BackupPhraseVersion, d.BackupPhraseVersion )
         , ISNULL( i.KeyPhraseVersion, d.KeyPhraseVersion )
         , ISNULL( i.Colophon, d.Colophon )
         , ISNULL( i.Edition, d.Edition )
         , @MAC
         , 'Instead' + SPACE(10) + CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
         , 'Complete'
         , ISNULL(i.CipherType, d.CipherType) 
    FROM deleted d
    LEFT JOIN inserted i
    ON d.Id = i.Id
  END TRY 
  BEGIN CATCH
    WHILE @@TRANCOUNT > 0 
      ROLLBACK TRANSACTION; 
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
      ( Id
      , DbName
      , Node
      , NodeName
      , BackupName
      , BackupNameBucket
      , UseHash
      , BackupPath
      , BackupPhraseVersion
      , KeyPhraseVersion
      , Colophon
      , Edition
      , MAC
      , Action
      , Status
      , CipherType 
      , ErrorData )
    SELECT @Id
         , d.DbName
         , d.Node
         , d.NodeName
         , d.BackupName
         , d.BackupNameBucket              
         , d.UseHash
         , d.BackupPath
         , d.BackupPhraseVersion
         , d.KeyPhraseVersion
         , d.Colophon 
         , d.Edition
         , ISNULL( @MAC, 0x0 )
         , 'Instead' + SPACE(10) + CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
         , 'Error'
         , d.CipherType 
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM deleted d
    LEFT JOIN inserted i
    on d.Id = i.Id
    OUTER APPLY (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                     , ERROR_NUMBER()
                                     , ERROR_SEVERITY()
                                     , ERROR_STATE()
                                     , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                     , ERROR_LINE()
                                     , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).trg_$(BACKUP_ACTIVITY_TABLE) 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID('$(EHA_SCHEMA).trg_$(CONTAINERS_TABLE)') IS NOT NULL
  DROP TRIGGER $(EHA_SCHEMA).trg_$(CONTAINERS_TABLE)
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: reject but make note of all update and delete attempts 
--    ASSERT: DMK is open  
-------------------------------------------------------------------------------
CREATE TRIGGER $(EHA_SCHEMA).trg_$(CONTAINERS_TABLE) 
ON  $(EHA_SCHEMA).$(CONTAINERS_TABLE)
$(WITH_OPTIONS)
INSTEAD OF UPDATE, DELETE
AS 
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST( CHECKSUM( Id
                                                          , @@PROCID   
                                                          , ObjectName
                                                          , 0x0 -- @Parameters
                                                          , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE) 
      ( Id
      , FileName
      , FilePath
      , MAC
      , Action
      , Status )
    SELECT @Id
         , 0x0
         , 0x0 
         , @MAC
         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END + SPACE(1) 
           + '$(CONTAINERS_TABLE)' + SPACE(1) + CAST(d.Id AS NCHAR(36))
         , 'Instead'  
    FROM deleted d
    JOIN inserted i
    on d.Id = i.Id;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE) 
      ( Id
      , FileName
      , FilePath
      , MAC
      , Action
      , Status 
      , ErrorData)
    SELECT @Id 
         , 0x0
         , 0x0
         , ISNULL( @MAC, 0x0 )   
         , OBJECT_NAME( @@PROCID )
         , 'Error'    
         , ENCRYPTBYKEY( KEY_GUID( '$(ERROR_SYMMETRIC_KEY)' )
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM deleted d
    OUTER APPLY (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                     , ERROR_NUMBER()
                                     , ERROR_SEVERITY()
                                     , ERROR_STATE()
                                     , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                     , ERROR_LINE()
                                     , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).trg_$(CONTAINERS_TABLE) 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID('$(EHA_SCHEMA).trg_$(CONTAINER_ACTIVITY_TABLE)') IS NOT NULL
  DROP TRIGGER $(EHA_SCHEMA).trg_$(CONTAINER_ACTIVITY_TABLE)
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: reject but make note of all update and delete attempts 
--    ASSERT: DMK is open  
-------------------------------------------------------------------------------
CREATE TRIGGER $(EHA_SCHEMA).trg_$(CONTAINER_ACTIVITY_TABLE) 
ON  $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE)
$(WITH_OPTIONS)
INSTEAD OF UPDATE, DELETE
AS 
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST( CHECKSUM( Id
                                                          , @@PROCID   
                                                          , ObjectName
                                                          , 0x0 -- @Parameters
                                                          , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE) 
      ( Id
      , FileName
      , FilePath
      , MAC
      , Action
      , Status )
    SELECT @Id
         , d.FileName
         , d.FilePath
         , @MAC
         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END + SPACE(1) 
           + '$(CONTAINER_ACTIVITY_TABLE)' + SPACE(1) + CAST(d.Id AS NCHAR(36))
         , 'Instead'  
    FROM deleted d
    JOIN inserted i
    on d.Id = i.Id;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE) 
      ( Id
      , FileName
      , FilePath
      , MAC
      , Action
      , Status 
      , ErrorData)
    SELECT @Id 
         , ISNULL( d.FileName, 0x0 )
         , ISNULL( d.FilePath, 0x0 )
         , ISNULL( @MAC, 0x0 )   
         , OBJECT_NAME( @@PROCID )
         , 'Error'    
         , ENCRYPTBYKEY( KEY_GUID( '$(ERROR_SYMMETRIC_KEY)' )
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM deleted d
    OUTER APPLY (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                     , ERROR_NUMBER()
                                     , ERROR_SEVERITY()
                                     , ERROR_STATE()
                                     , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                     , ERROR_LINE()
                                     , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).trg_$(CONTAINER_ACTIVITY_TABLE) 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID('$(EHA_SCHEMA).trg_$(NAMEVALUES_TABLE)') IS NOT NULL
  DROP TRIGGER $(EHA_SCHEMA).trg_$(NAMEVALUES_TABLE)
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: reject but make note of all update and delete attempts 
--    ASSERT: DMK is open  
-------------------------------------------------------------------------------
CREATE TRIGGER $(EHA_SCHEMA).trg_$(NAMEVALUES_TABLE) 
ON  $(EHA_SCHEMA).$(NAMEVALUES_TABLE)
$(WITH_OPTIONS)
INSTEAD OF UPDATE, DELETE
AS 
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST( CHECKSUM( Id
                                                          , @@PROCID   
                                                          , ObjectName
                                                          , 0x0 -- @Parameters
                                                          , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    SELECT @Id
         , @MAC
         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END + SPACE(1) 
           + '$(NAMEVALUES_TABLE)' + SPACE(1) + CAST(d.Id AS NCHAR(36))
         , 'Instead'  
    FROM deleted d
    JOIN inserted i
    on d.Id = i.Id;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status 
      , ErrorData)
    SELECT @Id 
         , ISNULL( @MAC, 0x0 )   
         , OBJECT_NAME(@@PROCID)
         , 'Error'    
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM deleted d
    OUTER APPLY (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                     , ERROR_NUMBER()
                                     , ERROR_SEVERITY()
                                     , ERROR_STATE()
                                     , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                     , ERROR_LINE()
                                     , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).trg_$(NAMEVALUES_TABLE) 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID('$(EHA_SCHEMA).trg_$(NAMEVALUE_ACTIVITY_TABLE)') IS NOT NULL
 DROP TRIGGER $(EHA_SCHEMA).trg_$(NAMEVALUE_ACTIVITY_TABLE)
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: make note of all update and delete attempts 
--    ASSERT: the caller has opened the Database Master Key  
-------------------------------------------------------------------------------
CREATE TRIGGER $(EHA_SCHEMA).trg_$(NAMEVALUE_ACTIVITY_TABLE) 
ON $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)
$(WITH_OPTIONS)
INSTEAD OF UPDATE, DELETE
AS 
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST( CHECKSUM( Id
                                                          , @@PROCID   
                                                          , ObjectName
                                                          , 0x0 -- @Parameters
                                                          , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    SELECT @Id
         ,@MAC
         , 'Instead' + SPACE(1) + CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END 
         , 'Complete'  
    FROM deleted d
    LEFT JOIN inserted i
    on d.Id = i.Id;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status 
      , ErrorData)
    SELECT @Id
         , ISNULL( @MAC, 0x0 ) 
         , 'Instead' + SPACE(1) + CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END 
         , 'Error'    
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM deleted d
    LEFT JOIN inserted i
    on d.Id = i.Id  
    OUTER APPLY (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                     , ERROR_NUMBER()
                                     , ERROR_SEVERITY()
                                     , ERROR_STATE()
                                     , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                     , ERROR_LINE()
                                     , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).trg_$(NAMEVALUE_ACTIVITY_TABLE) 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID('$(EHA_SCHEMA).trg_$(REPORT_ACTIVITY_TABLE)') IS NOT NULL
 DROP TRIGGER $(EHA_SCHEMA).trg_$(REPORT_ACTIVITY_TABLE)
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: make note of all update and delete attempts 
--    ASSERT: the caller has opened the Database Master Key  
-------------------------------------------------------------------------------
CREATE TRIGGER $(EHA_SCHEMA).trg_$(REPORT_ACTIVITY_TABLE) 
ON $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)
$(WITH_OPTIONS)
INSTEAD OF UPDATE, DELETE
AS 
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST( CHECKSUM( Id
                                                          , @@PROCID   
                                                          , ObjectName
                                                          , 0x0 -- @Parameters
                                                          , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
      ( Id
      , ReportProcedure
      , MAC
      , Status)
    SELECT @Id
         , d.ReportProcedure
         , @MAC
         , 'Instead' + SPACE(1) + CASE WHEN i.Id IS NULL 
                                       THEN 'DELETE' 
                                       ELSE 'UPDATE' 
                                       END
    FROM deleted d
    LEFT JOIN inserted i
    on d.Id = i.Id;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
      ( Id
      , ReportProcedure
      , MAC
      , Status 
      , ErrorData)
    SELECT @Id 
         , d.ReportProcedure
         , ISNULL( @MAC, 0x0 )    
         , 'Error'
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM deleted d
    LEFT JOIN inserted i
    on d.Id = i.Id
    OUTER APPLY (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                     , ERROR_NUMBER()
                                     , ERROR_SEVERITY()
                                     , ERROR_STATE()
                                     , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                     , ERROR_LINE()
                                     , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).trg_$(REPORT_ACTIVITY_TABLE) 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID('$(EHA_SCHEMA).trg_$(OFFSITE_ACTIVITY_TABLE)') IS NOT NULL
 DROP TRIGGER $(EHA_SCHEMA).trg_$(OFFSITE_ACTIVITY_TABLE)
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: make note of all update and delete attempts 
--    ASSERT: the caller has opened the Database Master Key  
-------------------------------------------------------------------------------
CREATE TRIGGER $(EHA_SCHEMA).trg_$(OFFSITE_ACTIVITY_TABLE) 
ON $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
$(WITH_OPTIONS)
INSTEAD OF UPDATE, DELETE
AS 
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST( CHECKSUM( Id
                                                          , @@PROCID   
                                                          , ObjectName
                                                          , 0x0 -- @Parameters
                                                          , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
    OR (SELECT COUNT(*) FROM deleted) <> 1
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status )
    SELECT @Id
         , d.CaptureInstance
         , d.MinLsn
         , d.MaxLsn
         , d.[RowCount]
         , @MAC 
         , 'Instead' + CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
         , 'Complete' 
    FROM deleted d
    LEFT JOIN inserted i
    on d.Id = i.Id;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status 
      , ErrorData )
    SELECT @Id
         , d.CaptureInstance
         , d.MinLsn
         , d.MaxLsn
         , d.[RowCount]
         , ISNULL( @MAC, 0x0 ) 
         , 'Instead' + CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
         , 'Error'    
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM deleted d
    LEFT JOIN inserted i
    on d.Id = i.Id  
    OUTER APPLY (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                     , ERROR_NUMBER()
                                     , ERROR_SEVERITY()
                                     , ERROR_STATE()
                                     , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                     , ERROR_LINE()
                                     , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).trg_$(OFFSITE_ACTIVITY_TABLE) 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID('$(EHA_SCHEMA).trg_$(NOTIFICATION_ACTIVITY_TABLE)') IS NOT NULL
 DROP TRIGGER $(EHA_SCHEMA).trg_$(NOTIFICATION_ACTIVITY_TABLE)
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: make note of all update and delete attempts 
--    ASSERT: the caller has opened the Database Master Key  
-------------------------------------------------------------------------------
CREATE TRIGGER $(EHA_SCHEMA).trg_$(NOTIFICATION_ACTIVITY_TABLE) 
ON $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)
$(WITH_OPTIONS)
INSTEAD OF UPDATE, DELETE
AS 
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST( CHECKSUM( Id
                                                          , @@PROCID   
                                                          , ObjectName
                                                          , 0x0 -- @Parameters
                                                          , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
    OR (SELECT COUNT(*) FROM deleted) <> 1
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE) 
      ( Id
      , ConversationHandle
      , ConversationGroupId
      , Message
      , Signature
      , MAC
      , Action
      , Status )
    SELECT @Id
         , d.ConversationHandle
         , d.ConversationGroupId
         , d.Message
         , d.Signature
         , @MAC 
         , 'Instead' + CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
         , 'Complete' 
    FROM deleted d
    LEFT JOIN inserted i
    on d.Id = i.Id;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE) 
      ( Id
      , ConversationHandle
      , ConversationGroupId
      , Message
      , Signature
      , MAC
      , Action
      , Status 
      , ErrorData )
    SELECT @Id
         , ISNULL( d.ConversationHandle, 0x0 )
         , ISNULL( d.ConversationGroupId, 0x0 )
         , ISNULL( d.Message, 0x0 )
         , ISNULL( d.Signature, 0x0 )
         , ISNULL( @MAC, 0x0 ) 
         , 'Instead' + CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
         , 'Error'    
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM deleted d
    LEFT JOIN inserted i
    ON d.Id = i.Id  
    OUTER APPLY (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                     , ERROR_NUMBER()
                                     , ERROR_SEVERITY()
                                     , ERROR_STATE()
                                     , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                     , ERROR_LINE()
                                     , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY);
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).trg_$(NOTIFICATION_ACTIVITY_TABLE) 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
---------------
-- Functions
---------------
IF OBJECT_ID ('$(EHA_SCHEMA).AddSalt') IS NOT NULL
   DROP FUNCTION $(EHA_SCHEMA).AddSalt
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: append securely saved salt to a passed value & hash result    
--  ASSERT: symmetric key required to DECRYPT salt value is open
-------------------------------------------------------------------------------
CREATE FUNCTION $(EHA_SCHEMA).AddSalt 
  ( @DbName NVARCHAR(128) 
  , @SchemaName NVARCHAR(128)
  , @TableName NVARCHAR(128)
  , @ColumnName NVARCHAR(128) 
  , @Word NVARCHAR(128) )
RETURNS INT
$(WITH_OPTIONS)
AS
BEGIN
  DECLARE @SaltName NVARCHAR(443) = FORMATMESSAGE( $(MESSAGE_OFFSET)01
                                                 , @DbName
                                                 , @SchemaName
                                                 , @TableName
                                                 , @ColumnName);
  RETURN (SELECT ABS( CHECKSUM( HASHBYTES( '$(HASHBYTES_ALGORITHM)'
                                         , @Word + CAST( DECRYPTBYKEY( nv.Value
                                                                     , 1
                                                                     , @SaltName ) 
                                                        AS NVARCHAR(128) ) ) ) )
          FROM sys.certificates AS c
          JOIN sys.crypt_properties AS cp
          ON c.thumbprint = cp.thumbprint
          CROSS JOIN $(EHA_SCHEMA).$(NAMEVALUES_TABLE) AS nv
          WHERE nv.NameBucket = ABS( CHECKSUM( HASHBYTES( '$(HASHBYTES_ALGORITHM)'
                                                        , RIGHT( @SaltName 
                                                               , FLOOR( LEN( @SaltName ) / 2 
                                                                      ) ) ) ) )
          AND c.name = '$(OBJECT_CERTIFICATE)'
          AND c.pvt_key_encryption_type = 'PW'
          AND cp.major_id = @@PROCID 
          AND @@NESTLEVEL > 1        
          AND DB_ID(@DBName) IS NOT NULL
          AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'CERTIFICATE', c.thumbprint) = 1
          AND EXISTS (SELECT * FROM sys.database_role_members 
                      WHERE [role_principal_id] = USER_ID('$(EHADMIN_ROLE)')
                      AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                      AND SYSTEM_USER = ORIGINAL_LOGIN() ) ) ;	
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).AddSalt
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
-- all functions should verify user authentication and object signature
IF OBJECT_ID ('$(EHA_SCHEMA).BackupPath') IS NOT NULL
   DROP FUNCTION $(EHA_SCHEMA).BackupPath
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: the filetable path  
--    terminating reverse solidus "\" is expected
-------------------------------------------------------------------------------
CREATE FUNCTION $(EHA_SCHEMA).BackupPath 
  (@DbName NVARCHAR(128))
RETURNS VARBINARY(8000)
$(WITH_OPTIONS)
AS
BEGIN 
  RETURN ( SELECT ENCRYPTBYKEY( KEY_GUID( '$(FILE_SYMMETRIC_KEY)' ) 
                              , CAST( '$(VHD_LETTER):\' AS NVARCHAR(1024) )
                              , 1
                              , @DbName )   
            FROM sys.certificates AS c
            JOIN sys.crypt_properties AS cp
            ON c.thumbprint = cp.thumbprint
            CROSS JOIN ( SELECT TOP(1) KeyGuid 
                         FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                         ORDER BY CreateUTCDt DESC, Id DESC ) b
            CROSS JOIN sys.database_role_members r
            WHERE r.role_principal_id = DATABASE_PRINCIPAL_ID ( 'EHAdminRole' ) 
            AND r.member_principal_id = DATABASE_PRINCIPAL_ID ( ORIGINAL_LOGIN() )  
            AND b.KeyGuid = KEY_GUID( '$(SESSION_SYMMETRIC_KEY)' )
            AND c.name = '$(OBJECT_CERTIFICATE)'
            AND c.pvt_key_encryption_type = 'PW'
            AND cp.major_id = @@PROCID 
            AND @@NESTLEVEL > 1        
            AND DB_ID(@DBName) IS NOT NULL
            AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'CERTIFICATE', c.thumbprint) = 1
            AND EXISTS (SELECT * FROM sys.database_role_members 
                        WHERE [role_principal_id] = USER_ID('$(EHADMIN_ROLE)')
                        AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                        AND SYSTEM_USER = ORIGINAL_LOGIN() ) );	
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).BackupPath 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).CheckFile') IS NOT NULL
  DROP FUNCTION $(EHA_SCHEMA).CheckFile
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: apply file naming rules and conventions
--    name not already in use and no identified sql injection
-------------------------------------------------------------------------------
CREATE FUNCTION $(EHA_SCHEMA).CheckFile 
  ( @Name VARBINARY(8000) )
RETURNS BIT
$(WITH_OPTIONS)
AS
BEGIN
  RETURN (SELECT CASE WHEN  PATINDEX('%[#,.;:"'']%', Name) 
                          + PATINDEX('%--%', Name)
                          + PATINDEX('%*/%', Name)
                          + PATINDEX('%/*%', Name)
                          + PATINDEX('%DROP%', Name)
                          + PATINDEX('%CREATE%', Name)
                          + PATINDEX('%SELECT%', Name)
                          + PATINDEX('%INSERT%', Name)
                          + PATINDEX('%UPDATE%', Name)
                          + PATINDEX('%DELETE%', Name)
                          + PATINDEX('%GRANT%', Name)
                          + PATINDEX('%ALTER%', Name) 
                          + PATINDEX('%AUX%', Name) 
                          + PATINDEX('%CLOCK$%', Name) 
                          + PATINDEX('%COM[1-8]%', Name)
                          + PATINDEX('%CON%', Name) 
                          + PATINDEX('%LPT[1-8]%', Name) 
                          + PATINDEX('%NUL%', Name) 
                          + PATINDEX('%PRN%', Name) = 0
                      AND NOT EXISTS ( SELECT COUNT(*) AS [Existing] 
                                       FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
                                       WHERE BackupNameBucket = $(EHA_SCHEMA).AddSalt( '$(EHDB)'
                                                                                     , '$(EHA_SCHEMA)'
                                                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                                                     , 'BackupNameBucket' 
                                                                                     , Name ) )    
                      THEN 1 ELSE 0 END
          FROM (SELECT CAST( DECRYPTBYKEY ( @Name ) AS NVARCHAR(448) ) AS Name  
                FROM sys.certificates c
                JOIN sys.crypt_properties cp
                ON c.thumbprint = cp.thumbprint
                CROSS JOIN sys.database_role_members r
                WHERE r.role_principal_id = DATABASE_PRINCIPAL_ID ( 'EHAdminRole' ) 
                AND r.member_principal_id = DATABASE_PRINCIPAL_ID ( ORIGINAL_LOGIN() )  
                AND c.name = 'ObjectCertificate'
                AND c.pvt_key_encryption_type = 'PW'
                AND cp.major_id = @@PROCID 
                AND @@NESTLEVEL > 1 
                AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'CERTIFICATE', c.thumbprint) = 1
                AND EXISTS (SELECT * FROM sys.database_role_members 
                            WHERE [role_principal_id] = USER_ID('$(EHADMIN_ROLE)')
                            AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                            AND SYSTEM_USER = ORIGINAL_LOGIN() ) ) AS derived );
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).CheckFile 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).CheckPhrase') IS NOT NULL
   DROP FUNCTION $(EHA_SCHEMA).CheckPhrase 
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: password/passphrase gauntlet
--    phrases are frequently used in dynamic SQL so SQL Injection is risk
-------------------------------------------------------------------------------
CREATE FUNCTION $(EHA_SCHEMA).CheckPhrase 
  ( @tvp AS NAMEVALUETYPE READONLY )
RETURNS @metatvp TABLE 
  ( Status NVARCHAR(30)
  , Signature VARBINARY(128) )
$(WITH_OPTIONS)
AS
BEGIN
  DECLARE @Status NVARCHAR(30)
        , @Name NVARCHAR(448)
        , @UpValue NVARCHAR(128) 
        , @Value NVARCHAR(128) ;
  -- dft password policy as described in 2008R2 BOL + SQL Injection black list
  -- fyi: SELECT CAST(NEWID() AS VARCHAR(128)) returns a valid password 
  SET @Status = 'authenticity';
  IF EXISTS ( SELECT *
              FROM sys.certificates c
              JOIN sys.crypt_properties cp
              ON c.thumbprint = cp.thumbprint
              CROSS JOIN sys.database_role_members r
              WHERE r.role_principal_id = DATABASE_PRINCIPAL_ID ( '$(EHADMIN_ROLE)' ) 
              AND r.member_principal_id = DATABASE_PRINCIPAL_ID ( ORIGINAL_LOGIN() )  
              AND c.name = 'ObjectCertificate'
              AND c.pvt_key_encryption_type = 'PW'
              AND cp.major_id = @@PROCID 
              AND @@NESTLEVEL > 1 -- no direct exec of function 
              AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'CERTIFICATE', c.thumbprint) = 1
              AND EXISTS ( SELECT * FROM sys.database_role_members 
                            WHERE [role_principal_id] = USER_ID('$(EHADMIN_ROLE)')
                            AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                            AND SYSTEM_USER = ORIGINAL_LOGIN() ) )        
    BEGIN
      SET @Status = 'decode';
      SET @Name = ( SELECT DECRYPTBYKEY( Name 
                                       , 1
                                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) ) 
      FROM @tvp );
      SET @Value = ( SELECT DECRYPTBYKEY( Value, 1, @Name ) FROM @tvp );                    
      IF PATINDEX('%.CONFIG', UPPER(@Name) )  -- no strength test, will fall through 
       + PATINDEX('%.IDENTITY', UPPER(@Name) )             
       + PATINDEX('%.PRIVATE', UPPER(@Name) ) 
       + PATINDEX('%.SALT', UPPER(@Name) )           
       + PATINDEX('%.SOURCE', UPPER(@Name) ) > 0       
        SET @Status = 'OK';
      ELSE
        BEGIN
          SET @UpValue = UPPER(@Value);
          SET @Status = 'strength';
          IF ( (    ( LEN(@Value) >= $(MIN_PHRASE_LENGTH) )   -- more is better
                AND ( PATINDEX('%[#,.;:]%'
                    , @Value ) = 0 )   -- none of these symbols as recommended in BOL 
                AND ( SELECT CASE WHEN PATINDEX('%[A-Z]%'
                                                , @Value) > 0 
                                  THEN 1 ELSE 0 END    -- has uppercase
                            + CASE WHEN PATINDEX('%[a-z]%'
                                                , @Value) > 0 
                                  THEN 1 ELSE 0 END    -- has lowercase  
                            + CASE WHEN PATINDEX('%[0-9]%'
                                                , @Value) > 0 
                                  THEN 1 ELSE 0 END    -- has number
                            + CASE WHEN PATINDEX('%^[A-Z], ^[a-z], ^[0-9]%'
                                                , @Value ) > 0  -- has symbol
                                  THEN 1 ELSE 0 END ) > 2 ) )   -- at least 3 of 4
            BEGIN 
              -- black list is not so strong but can look for the obvious 
              SET @Status = 'injection';                       
              IF ( PATINDEX('%[__"'']%', @UpValue)   -- underscore (so no sp_ or xp_) or quotes
                 + PATINDEX('%DROP%'   , @UpValue)   -- multi-character commands... 
                 + PATINDEX('%ADD%'    , @UpValue)
                 + PATINDEX('%CREATE%' , @UpValue)
                 + PATINDEX('%SELECT%' , @UpValue)
                 + PATINDEX('%INSERT%' , @UpValue)
                 + PATINDEX('%UPDATE%' , @UpValue)
                 + PATINDEX('%DELETE%' , @UpValue)
                 + PATINDEX('%GRANT%'  , @UpValue)
                 + PATINDEX('%REVOKE%' , @UpValue)
                 + PATINDEX('%RUNAS%'  , @UpValue)
                 + PATINDEX('%ALTER%'  , @UpValue)
                 + PATINDEX('%EXEC%'   , @UpValue)
                 + PATINDEX('%--%'     , @Value)     -- comments...
                 + PATINDEX('%**/%'    , @Value) 
                 + PATINDEX('%/**%'    , @Value)  = 0 )
                BEGIN 
                  SET @Status = 'duplicate';
                  IF NOT EXISTS ( SELECT *                  -- not already used  
                                  FROM $(EHA_SCHEMA).$(NAMEVALUES_TABLE) n
                                  WHERE ValueBucket = $(EHA_SCHEMA).AddSalt( '$(EHDB)'
                                                                            , '$(EHA_SCHEMA)'
                                                                            , '$(NAMEVALUES_TABLE)'
                                                                            , 'ValueBucket' 
                                                                            , @Value)
                                  AND CAST(DecryptByKey( n.Value -- should be rare
                                                        , 1
                                                        , @Name ) AS NVARCHAR(128) )  =  @Value )  
                    SET @Status = 'OK';
                END
            END
        END
    END
  INSERT @metatvp
    ( Status
    , Signature ) 
  VALUES 
    ( @Status
    , SignByCert( CERT_ID('$(AUTHENTICITY_CERTIFICATE)'), @Status ) );
  RETURN;
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).CheckPhrase 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).GetEHPhraseName') IS NOT NULL
   DROP FUNCTION $(EHA_SCHEMA).GetEHPhraseName
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: deterministic standardized name for managed encryption phrase value
--    but is an encryptped value so will return different cipher text for same 
--    parms each time called 
-------------------------------------------------------------------------------
CREATE FUNCTION $(EHA_SCHEMA).GetEHPhraseName 
  ( @DbName NVARCHAR(128)  
  , @NodeName NVARCHAR(128)  
  , @Purpose NVARCHAR(10) )  
RETURNS VARBINARY(8000)
$(WITH_OPTIONS)
AS
BEGIN
  RETURN ( SELECT ENCRYPTBYKEY( KEY_GUID('$(NAME_SYMMETRIC_KEY)')
                              , CAST ( REPLACE(@@SERVERNAME + '__', '\', '$') 
	                                   + ISNULL( @DbName + '__', '')
                                     + REPLACE(@NodeName + '__', ' ', '_')    
	                                   + @Purpose
                                     AS NVARCHAR(448) ) 
                              , 1
                              , CAST ( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') 
                                     AS NCHAR(36) ) ) 
           FROM sys.certificates c
           JOIN sys.crypt_properties cp
           ON c.thumbprint = cp.thumbprint
           WHERE c.name = '$(OBJECT_CERTIFICATE)'
           AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'certificate', c.thumbprint) = 1 
           AND c.pvt_key_encryption_type = 'PW'
           AND cp.major_id = @@PROCID        
           AND @@NESTLEVEL > 1        
           AND DB_ID(@DBName) IS NOT NULL
           AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'CERTIFICATE', c.thumbprint) = 1
           AND EXISTS ( SELECT * FROM sys.database_role_members 
                        WHERE [role_principal_id] = USER_ID('$(EHADMIN_ROLE)')
                        AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                        AND SYSTEM_USER = ORIGINAL_LOGIN() ) ); 	
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).GetEHPhraseName
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).GetNode') IS NOT NULL
   DROP FUNCTION $(EHA_SCHEMA).GetNode
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: this/next available sibling node in depth aligned hierarchy 
-- 
-- hierarchy is 4 container based levels root-srv-db-cert
-- use to dynamically identify objects dropped from the instance
-- not all possibilities are represented in following ASCII modulated thought 
-- hierarchy diagram connectors:
--   | - catalog connection
--   _ - cryptographic dependency: ecrypted by parent  
--   x - cryptographic root: no cryptographic relationship to parent     
--   ~ - and so on: hierarchy above connector might expand or contract
-------------------------------------------------------------------------------
-- SQL Encryption Hierarchy Administration root                                                      \
--   |x SQL Instance 1 Service Master Key ................. \1                                          
--   | |_ Database A Master Key ........................... \1\1                     
--   | | |_ Certificate I                                   \1\1\1                    
--   | | |x Certificate II                                  \1\1\2                              
--   | | |x Certificate III                                 \1\1\3
--   | | |_ Certificate IV                                  \1\1\4
--   | |x Database B Master Key ........................... \1\2                    
--   |   |x Certificate II                                  \1\2\1
--   |   |_ Certificate VII                                 \1\2\2                             
--   ~
--   |x SQL Instance 2 Service Master Key ................. \2
--   | |_ Database A Master Key ........................... \2\1
--   | | |_ Certificate a                                   \2\1\1
--   | |_ Database C Master Key ........................... \2\2
--   |   |_ Certificate b                                   \2\2\1
--   ~ 
--   |x SQL Instance 3 Service Master Key ................. \3
--   | |x (implied:no Database Master Key)................. \3\1
--   |   |x Certificate a                                   \3\1\1
--   ~
--   |x SQL Instance ? Service Master Key ................. \n   
--     |? Database ? Master Key ........................... \n\n
--       |? Certificate ? ................................  \n\n\n
-------------------------------------------------------------------------------
CREATE FUNCTION $(EHA_SCHEMA).GetNode 
  ( @NodeName NVARCHAR(128)
  , @DbName NVARCHAR(128) 
  , @ServerName NVARCHAR(128) )  
RETURNS HIERARCHYID
$(WITH_OPTIONS)
AS
BEGIN
  DECLARE @Node HIERARCHYID;
  WITH cte 
    AS ( SELECT '' AS [DbName]
              , 'root' AS [NodeName]
              , '/' AS [Node]
              , 0 AS [Level]
        UNION ALL
        SELECT [DbName]
              , [NodeName]
              , [Node]
              , [Level]
        FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
        WHERE ServerName = @ServerName 
        AND Action IN ( 'Install'
                , 'BackupServiceMasterKey'
                , 'BackupDatabaseMasterKey'
                , 'BackupCertificate' )
        AND Status = 'Complete')
  SELECT @Node = ISNULL( this.Node
                       , parent.node.GetDescendant( last.Node, NULL) )  
  FROM cte parent         
  CROSS APPLY ( SELECT MAX(Node) AS Node
                FROM cte 
                WHERE Node.GetAncestor(1) = parent.Node) AS last
  LEFT JOIN cte AS this
  ON this.Node.GetAncestor(1) = parent.Node
  AND this.DbName  = @DbName
  AND this.NodeName = @NodeName
  WHERE parent.Level =  CASE @NodeName  
                        WHEN 'Service Master Key'
                        THEN 0
                        WHEN 'Database Master Key'
                        THEN 1
                        ELSE 2 END
  AND parent.DbName = CASE WHEN parent.level = 2
                          THEN @DbName
                          WHEN parent.level = 1
                          THEN 'master'
                          ELSE '' END
  RETURN ( SELECT @Node
           FROM sys.certificates c
           JOIN sys.crypt_properties cp
           ON c.thumbprint = cp.thumbprint
           WHERE c.name = '$(OBJECT_CERTIFICATE)'
           AND c.pvt_key_encryption_type = 'PW'
           AND cp.major_id = @@PROCID        
           AND @@NESTLEVEL > 1        
           AND DB_ID(@DBName) IS NOT NULL
           AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'CERTIFICATE', c.thumbprint) = 1
           AND EXISTS ( SELECT * FROM sys.database_role_members 
                        WHERE [role_principal_id] = USER_ID('$(EHADMIN_ROLE)')
                        AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                        AND SYSTEM_USER = ORIGINAL_LOGIN() ) ); 
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).GetNode
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).NewCertificateBackupName') IS NOT NULL
   DROP FUNCTION $(EHA_SCHEMA).NewCertificateBackupName
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: a unique name for the certificate backup file
--  proof of authenticity 
--     object is signed
--     user is sysadmin and in role  
--     can use key opened by caller  
--  caller must be authentic in order to see and use the value created
--  others can verify if caller persists the encrypted value
-------------------------------------------------------------------------------
CREATE FUNCTION $(EHA_SCHEMA).NewCertificateBackupName 
 ( @DbName NVARCHAR(128)
 , @NodeName NVARCHAR(128) )
RETURNS VARBINARY(8000)
$(WITH_OPTIONS)
AS
BEGIN
  DECLARE @NewName VARBINARY(8000);
  WHILE ( $(EHA_SCHEMA).CheckFile( @NewName ) = 1 ) OR ( @NewName IS NULL )
    SET @NewName = (SELECT ENCRYPTBYKEY( KEY_GUID( '$(NAME_SYMMETRIC_KEY)' )
                                       , CAST ( REPLACE(@@SERVERNAME,'\','$') + '__' 
                                              + @DbName + '__' 
                                              + @NodeName + '__' 
                                              + FORMAT( SYSUTCDATETIME()
                                                      , 'yyyyMMddHHmmssfffffff' ) 
                                              AS NVARCHAR(448) ) )  
                    FROM sys.certificates c
                    JOIN sys.crypt_properties cp
                    ON c.thumbprint = cp.thumbprint
                    WHERE c.name = '$(OBJECT_CERTIFICATE)'
                    AND c.pvt_key_encryption_type = 'PW'
                    AND cp.major_id = @@PROCID        
                    AND @@NESTLEVEL > 1        
                    AND DB_ID(@DBName) IS NOT NULL
                    AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'CERTIFICATE', c.thumbprint) = 1
                    AND EXISTS ( SELECT * FROM sys.database_role_members 
                                  WHERE [role_principal_id] = USER_ID('$(EHADMIN_ROLE)')
                                  AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                                  AND SYSTEM_USER = ORIGINAL_LOGIN() ) );       
  RETURN ( @NewName );
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).NewCertificateBackupName 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).NewMasterKeyBackupName') IS NOT NULL
   DROP FUNCTION $(EHA_SCHEMA).NewMasterKeyBackupName
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: get the name of the file - encrypted for tvp - a service master 
--        key backup or a database master key backup will use 
-------------------------------------------------------------------------------
CREATE FUNCTION $(EHA_SCHEMA).NewMasterKeyBackupName 
  ( @DbName NVARCHAR(128) = NULL )
RETURNS VARBINARY(8000)
$(WITH_OPTIONS)
AS
BEGIN
  DECLARE @NewName VARBINARY(8000);
  WHILE ( $(EHA_SCHEMA).CheckFile( @NewName ) = 1 ) OR ( @NewName IS NULL )  
    SET @NewName = (SELECT ENCRYPTBYKEY( KEY_GUID('$(FILE_SYMMETRIC_KEY)')
                                       , CAST ( REPLACE(@@SERVERNAME,'\','$') + '__'
                                              + ISNULL ( @DbName + '__MasterKey'
                                                       , 'ServiceMasterKey' ) + '__'
                                              + FORMAT( SYSUTCDATETIME()
                                                      , 'yyyyMMddHHmmssfffffff')  
                                              AS NVARCHAR(448) ) ) AS NewName 
                    FROM sys.certificates AS c
                    JOIN sys.crypt_properties AS cp
                    ON c.thumbprint = cp.thumbprint
                    WHERE c.name = '$(OBJECT_CERTIFICATE)'
                    AND c.pvt_key_encryption_type = 'PW'
                    AND cp.major_id = @@PROCID        
                    AND @@NESTLEVEL > 1        
                    -- @DBName can be null here
                    AND IS_OBJECTSIGNED( 'OBJECT'
                                       , @@PROCID
                                       , 'CERTIFICATE'
                                       , c.thumbprint ) = 1
                    AND EXISTS ( SELECT * FROM sys.database_role_members 
                                  WHERE [role_principal_id] = USER_ID('$(EHADMIN_ROLE)')
                                  AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                                  AND SYSTEM_USER = ORIGINAL_LOGIN() ) );       
  RETURN ( @NewName );
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).NewMasterKeyBackupName 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
---------------------
--NameValue procs
---------------------
IF OBJECT_ID('$(EHA_SCHEMA).AddNameValue','P') IS NOT NULL
	DROP PROCEDURE $(EHA_SCHEMA).AddNameValue 
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: encrypt, hash and store Value a NAMEVALUETYPE tvp to 
--  $(EHA_SCHEMA).$(NAMEVALUES_TABLE)   
--  ASSERT: passed name does not use the authenticator 
--  ASSERT: DMK and symmetric keys opened by caller   
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).AddNameValue 
 ( @tvp NAMEVALUETYPE READONLY
 , @Version SMALLINT OUTPUT )
$(WITH_OPTIONS)
AS
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128)
      , @Name NVARCHAR(448)
      , @NameBucket INT
      , @Parameters VARBINARY(8000)
      , @Status NVARCHAR(30)
      , @Value NVARCHAR(128)
      , @ValueBucket INT;
  BEGIN TRY
    IF NOT EXISTS (SELECT * from sys.openkeys 
                   WHERE key_name = '$(AUDIT_SYMMETRIC_KEY)'
                   AND @@NESTLEVEL > 1 )
      EXEC $(EHA_SCHEMA).OpenSession;
    SET @Parameters = 
      ( SELECT ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                           , FORMATMESSAGE( '@tvp.Name = ''%s'', @tvp.Value = ''%s'''
                                          , Name
                                          , CAST( DECRYPTBYKEY( Value, 1, Name ) AS NVARCHAR(128) ) )
                          , 1, CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) )
        FROM (SELECT CAST( DECRYPTBYKEY( Name 
                                       , 1
                                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) ) AS NVARCHAR(448) ) AS Name
                   , Value
              FROM  @tvp ) AS derived );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                         , @Parameters
                         , @Id OUTPUT
                         , @MAC OUTPUT; 
    -- verify a book row for passed ID that using returned authenticator (signature) 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    -- get buckets for clear text name & value
    SET @Name = ( SELECT CAST( DECRYPTBYKEY( Name
                                           , 1
                                           , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) ) 
                              AS NVARCHAR(448) ) 
    FROM @tvp ); 
    SET @Value = ( SELECT CAST( DECRYPTBYKEY( Value, 1, @Name ) AS NVARCHAR(128) ) FROM @tvp );
    IF PATINDEX( '%.SALT', UPPER(@Name) ) > 0
      BEGIN
        SET @NameBucket  = ABS( CHECKSUM( HASHBYTES( '$(HASHBYTES_ALGORITHM)'
                                                   , RIGHT( @Name,  FLOOR( LEN(@Name) / 2  ) ) ) ) );
        SET @ValueBucket = ABS( CHECKSUM( HASHBYTES( '$(HASHBYTES_ALGORITHM)'
                                                   , RIGHT( @Value, FLOOR( LEN(@Value) / 2 ) ) ) ) );
      END
    ELSE
      BEGIN
        SET @NameBucket = $(EHA_SCHEMA).AddSalt( '$(EHDB)'
                                               , '$(EHA_SCHEMA)'
                                               , '$(NAMEVALUES_TABLE)'
                                               , 'NameBucket' 
                                               , @Name );
        SET @ValueBucket = $(EHA_SCHEMA).AddSalt( '$(EHDB)'
                                                , '$(EHA_SCHEMA)'
                                                , '$(NAMEVALUES_TABLE)'
                                                , 'ValueBucket' 
                                                , @Value );
      END
    -- next version for this NameValue.Name
    -- EHphrases must be unique (CheckPhrase) but other NameValues, e.g..Private or Salt need not be unique
    SET @Version = ISNULL( ( SELECT TOP(1) 
                                    CASE WHEN @ValueBucket = tab.ValueBucket                                     
                                         THEN tab.Version
                                         ELSE tab.Version + 1 END AS Version 
                              FROM $(EHA_SCHEMA).$(NAMEVALUES_TABLE) tab
                              WHERE tab.NameBucket = @NameBucket 
                              AND tab.Version = ISNULL( @Version, tab.Version)
                              ORDER BY Version DESC ), 1 );                
    SET @Status = ( SELECT Status
                    FROM $(EHA_SCHEMA).CheckPhrase( @tvp ) AS metatvp
                    WHERE VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                            , Status
                                            , Signature ) = 1 );
    IF @Status <> 'OK'
      RAISERROR($(MESSAGE_OFFSET)35, 16, 1, 'CheckPhrase', @Status);
    -- name encryption conversion
    IF @Version > 0  -- need to add this one
      BEGIN
        INSERT $(EHA_SCHEMA).$(NAMEVALUES_TABLE) 
            ( Id
            , NameBucket
            , ValueBucket
            , Version
            , Name
            , Value)
        SELECT @Id
             , @NameBucket
             , @ValueBucket
             , @Version
             , ENCRYPTBYKEY( KEY_GUID('$(NAME_SYMMETRIC_KEY)')
                           , @Name
                           , 1
                           , @Id )
             , Value
        FROM @tvp;      
        INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status )
        SELECT @Id
             , @MAC 
             , OBJECT_NAME(@@PROCID)
             , 'Complete';    
      END
    ELSE 
      SET @Version = ABS(@Version);
    IF @@NESTLEVEL = 1 
      CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status 
      , ErrorData)
    SELECT @Id 
         , ISNULL( @MAC, 0x0 )
         , OBJECT_NAME(@@PROCID)
         , 'Error'    
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                              , ERROR_NUMBER()
                              , ERROR_SEVERITY()
                              , ERROR_STATE()
                              , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                              , ERROR_LINE()
                              , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE ALL SYMMETRIC KEYS;
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH; 
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).AddNameValue
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID('$(EHA_SCHEMA).SelectNameValue','P') IS NOT NULL
	DROP PROCEDURE $(EHA_SCHEMA).SelectNameValue;
GO
---------------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: select and decrypt an encrypted namevalue pair
--  Use result set instead of OUTPUT param for INSERT @tvp EXEC SelectNameValue usage   
--  ASSERT: DMK and symmetric key are already open even more secure would be to REQUIRE
--          the implied nesting. Here the possiblity to call from command line is open.  
----------------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).SelectNameValue 
 ( @Name VARBINARY(8000) 
 , @Version SMALLINT = NULL ) -- null gets latest
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @Id NCHAR(36)
      , @MAC VARBINARY(128)
      , @NameBucket INT
      , @Parameters VARBINARY(8000)
      , @ErrorData VARBINARY(8000);
SET NOCOUNT ON;  
  BEGIN TRY
    SET @Parameters = 
      ( SELECT ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                           , FORMATMESSAGE( '@Name = ''%s'''
                                           , DECRYPTBYKEY ( @Name
                                                          , 1
                                                          , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) ) )
                           , 1
                           , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    SELECT TOP (1) 
           @Name AS Name
         , CAST(DECRYPTBYKEY(Value
                            , 1
                            , @Name ) AS NVARCHAR(128) ) AS Value
    FROM $(EHA_SCHEMA).$(NAMEVALUES_TABLE)
    WHERE NameBucket =  $(EHA_SCHEMA).AddSalt( '$(EHDB)'
                                             , '$(EHA_SCHEMA)'
                                             , '$(NAMEVALUES_TABLE)'
                                             , 'NameBucket' 
                                             , @Name ) 
    AND Version = ISNULL( @Version, Version )
    ORDER BY Version DESC; 
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    SELECT @Id
         , @MAC
         , OBJECT_NAME(@@PROCID)
         , 'Complete';    
    IF @@NESTLEVEL = 1 
      CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status 
      , ErrorData)
    SELECT @Id
         , ISNULL( @MAC, 0x0 ) 
         , OBJECT_NAME(@@PROCID)
         , 'Error'    
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                              , ERROR_NUMBER()
                              , ERROR_SEVERITY()
                              , ERROR_STATE()
                              , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                              , ERROR_LINE()
                              , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
    CLOSE ALL SYMMETRIC KEYS;
    IF @@NESTLEVEL > 1
      THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).SelectNameValue
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).ValidateNameValue') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).ValidateNameValue
GO
---------------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: validate encrypted value 
--  ASSERT: DMK and symmetric key are already open even more secure would be to REQUIRE
--          the implied nesting. Here the possiblity to call from command line is open.  
----------------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).ValidateNameValue 
 ( @tvp NAMEVALUETYPE READONLY
 , @Version SMALLINT = NULL     -- use latest if null
 , @IsValid BIT OUTPUT )
$(WITH_OPTIONS)
AS
BEGIN 
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128)
      , @Name NVARCHAR(448)
      , @Parameters VARBINARY(8000)
      , @Status NVARCHAR(30)
      , @Value NVARCHAR(128);      
  BEGIN TRY
    SET @IsValid = 0;
    SET @Parameters = 
      ( SELECT ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                           , FORMATMESSAGE( '@tvp.Name = ''%s'', @tvp.Value = ''%s'' @Version = %d'
                                          , CAST( DECRYPTBYKEY( Name ) AS NVARCHAR(448) )
                                          , sys.fn_varbintohexstr( DECRYPTBYKEY( Value
                                                                               , 1
                                                                               , CAST( DECRYPTBYKEY( Name ) AS NVARCHAR(448) ) ) ) 
                                          , @Version)
                          , 1
                          , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) )
                        FROM @tvp);
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    SET @Status = ( SELECT Status
                    FROM $(EHA_SCHEMA).CheckPhrase(@tvp) AS metatvp
                    WHERE VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                            , Status
                                            , Signature ) = 1 );
    IF @Status <> 'OK'
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'Value', @Status);
    SET @IsValid = 1;
    SELECT TOP(1) @IsValid = CASE WHEN tab.ValueBucket = CASE WHEN PATINDEX( '%.SALT', UPPER(derived.Name) ) > 0
                                                              THEN ABS( CHECKSUM( HASHBYTES( '$(HASHBYTES_ALGORITHM)'
                                                                                           , derived.Name ) ) ) 
                                                              ELSE $(EHA_SCHEMA).AddSalt( '$(EHDB)'
                                                                                        , '$(EHA_SCHEMA)'
                                                                                        , '$(NAMEVALUES_TABLE)'
                                                                                        , 'NameBucket' 
                                                                                        , derived.Name )
                                                              END
                                  THEN 1 ELSE 0 END
    FROM $(EHA_SCHEMA).$(NAMEVALUES_TABLE) tab
    JOIN ( SELECT DECRYPTBYKEY( Name ) AS Name
                , DECRYPTBYKEY( Value
                              , 1
                              ,  CAST( DECRYPTBYKEY( Name ) AS NVARCHAR(448) ) ) AS Value
                , Name AS PassedName
                , Value AS PassedValue 
           FROM @tvp ) derived
    ON tab.NameBucket =  CASE WHEN PATINDEX( '%.SALT', UPPER(derived.Name) ) > 0
                              THEN ABS( CHECKSUM( HASHBYTES( '$(HASHBYTES_ALGORITHM)'
                                                           , derived.Name ) ) ) 
                              ELSE $(EHA_SCHEMA).AddSalt( '$(EHDB)'
                                                        , '$(EHA_SCHEMA)'
                                                        , '$(NAMEVALUES_TABLE)'
                                                        , 'NameBucket' 
                                                        , derived.Name )
                              END 
    WHERE tab.Version = ISNULL(@Version, tab.Version)
    AND CAST(DecryptByKey( tab.Value
                         , 1
                         , CAST(DecryptByKey( tab.Name
                                            , 1
                                            , CAST( tab.Id AS NCHAR(36) ) 
                                            ) AS NVARCHAR(128) ) 
                         ) AS NVARCHAR(128) ) = derived.Value 
    ORDER BY Version DESC;
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status)
    SELECT @Id
         , @MAC
         , OBJECT_NAME(@@PROCID)
         , CASE WHEN @IsValid = 1 THEN  'Valid' ELSE 'Invalid' END 
    FROM @tvp;    
    IF @@NESTLEVEL = 1 
      CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
     ( Id
     , MAC
     , Action
     , Status 
     , ErrorData)
    SELECT @Id
         , ISNULL( @MAC, 0x0 )
         , OBJECT_NAME(@@PROCID)
         , 'Error'    
         , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                       , ErrorInfo 
                       , 1
                       , @Id )
    FROM @tvp  
    OUTER APPLY (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                     , ERROR_NUMBER()
                                     , ERROR_SEVERITY()
                                     , ERROR_STATE()
                                     , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                     , ERROR_LINE()
                                     , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;

    CLOSE ALL SYMMETRIC KEYS;
     IF @@NESTLEVEL > 1
       THROW;
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).ValidateNameValue
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).MakeSalt') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).MakeSalt
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: add a salt value with standardized name to NameValues
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).MakeSalt 
  ( @DbName NVARCHAR(128) 
  , @SchemaName NVARCHAR(128)
  , @TableName NVARCHAR(128)
  , @ColumnName NVARCHAR(128) )
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128)
      , @Parameters VARBINARY(8000)
      , @ReturnCode INT
      , @SaltName NVARCHAR(448) = FORMATMESSAGE( $(MESSAGE_OFFSET)01
                                               , @DbName
                                               , @SchemaName
                                               , @TableName
                                               , @ColumnName )
      , @tvp NAMEVALUETYPE
      , @Version INT; 
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)' )
                                  , FORMATMESSAGE( '@DBName = ''%s'''
                                               + ', @SchemaName= ''%s''' 
                                               + ', @TableName = ''%s''' 
                                               + ', @ColumnName = ''%s'''
                                                 , @DbName
                                                 , @SchemaName
                                                 , @TableName
                                                 , @ColumnName )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)' )
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);  
    -- if salt exists will get new version in AddNameValues 
    INSERT @tvp ( Name, Value ) 
    SELECT ENCRYPTBYKEY( KEY_GUID('$(NAME_SYMMETRIC_KEY)')
                       , @SaltName
                       , 1
                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) )
         , ENCRYPTBYKEY( KEY_GUID('$(VALUE_SYMMETRIC_KEY)')
                       , sys.fn_varbintohexstr (CRYPT_GEN_RANDOM( LEN(@SaltName)
                                                                , HASHBYTES( '$(HASHBYTES_ALGORITHM)' 
                                                                           , @SaltName ) ) ), 1, @SaltName );
    EXEC @ReturnCode = $(EHA_SCHEMA).AddNameValue @tvp, @Version OUTPUT;   
    IF @ReturnCode <> 0
      RAISERROR( $(MESSAGE_OFFSET)12, 16, 1
                , @DbName, @SchemaName, @TableName, @ColumnName, 'MakeSalt' ,@ReturnCode);  
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    SELECT @Id
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete' 
    FROM @tvp;    
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        WHILE @@TRANCOUNT > 0
          ROLLBACK TRANSACTION
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
         ( Id
         , MAC 
         , Action
         , Status 
         , ErrorData)
        SELECT @Id
             , ISNULL( @MAC, 0x0 )
             , OBJECT_NAME(@@PROCID)
             , 'Error'    
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).MakeSalt
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).SavePortableSymmetricKey') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).SavePortableSymmetricKey
GO
-------------------------------------------------------------------------------
-- bwunder at yahoo dot com
-- Desc: Save the Identity and Source of a symmetric key to NameValues
-- The Phrase may also be stored in NameValues idenpendently (not done here)
-- Save the phrase as a private value and use that private value phrase as
-- authorization to decipher any existing data encrypted buy the portable key
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).SavePortableSymmetricKey 
 ( @KeyName NVARCHAR(128) 
 , @KeyIdentity VARBINARY(8000)
 , @KeySource VARBINARY(8000) )
$(WITH_OPTIONS)
AS
BEGIN 
DECLARE @MAC VARBINARY(128)
      , @Parameters VARBINARY(8000)
      , @Id NCHAR(36)
      , @Identitytvp NAMEVALUETYPE
      , @Sourcetvp NAMEVALUETYPE
      , @Version INT
      , @ErrorData VARBINARY(8000);
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)' )
                                  , FORMATMESSAGE( '@KeyName = ''%s'', @KeyIdentity = %s, @KeySource = %s'
                                                 , @KeyName
                                                 , sys.fn_varbintohexstr( @KeyIdentity )
                                                 , sys.fn_varbintohexstr( @KeySource ) )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID( '$(AUTHENTICITY_CERTIFICATE)' )
                                                   , CAST(CHECKSUM ( Id
                                                                   , @@PROCID   
                                                                   , ObjectName
                                                                   , @Parameters
                                                                   , KeyGuid
                                                                   , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT @Identitytvp 
      ( Name
      , Value) 
    SELECT ENCRYPTBYKEY( KEY_GUID('$(NAME_SYMMETRIC_KEY)')
                       , KeyName
                       , 1
                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) )
          , ENCRYPTBYKEY( KEY_GUID('$(VALUE_SYMMETRIC_KEY)')
                        , CAST( DECRYPTBYKEY( @KeyIdentity ) AS NVARCHAR(128) )
                        , 1
                        , KeyName )
    FROM (SELECT FORMATMESSAGE( '%s.Identity', @KeyName ) AS KeyName 
          WHERE @KeyIdentity IS NOT NULL) AS derived;
    EXEC $(EHA_SCHEMA).AddNameValue @Identitytvp, @Version OUTPUT;   
    INSERT @Sourcetvp 
      ( Name
      , Value) 
    SELECT ENCRYPTBYKEY( KEY_GUID('$(NAME_SYMMETRIC_KEY)')
                       , KeyName
                       , 1
                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) )
          , ENCRYPTBYKEY( KEY_GUID('$(VALUE_SYMMETRIC_KEY)')
                        , CAST( DECRYPTBYKEY( @KeySource ) AS NVARCHAR(128) )
                        , 1
                        , KeyName )
    FROM (SELECT FORMATMESSAGE( '%s.Source', @KeyName ) AS KeyName 
          WHERE @KeySource IS NOT NULL) AS derived;
    EXEC $(EHA_SCHEMA).AddNameValue @Sourcetvp, @Version OUTPUT;   
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    VALUES ( @Id
           , @MAC
           , OBJECT_NAME(@@PROCID)
           , 'Complete' );    
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
         ( Id
         , MAC 
         , Action
         , Status 
         , ErrorData)
        SELECT @Id
             , ISNULL( @MAC, 0x0 )
             , OBJECT_NAME(@@PROCID)
             , 'Error'    
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
        IF @@NESTLEVEL > 1
          THROW;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).SavePortableSymmetricKey
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).GetPortableSymmetricKey') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).GetPortableSymmetricKey
GO
-------------------------------------------------------------------------------
-- bwunder at yahoo dot com
-- Desc: Fetch the Identity and Source of a symmetric key from NameValues
-- The Phrase may also be stored in NameValues but is not retrieved here
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).GetPortableSymmetricKey 
 ( @KeyName NVARCHAR(128) 
 , @KeyIdentity VARBINARY(8000) OUTPUT
 , @KeySource VARBINARY(8000) OUTPUT )
$(WITH_OPTIONS)
AS
BEGIN 
DECLARE @MAC VARBINARY(128)
      , @Parameters VARBINARY(8000)
      , @Id NCHAR(36)
      , @Identitytvp NAMEVALUETYPE
      , @Sourcetvp NAMEVALUETYPE
      , @Version INT
      , @ErrorData VARBINARY(8000);
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)' )
                                  , FORMATMESSAGE( '@KeyName = ''%s'''
								                 , @KeyName )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)' )
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT @Identitytvp 
      ( Name
      , Value) 
    VALUES( ENCRYPTBYKEY( KEY_GUID('$(NAME_SYMMETRIC_KEY)')
                        , FORMATMESSAGE('%s.Identity', @KeyName) 
                        , 1
                        , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) )
          , ENCRYPTBYKEY( KEY_GUID('$(VALUE_SYMMETRIC_KEY)')
                        , CAST( DECRYPTBYKEY( @KeyIdentity ) AS NVARCHAR(128) ), 1, FORMATMESSAGE( '%s.Identity'
                                                        , @KeyName ) ) );
    EXEC $(EHA_SCHEMA).AddNameValue @Identitytvp, @Version OUTPUT;   
    INSERT @Sourcetvp 
      ( Name
      , Value) 
    VALUES( ENCRYPTBYKEY( KEY_GUID('$(NAME_SYMMETRIC_KEY)')
                        , FORMATMESSAGE( '%s.Source', @KeyName ) 
                        , 1
                        , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) )
          , ENCRYPTBYKEY( KEY_GUID('$(VALUE_SYMMETRIC_KEY)')
                        , CAST( DECRYPTBYKEY( @KeySource ) AS NVARCHAR(128) ), 1, FORMATMESSAGE( '%s.Source'
                                                      , @KeyName ) ) );
    EXEC $(EHA_SCHEMA).AddNameValue @Sourcetvp, @Version OUTPUT;   
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    VALUES ( @Id
           , @MAC
           , OBJECT_NAME(@@PROCID)
           , 'Complete' );    
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
         ( Id
         , MAC 
         , Action
         , Status 
         , ErrorData)
        SELECT @Id
             , ISNULL( @MAC, 0x0 )
             , OBJECT_NAME(@@PROCID)
             , 'Error'    
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
        IF @@NESTLEVEL > 1
          THROW;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).GetPortableSymmetricKey
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).SavePrivateValue') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).SavePrivateValue
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: save a value to namevalues encrypted by a private passphrase 
--      privately encrypted value is fed to AddNameValue
--      by default, phrase and clear text value are not persisted      
--      to save private data in the audit trail specify 
--          @AuditPrivateData = 1 
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).SavePrivateValue 
 ( @Name NVARCHAR(448) 
 , @Value VARBINARY(8000) 
 , @EncryptionPhrase VARBINARY(8000) 
 , @AuditPrivateData TINYINT = 0 ) -- tiny because formatmessage does not speak BIT  
$(WITH_OPTIONS)
AS
BEGIN 
DECLARE @DbName NVARCHAR(128)
      , @ErrorData VARBINARY(8000)  
      , @Id NCHAR(36) 
      , @MAC VARBINARY(128) 
      , @Parameters VARBINARY(8000)
      , @ReturnCode INT
      , @tvp NAMEVALUETYPE
      , @Version INT;
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)' )
                                  , FORMATMESSAGE( '@Name = ''%s'', @Value = ''%s'', @PrivatePhrase = ''%s'', @AuditPrivateData = %d'
                                                 , @Name
												                         , CASE WHEN @AuditPrivateData = 1 
                                                        THEN @Value
                                                        ELSE N'**PRIVATE DATA NOT AUDITED**'
                                                        END
												                         , CASE WHEN @AuditPrivateData = 1 
                                                        THEN @EncryptionPhrase
                                                        ELSE N'**PRIVATE DATA NOT AUDITED**'
                                                        END
												                         , @AuditPrivateData ) 
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS 
        ( SELECT *
          FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
          WHERE Id = @Id
          AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
          AND ObjectName = OBJECT_NAME(@@PROCID) 
          AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)' )
                                , CAST(CHECKSUM( Id
                                                , @@PROCID   
                                                , ObjectName
                                                , @Parameters
                                                , KeyGuid
                                                , Status ) AS NVARCHAR(128) )
                                    , @MAC ) = 1 )  
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    SET @Value = ENCRYPTBYPASSPHRASE( CAST( DECRYPTBYKEY( @EncryptionPhrase ) AS NVARCHAR(128) )
                                    , CAST( DECRYPTBYKEY ( @Value ) AS NVARCHAR(128) ) )  
    INSERT @tvp 
      ( Name
      , Value ) 
    SELECT ENCRYPTBYKEY( KEY_GUID( '$(NAME_SYMMETRIC_KEY)' )
                       , CAST( ISNULL( @Name
                                     , REPLACE(ORIGINAL_LOGIN(), '\','$') ) 
                             + '.Private' AS NVARCHAR(128) ) 
                       , 1
                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) )
         , ENCRYPTBYKEY( KEY_GUID( '$(VALUE_SYMMETRIC_KEY)' ) 
                       , CAST( DECRYPTBYKEY ( @Value ) AS NVARCHAR(128) )
                       , 1
                       , @Name );                    
    EXEC $(EHA_SCHEMA).AddNameValue @tvp, @Version OUTPUT;   
    RAISERROR($(MESSAGE_OFFSET)10,0,0, @Name, @Version);
    INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    SELECT @Id
         , @MAC
         , OBJECT_NAME(@@PROCID)
         , 'Complete' 
    FROM @tvp;    
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
         ( Id
         , MAC 
         , Action
         , Status 
         , ErrorData)
        SELECT @Id
             , ISNULL( @MAC, 0x0 )
             , OBJECT_NAME(@@PROCID)
             , 'Error'    
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
        IF @@NESTLEVEL > 1
          THROW;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).SavePrivateValue
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).GetPrivateValue') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).GetPrivateValue
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: get value by name then decrypt with a passphrase 
--      by default private encryption phrase and clear value are not saved
--      to the audit trail. to save to audit trail specify
--          @AuditPrivateData = 1
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).GetPrivateValue 
 ( @Name NVARCHAR(448) 
 , @PrivatePhrase NVARCHAR(128)
 , @AuditPrivateData TINYINT = 0 -- formatmessage does not speak BIT  
 , @Value NVARCHAR(128) OUTPUT )  
$(WITH_OPTIONS)              
AS
BEGIN 
DECLARE @DbName NVARCHAR(128)
      , @ErrorData VARBINARY(8000)  
      , @Id NCHAR(36)
      , @MAC VARBINARY(128) 
      , @Parameters VARBINARY(8000)
      , @ReturnCode INT
      , @tvp NAMEVALUETYPE
      , @Version INT;
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)' )
                                  , FORMATMESSAGE( '@Name = ''%s'', @PrivatePhrase = ''%s'', @AuditPrivateData = %d'
                                                 , @Name
												 , CASE 
                                                   WHEN @AuditPrivateData = 1 
                                                   THEN @PrivatePhrase
                                                   ELSE N'**PRIVATE DATA NOT AUDITED**'
                                                   END
												 , @AuditPrivateData ) 
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS 
        ( SELECT *
          FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
          WHERE Id = @Id
          AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
          AND ObjectName = OBJECT_NAME(@@PROCID) 
          AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)' )
                                , CAST(CHECKSUM( Id
                                                , @@PROCID   
                                                , ObjectName
                                                , @Parameters
                                                , KeyGuid
                                                , Status ) AS NVARCHAR(128) )
                                    , @MAC ) = 1 )  
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    INSERT @tvp (Name, Value) 
    EXEC $(EHA_SCHEMA).SelectNameValue @Name;
    SELECT Name 
         , CAST( DECRYPTBYPASSPHRASE( @PrivatePhrase
                                    , LEFT( Value
                                          , LEN(Value) - LEN('.Private') ) ) AS NVARCHAR(128) ) AS Value 
    FROM (SELECT Name
               , CAST( DECRYPTBYKEY( Value, 1, @Name) AS NVARCHAR(448) ) AS Value 
          FROM @tvp) AS derived
     INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    SELECT @Id
         , @MAC
         , OBJECT_NAME(@@PROCID)
         , 'Complete' 
    FROM @tvp;    
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
         ( Id
         , MAC 
         , Action
         , Status 
         , ErrorData)
        SELECT @Id
             , ISNULL( @MAC, 0x0 )
             , OBJECT_NAME(@@PROCID)
             , 'Error'    
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
        IF @@NESTLEVEL > 1
          THROW;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).GetPrivateValue
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
------------------------
--backup/restsore procs
------------------------
IF OBJECT_ID ('$(EHA_SCHEMA).BackupServiceMasterKey') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).BackupServiceMasterKey
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: backup the service master key of the SQL Server Instance
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).BackupServiceMasterKey 
 ( @BackupPhrase VARBINARY(8000) 
 , @UseHash TINYINT = 0    -- use Name (0) or NameBucket (1) as the file name
 , @ForceNew TINYINT = 0 ) -- backup even if crypto object already in archive
$(WITH_OPTIONS)
AS
BEGIN 
DECLARE @ActionType NVARCHAR(10) = 'Backup'
      , @BackupDDL NVARCHAR(MAX)
      , @BackupName VARBINARY(8000)
      , @BackupNameBucket INT
      , @BackupPath VARBINARY(8000)
      , @BackupPhraseName NVARCHAR(448)
      , @BackupPhraseVersion SMALLINT
      , @CipherType NCHAR(2)
      , @Colophon INT
      , @DbName NVARCHAR(128) = 'master'
      , @Edition SMALLINT = 1
      , @ErrorData VARBINARY(8000)  
      , @Id NCHAR(36)
      , @MAC VARBINARY(128) 
      , @Node HIERARCHYID
      , @NodeName NVARCHAR(128) = 'Service Master Key'
      , @ObjectInfoDDL NVARCHAR(512)
      , @Parameters VARBINARY(8000)
      , @ParentName NVARCHAR(128) = 'root'
      , @ReturnCode INT
      , @tvp NAMEVALUETYPE;
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)' )
                                  , FORMATMESSAGE( '@BackupPhrase = %#x' 
								                                 + ', @UseHash = %d' 
												                         + ', @ForceNew = %d'
                                                 , @BackupPhrase
                                                 , @UseHash
                                                 , @ForceNew )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)' )
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    -- DMK and File, Name & Value certs opened by successful book so OK to set encrypted values now 
    SET @Node = $(EHA_SCHEMA).GetNode ( @NodeName, @DbName, @@SERVERNAME )
    SET @BackupName = $(EHA_SCHEMA).NewMasterKeyBackupName( @NodeName );
    SELECT @BackupNameBucket =  $(EHA_SCHEMA).AddSalt( '$(EHDB)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'BackupNameBucket' 
                                                     , Word )
    FROM ( SELECT CAST( DECRYPTBYKEY( @BackupName ) AS NVARCHAR(128) ) AS Word ) AS derived;
    SET @BackupPath = $(EHA_SCHEMA).BackupPath(@DbName);
    SET @ObjectInfoDDL = FORMATMESSAGE( $(MESSAGE_OFFSET)22
                                      , FORMATMESSAGE( $(MESSAGE_OFFSET)21
                                                     , '$(EHDB)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'Colophon'
                                                     , 'key_guid' ) 
                                      , @DbName
                                      ,'##MS_ServiceMasterKey##' );
    EXEC @ReturnCode = sp_executesql @ObjectInfoDDL
                                   , N'@CipherType NCHAR(2) OUTPUT, @Colophon INT OUTPUT'
                                   , @CipherType OUTPUT
                                   , @Colophon OUTPUT;
    IF (SELECT TOP(1) Colophon
        FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
        WHERE ServerName = @@SERVERNAME
        AND Action = OBJECT_NAME(@@PROCID)
        AND Status = 'Complete'
        ORDER BY CreateUTCDT DESC ) = @Colophon   
      BEGIN
        IF @ForceNew <> 1
          RAISERROR($(MESSAGE_OFFSET)38, 16, 1, @DbName, @NodeName ); 
        ELSE
          SET @Edition = 1 
                       + (SELECT MAX(Edition)
                          FROM  $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
                          WHERE ServerName = @@SERVERNAME
                          AND Action = OBJECT_NAME(@@PROCID)
                          AND Status = 'Complete'
                          AND Colophon = @Colophon );
      END   
    INSERT @tvp 
      ( Name
      , Value) 
    SELECT EncryptedName
         , ENCRYPTBYKEY( KEY_GUID('$(VALUE_SYMMETRIC_KEY)')
                       , CAST( DECRYPTBYKEY( @BackupPhrase ) AS NVARCHAR(128) ) -- #SessionKey
                       , 1
                       , CAST( DECRYPTBYKEY( EncryptedName
                                           , 1
                                           , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) ) 
                              AS NVARCHAR(448) ) ) 
    FROM (SELECT $(EHA_SCHEMA).GetEHPhraseName( @DbName
                                              , @NodeName
                                              , @ActionType ) AS EncryptedName ) AS derived
    EXEC $(EHA_SCHEMA).AddNameValue @tvp, @BackupPhraseVersion OUTPUT;   
    SELECT @BackupDDL = FORMATMESSAGE ( $(MESSAGE_OFFSET)25
                                      , CAST( DECRYPTBYKEY( @BackupPath
                                                          , 1
                                                          , @DbName ) AS NVARCHAR(1024) ) 
                                     , CASE WHEN @UseHash = 1 
                                            THEN CAST( @BackupNameBucket AS NVARCHAR(448) ) 
                                            ELSE CAST( DECRYPTBYKEY( @BackupName ) AS NVARCHAR(448) )  
                                            END    
                                      , '$(MASTER_KEY_BACKUP_EXT)'
                                      , CAST( DECRYPTBYKEY( Value
                                                          , 1
                                                          , CAST( DECRYPTBYKEY( Name ) AS NVARCHAR(448) )
                                                           ) AS NVARCHAR(128) ) ) 
    FROM @tvp;       
    EXEC @ReturnCode = sp_executesql @BackupDDL;
    IF @ReturnCode <> 0
      RAISERROR($(MESSAGE_OFFSET)12, 16, 1, @NodeName, '', '', '', @ActionType, @ReturnCode );
    ELSE
      RAISERROR($(MESSAGE_OFFSET)11, 0, 0, @NodeName, '', '', '', @ActionType );
    INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
      ( Id
      , DbName
      , Node
      , NodeName
      , BackupName
      , BackupNameBucket
      , UseHash
      , BackupPath
      , BackupPhraseVersion 
      , Action
      , Status
      , Colophon
      , Edition
      , MAC
      , CipherType )
    VALUES ( @Id
           , @DbName
           , @Node
           , @NodeName
           , @BackupName
           , @BackupNameBucket
           , @UseHash 
           , @BackupPath
           , @BackupPhraseVersion
           , OBJECT_NAME(@@PROCID)
           , 'Complete'
           , @Colophon
           , @Edition
           , @MAC
           , @CipherType );  
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
          ( Id
          , DbName
          , Node
          , NodeName
          , BackupName
          , BackupNameBucket
          , UseHash
          , BackupPath 
          , BackupPhraseVersion
          , Action
          , Status
          , Colophon
          , Edition
          , MAC
          , CipherType
          , ErrorData )
        SELECT @Id 
             , ISNULL( @DbName, '' )
	           , @Node
             , ISNULL( @NodeName, '' ) 
             , ISNULL( @BackupName, 0x0 ) 
             , ISNULL( @BackupNameBucket, 0 )
             , @UseHash 
             , ISNULL( @BackupPath, 0x0 )
             , ISNULL( @BackupPhraseVersion, 0 ) 
             , OBJECT_NAME( @@PROCID )
             , 'Error'
             , ISNULL( @Colophon, 0 )
             , ISNULL( @Edition, 0 )
             , ISNULL( @MAC, 0x0 )
             , ISNULL( @CipherType, '' )
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;  
      END
  END CATCH 
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).BackupServiceMasterKey
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).RestoreServiceMasterKey') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).RestoreServiceMasterKey
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: restore the service master key of the SQL Server Instance from backup
--    ASSERT: SMK is a symmetric key in master named "##MS_ServiceMasterKey##"
--    Restore implicitly regenerates the underlying hierarchy nodes   
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).RestoreServiceMasterKey 
  ( @IdToRestore NCHAR(36) = NULL   -- default is most recent
  , @ForceReplace TINYINT = 0 )     -- if 1 restore even if data loss  
$(WITH_OPTIONS)
AS
BEGIN 
DECLARE @ActionType NVARCHAR(10) = 'Restore'
      , @BackupName VARBINARY(8000)
      , @BackupNameBucket INT
      , @BackupPath VARBINARY(8000)
      , @BackupPhraseName VARBINARY(8000) 
      , @BackupPhraseVersion SMALLINT 
      , @Backuptvp NAMEVALUETYPE
      , @Colophon INT
      , @ColophonOld INT
      , @Edition SMALLINT
      , @ErrorData VARBINARY(8000)
      , @DbName NVARCHAR(128) = 'master'
      , @Node HIERARCHYID
      , @NodeName NVARCHAR(128) = 'Service Master Key'
      , @CipherType NCHAR(2)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128)
      , @ObjectInfoDDL NVARCHAR(512)
      , @Parameters VARBINARY(8000)
      , @RestoreDDL NVARCHAR(MAX)
      , @ReturnCode INT
      , @UseHash TINYINT;
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@IdToRestore = %d, @ForceRestore = %d'
                                                 , @IdToRestore
                                                 , @ForceReplace )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS  ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                     WHERE Id = @Id
                     AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                     AND ObjectName = OBJECT_NAME(@@PROCID) 
                     AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                           , CAST(CHECKSUM( Id
                                                          , @@PROCID   
                                                          , ObjectName
                                                          , @Parameters
                                                          , KeyGuid
                                                          , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    SET @BackupPhraseName = $(EHA_SCHEMA).GetEHPhraseName( @DbName
                                                         , @NodeName
                                                         , @ActionType );

    INSERT @Backuptvp (Name, Value) 
    EXEC $(EHA_SCHEMA).SelectNameValue @BackupPhraseName;
    SELECT TOP(1) @BackupName = k.BackupName
                , @BackupNameBucket = k.BackupNameBucket
                , @UseHash = k.UseHash  
                , @BackupPath = k.BackupPath
                , @BackupPhraseVersion = k.BackupPhraseVersion
                , @ColophonOld = k.Colophon
                , @Edition = k.Edition
                , @Node = k.Node  
                , @CipherType = k.CipherType                
                , @RestoreDDL = 
                    FORMATMESSAGE ( $(MESSAGE_OFFSET)12  
                                  , @DbName   
                                  , CAST( DecryptByKey( k.BackupPath
                                                      , 1
                                                      , @DbName ) AS NVARCHAR(1024) ) 
                                   , CASE WHEN @UseHash = 1 
                                          THEN CAST( @BackupNameBucket AS NVARCHAR(448) ) 
                                          ELSE CAST( DECRYPTBYKEY( @BackupName ) AS NVARCHAR(448) )  
                                          END    
                                  , '$(MASTER_KEY_BACKUP_EXT)''' 
                                  , CAST( DECRYPTBYKEY( b.Value
                                                      , 1
                                                      , CAST ( DECRYPTBYKEY( b.Name ) 
                                                              AS NVARCHAR(448) ) 
                                                        ) AS NVARCHAR(128) ) 
                                  , CASE WHEN @ForceReplace = 1 
                                          THEN 'FORCE' 
                                          ELSE '' END ) 
    FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) k
    CROSS JOIN @Backuptvp b
    WHERE ServerName = CASE WHEN @IdToRestore IS NULL 
                            THEN @@SERVERNAME 
                            ELSE ServerName END 
    AND k.DbName = @DbName
    AND k.NodeName = @NodeName
    AND k.Action = REPLACE(OBJECT_NAME(@@PROCID), @ActionType, 'Backup' )
    AND k.Status = 'Complete'
    AND k.Id = ISNULL(@IdToRestore, k.Id)
    AND (k.ServerName = @@SERVERNAME OR @IdToRestore IS NOT NULL)  
    ORDER BY CreateUTCDT DESC;
    EXEC @ReturnCode = sp_executesql @RestoreDDL;
    IF @ReturnCode <> 0 or @MAC IS NULL
      RAISERROR($(MESSAGE_OFFSET)12,16,1,@NodeName,'','','', @ActionType, @ReturnCode);
    ELSE
      RAISERROR($(MESSAGE_OFFSET)11,0,0,@NodeName,'','','', @ActionType);
    SET @ObjectInfoDDL = FORMATMESSAGE( $(MESSAGE_OFFSET)22
                                      , FORMATMESSAGE( $(MESSAGE_OFFSET)21
                                                     , '$(EHDB)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'Colophon'
                                                     , 'key_guid' )
                                      , @DbName                
                                      ,'##MS_ServiceMasterKey##' );
    EXEC sp_executesql @ObjectInfoDDL
                     , N'@CipherType NCHAR(2) OUTPUT, @Colophon INT OUTPUT'
                     , @CipherType OUTPUT 
                     , @Colophon OUTPUT;
    -- if the Colophon is unchanged increment the Edition
    IF @Colophon = @ColophonOld
      SET @Edition = 1 
                   + (SELECT MAX(Edition)
                      FROM  $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
                      WHERE ServerName = @@SERVERNAME
                      AND Action = OBJECT_NAME(@@PROCID)
                      AND Status = 'Complete'
                      AND NodeName = @NodeName
                      AND Colophon = @Colophon );
    INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
      ( Id
      , DbName
      , Node
      , NodeName
      , BackupName
      , BackupNameBucket
      , UseHash
      , BackupPath
      , BackupPhraseVersion 
      , Action
      , Status
      , Colophon
      , Edition
      , MAC
      , CipherType )
    SELECT @Id 
      , @DbName
      , @Node
      , @NodeName
      , @BackupName
      , @BackupNameBucket
      , @UseHash
      , @BackupPath
      , @BackupPhraseVersion
      , OBJECT_NAME(@@PROCID)
      , 'Complete'
      , @Colophon
      , @Edition 
      , @MAC 
      , @CipherType;
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
          ( Id
          , DbName
          , Node 
          , NodeName
          , BackupName
          , BackupNameBucket
          , UseHash
          , BackupPath
          , BackupPhraseVersion 
          , Action
          , Status
          , Colophon
          , Edition
          , MAC
          , CipherType
          , ErrorData)
        SELECT @Id 
             , ISNULL( @DbName, '' )
             , ISNULL( @Node, 0x0 )
             , ISNULL( @NodeName, 'Service Master Key' )
             , ISNULL( @BackupName, 0x0 )             
             , ISNULL( @BackupNameBucket, 0 )
             , ISNULL( @UseHash, 0 )  
             , ISNULL( @BackupPath, 0x0 )
             , ISNULL( @BackupPhraseVersion,0 )
             , OBJECT_NAME(@@PROCID)
             , 'Error'
             , ISNULL( @Colophon,0 )
             , ISNULL( @Edition,0 )
             , ISNULL( @MAC,0x0 )
             , ISNULL( @CipherType, '' ) 
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
         CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH 
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).RestoreServiceMasterKey
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).BackupDatabaseMasterKey') IS NOT NULL
  DROP PROCEDURE $(EHA_SCHEMA).BackupDatabaseMasterKey
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: backup a database master key
--    ASSERT: DMK is a symmetric key in the db named "##MS_DatabaseMasterKey##"
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).BackupDatabaseMasterKey 
  ( @DbName NVARCHAR(128)
  , @BackupPhrase VARBINARY(8000)
  , @KeyPhrase VARBINARY(8000) = NULL -- specify NULL or DEFAULT if no encryption PHRASE used 
  , @UseHash TINYINT = 0              -- use BackupName (0) clear text or BackupNameBucket (1) value as file name
  , @ForceNew TINYINT = 0 )           -- if 1 backup even if key already on file
$(WITH_OPTIONS)
AS
BEGIN 
DECLARE @ActionType NVARCHAR(10) = 'Backup'
    , @BackupDDL NVARCHAR(4000)
    , @BackupName VARBINARY(8000)
    , @BackupNameBucket INT
    , @BackupPath VARBINARY(8000)
    , @BackupPhraseVersion SMALLINT
    , @Backuptvp NAMEVALUETYPE
    , @Colophon INT
    , @Edition SMALLINT = 1
    , @CipherType NCHAR(2)
    , @Id NCHAR(36)
    , @KeyPhraseVersion SMALLINT
    , @Keytvp NAMEVALUETYPE
    , @MAC VARBINARY(128) 
    , @Node HIERARCHYID
    , @NodeName NVARCHAR(128) = 'Database Master Key'
    , @ObjectInfoDDL NVARCHAR(512)
    , @Parameters varbinary(8000)
    , @ParentName NVARCHAR(128) = 'Service Master Key'
    , @ReturnCode INT
    , @ErrorData VARBINARY(8000);
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@DbName = ''%s'',' 
                                                + '@BackupPhrase = ''%s, ' 
                                                + '@KeyPhrase = ''%s'', ' 
                                                + '@ForceNew = %d'
                                                , @DbName
                                                , CAST( DECRYPTBYKEY( @BackupPhrase ) AS NVARCHAR(128) )
                                                , CAST( DECRYPTBYKEY( @KeyPhrase ) AS NVARCHAR(128) )
                                                , @ForceNew )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    IF DB_ID(@DbName) IS NULL
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'Database', 'database not found');
    -- booking complete, keys open
    SET @Node = $(EHA_SCHEMA).GetNode ( @NodeName, @DbName, @@SERVERNAME )
    SET @ObjectInfoDDL = FORMATMESSAGE( $(MESSAGE_OFFSET)22
                                      , FORMATMESSAGE( $(MESSAGE_OFFSET)21
                                                     , '$(EHDB)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'Colophon'
                                                     , 'key_guid' )
                                      , @DbName                
                                      ,'##MS_DatabaseMasterKey##' );
    EXEC sp_executesql @ObjectInfoDDL
                     , N'@CipherType NCHAR(2) OUTPUT, @Colophon INT OUTPUT'
                     , @CipherType OUTPUT 
                     , @Colophon OUTPUT;
    IF (SELECT TOP(1) Colophon
        FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
        WHERE ServerName = @@SERVERNAME
        AND DbName = @DbName
        AND NodeName = @NodeName
        AND Action = OBJECT_NAME(@@PROCID)
        AND Status = 'Complete'
        ORDER BY CreateUTCDT DESC) = @Colophon   
      BEGIN
        IF @ForceNew <> 1
          RAISERROR($(MESSAGE_OFFSET)38, 16, 1, @DbName, @NodeName ); 
        ELSE
          SET @Edition = (SELECT MAX(Edition) + 1
                          FROM  $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
                          WHERE ServerName = @@SERVERNAME
                          AND Action = OBJECT_NAME(@@PROCID)
                          AND Status = 'Complete'
                          AND Colophon = @Colophon );
      END   
    INSERT @Backuptvp 
      ( Name
      , Value) 
    SELECT EncryptedName
         , ENCRYPTBYKEY( KEY_GUID('$(VALUE_SYMMETRIC_KEY)')
                       , CAST( DECRYPTBYKEY( @BackupPhrase ) AS NVARCHAR(128) ) -- #SessionKey
                       , 1
                       , CAST( DECRYPTBYKEY( EncryptedName
                                           , 1
                                           , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) ) 
                             AS NVARCHAR(448) ) ) 
    FROM (SELECT $(EHA_SCHEMA).GetEHPhraseName( @DbName
                                              , @NodeName
                                              , @ActionType ) AS EncryptedName ) AS derived;
    EXEC $(EHA_SCHEMA).AddNameValue @Backuptvp, @BackupPhraseVersion OUTPUT;   
    SET @BackupName = $(EHA_SCHEMA).NewMasterKeyBackupName( @DbName );
    SELECT @BackupNameBucket =  $(EHA_SCHEMA).AddSalt( '$(EHDB)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'BackupNameBucket' 
                                                     , BackupName )
    FROM ( SELECT CAST( DECRYPTBYKEY( @BackupName ) AS NVARCHAR(128) ) AS BackupName ) AS derived;
    SET @BackupPath = $(EHA_SCHEMA).BackupPath( @DbName ); 
    IF @KeyPhrase IS NOT NULL
      BEGIN
        INSERT @Keytvp 
          ( Name
          , Value) 
        SELECT EncryptedName
             , ENCRYPTBYKEY( KEY_GUID('$(VALUE_SYMMETRIC_KEY)')
                           , CAST( DECRYPTBYKEY( @KeyPhrase ) AS NVARCHAR(128) )
                           , 1
                           , CAST( DECRYPTBYKEY( EncryptedName 
                                               , 1
                                               , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)' ) AS NCHAR(36) ) ) 
                                  AS NVARCHAR(448) ) ) 
        FROM (SELECT $(EHA_SCHEMA).GetEHPhraseName( @DbName
                                                  , @NodeName
                                                  , 'Encryption' ) AS EncryptedName ) AS derived;
        EXEC $(EHA_SCHEMA).AddNameValue @Keytvp, @KeyPhraseVersion OUTPUT;
      END         
    SET @BackupDDL = ( SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)26
                                           , @DbName
                                           , CASE WHEN DB_NAME() <> @DbName 
                                                  AND @KeyPhrase IS NOT NULL
                                                  THEN FORMATMESSAGE ( $(MESSAGE_OFFSET)20
                                                                     , CAST( DECRYPTBYKEY( @KeyPhrase ) AS NVARCHAR(128) ) )
                                                  ELSE N'' END
                                           , CAST( DECRYPTBYKEY( @BackupPath, 1, @DbName ) AS NVARCHAR(1024) ) 
                                           , CASE WHEN @UseHash = 1 
                                                  THEN CAST( @BackupNameBucket AS NVARCHAR(448) ) 
                                                  ELSE CAST( DECRYPTBYKEY( @BackupName ) AS NVARCHAR(448) )  
                                                  END    
                                           , '$(MASTER_KEY_BACKUP_EXT)'
                                           , CAST( DECRYPTBYKEY( @BackupPhrase ) AS NVARCHAR(128) )
                                           , CASE WHEN DB_NAME() <> @DbName AND @KeyPhrase IS NOT NULL
                                                  THEN 'CLOSE MASTER KEY;'
                                                  ELSE '' END ) );
    EXEC @ReturnCode = sp_executesql @BackupDDL;
    IF @ReturnCode <> 0
      RAISERROR($(MESSAGE_OFFSET)12,16,1,'DATABASE', @DbName,'Master Key','', @ActionType, @ReturnCode);
    ELSE
      RAISERROR($(MESSAGE_OFFSET)11,0,0,'DATABASE', @DbName,'Master Key','', @ActionType);
    INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
      ( Id
      , DbName
      , Node
      , NodeName
      , BackupName
      , BackupNameBucket
      , UseHash
      , BackupPath 
      , BackupPhraseVersion
      , KeyPhraseVersion
      , Action
      , Status
      , Colophon
      , Edition
      , MAC
      , CipherType )
    VALUES ( @Id 
           , @DbName
           , @Node
           , @NodeName
           , @BackupName
           , @BackupNameBucket
           , @UseHash
           , @BackupPath
           , @BackupPhraseVersion
           , @KeyPhraseVersion
           , OBJECT_NAME(@@PROCID)
           , 'Complete'
           , @Colophon
           , @Edition
           , @MAC
           , @CipherType );
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
          ( Id
          , DbName
          , Node
          , NodeName
          , BackupName
          , BackupNameBucket
          , UseHash
          , BackupPath 
          , BackupPhraseVersion
          , KeyPhraseVersion
          , Action
          , Status
          , Colophon
          , Edition
          , MAC
          , CipherType
          , ErrorData)
        SELECT @Id 
             , @DbName
             , @Node
             , ISNULL( @NodeName, 'Database Master Key' )
             , ISNULL( @BackupName, 0x0 )             
             , ISNULL( @BackupNameBucket, 0 )
             , ISNULL( @UseHash, 0 ) 
             , ISNULL( @BackupPath, 0x0 )
             , ISNULL( @BackupPhraseVersion, 0 )
             , ISNULL( @KeyPhraseVersion, 0 )
             , OBJECT_NAME(@@PROCID)
             , 'Error'
             , ISNULL( @Colophon, 0 )
             , ISNULL( @Edition, 0 )
             , ISNULL( @MAC, 0x0 )
             , ISNULL( @CipherType, '' )
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH 
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).BackupDatabaseMasterKey
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).RestoreDatabaseMasterKey') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).RestoreDatabaseMasterKey
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: restore a database master key from a backup
--  ASSERT: DMK is a symmetric key in the db named "##MS_DatabaseMasterKey##"
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).RestoreDatabaseMasterKey 
 ( @DbName NVARCHAR(128) 
 , @IdToRestore NCHAR(36) = NULL  -- if null use most recent
 , @ForceReplace TINYINT = 0 )    -- if 1 restore even if data loss
$(WITH_OPTIONS) 
AS
BEGIN 
DECLARE @ActionType NVARCHAR(10) = 'Restore'
      , @BackupName VARBINARY(8000)
      , @BackupNameBucket INT
      , @BackupPath VARBINARY(8000)
      , @BackupPhrase NVARCHAR(128) 
      , @BackupPhraseName NVARCHAR(448)
      , @BackupPhraseVersion SMALLINT
      , @Backuptvp NAMEVALUETYPE
      , @CipherType NCHAR(2)
      , @Colophon INT
      , @ColophonOld INT
      , @DMKRestoreDDL NVARCHAR(2048)
      , @DMKtvp NAMEVALUETYPE
      , @Edition SMALLINT
      , @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @KeyPhraseName NVARCHAR(448)
      , @KeyPhraseVersion SMALLINT
      , @Keytvp NAMEVALUETYPE 
      , @MAC VARBINARY(128)
      , @Node HIERARCHYID
      , @NodeName NVARCHAR(128) = 'Database Master Key'
      , @ObjectInfoDDL NVARCHAR(512)
      , @Parameters VARBINARY(8000)
      , @ReturnCode INT
      , @UseHash TINYINT;
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@DbName = ''%s'',' 
                                                + '@IdToRestore = %d,' 
                                                + '@ForceReplace = %d'
                                                , @DbName
                                                , @IdToRestore
                                                , @ForceReplace)
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    IF DB_ID(@DbName) IS NULL
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'@DbName', 'database not found');
    SELECT TOP (1)  @BackupName = BackupName 
                  , @BackupNameBucket = BackupNameBucket
                  , @BackupPath = BackupPath
                  , @BackupPhraseVersion = BackupPhraseVersion
                  , @Node = @Node
                  , @CipherType = CipherType
                  , @ColophonOld = Colophon
                  , @KeyPhraseVersion = KeyPhraseVersion
                  , @UseHash = UseHash 
    FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
    WHERE ServerName = CASE WHEN @IdToRestore IS NULL 
                            THEN @@SERVERNAME 
                            ELSE ServerName END 
    AND DbName = CASE WHEN @IdToRestore IS NULL 
                            THEN @DbName 
                            ELSE DbName END 
    AND NodeName = @NodeName
    AND Action = REPLACE( OBJECT_NAME(@@PROCID) , @ActionType, 'Backup' )
    AND Status = 'Complete'
    AND Id = ISNULL(@IdToRestore, Id)
    ORDER BY CreateUTCDT DESC;  
    SET @BackupPhraseName = $(EHA_SCHEMA).GetEHPhraseName( @DbName, @NodeName, 'Backup' );
    INSERT @Backuptvp (Name, Value)
    EXEC $(EHA_SCHEMA).SelectNameValue @BackupPhraseName, @BackupPhraseVersion;
    SET @KeyPhraseName = $(EHA_SCHEMA).GetEHPhraseName( @DbName, @NodeName, 'Encryption' );
    INSERT @Keytvp (Name, Value)
    EXEC $(EHA_SCHEMA).SelectNameValue @KeyPhraseName, @KeyPhraseVersion;
    SET @DMKRestoreDDL = 'USE ' + @DbName + ';'; 
    -- DMK encrypted by password must be explicitly opened (passphrase must already be on file)
    IF @CipherType = 'PW'
      BEGIN
        INSERT @DMKtvp (Name, Value)
        EXEC $(EHA_SCHEMA).SelectNameValue @KeyPhraseName, NULL;
        SET @DMKRestoreDDL += ( SELECT 'OPEN MASTER KEY' + SPACE(1)  
                                     + 'DECRYPTION BY PASSWORD = ''' 
                                     + CAST( DECRYPTBYKEY( Value
                                                          , 1
                                                          , CAST ( DECRYPTBYKEY( Name ) 
                                                                  AS NVARCHAR(448) ) 
                                                          ) AS NVARCHAR(128) ) + ''''
                                FROM @DMKtvp );
      END                          
    SET @DMKRestoreDDL += 
        (SELECT 'RESTORE MASTER KEY' + SPACE(1)
              + 'FROM FILE = ''' 
              + CAST(DecryptByKey(@BackupPath, 1, @DbName ) AS NVARCHAR(1024)) 
              + CASE WHEN @UseHash = 1 
                    THEN CAST( @BackupNameBucket AS NVARCHAR(448) ) 
                    ELSE CAST( DECRYPTBYKEY( @BackupName ) AS NVARCHAR(448) )  
                    END    
              + '$(MASTER_KEY_BACKUP_EXT)''' + SPACE(1)
              + 'DECRYPTION BY PASSWORD = ''' + CAST( DECRYPTBYKEY( b.Value
                                                                  , 1
                                                                  , CAST ( DECRYPTBYKEY( b.Name ) 
                                                                          AS NVARCHAR(448) ) 
                                                                  ) AS NVARCHAR(128) ) + '''' + SPACE(1)
              + CASE WHEN @CipherType IN ('PW','SP') 
                     THEN  'ENCRYPTION BY PASSWORD = ''' + CAST( DECRYPTBYKEY( k.Value
                                                               , 1
                                                               , CAST ( DECRYPTBYKEY( b.Name ) 
                                                                          AS NVARCHAR(448) )
                                                               ) AS NVARCHAR(128) ) + '''' + SPACE(1)

                     ELSE ''  END
              + CASE WHEN @ForceReplace = 1 THEN SPACE(1) + 'FORCE;' ELSE ';' END       
              + 'OPEN MASTER KEY DECRYPTION BY PASSWORD = ''' 
              + 'DECRYPTION BY PASSWORD = ''' + CAST( DECRYPTBYKEY( b.Value
                                                                  , 1
                                                                  , CAST ( DECRYPTBYKEY( b.Name ) 
                                                                          AS NVARCHAR(448) ) 
                                                                  ) AS NVARCHAR(128) ) + ''';'
         FROM @Backuptvp b
         CROSS JOIN @Keytvp k ); 
    EXEC @ReturnCode = sp_executesql @DMKRestoreDDL;
    IF @ReturnCode <> 0 
      RAISERROR($(MESSAGE_OFFSET)12, 16, 1, 'DATABASE', @DbName, @NodeName, '', @ActionType, @ReturnCode );
    ELSE
      RAISERROR($(MESSAGE_OFFSET)11, 0, 0, 'DATABASE', @DbName, @NodeName, '', @ActionType );
    -- @CipherType can be blank if encryption type not in ESKM, ESKP is it true???
    SET @ObjectInfoDDL = FORMATMESSAGE( $(MESSAGE_OFFSET)22
                                      , FORMATMESSAGE( $(MESSAGE_OFFSET)21
                                                     , '$(EHDB)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'Colophon'
                                                     , 'key_guid' ) 
                                      , @DbName
                                      ,'##MS_DatabaseMasterKey##' );
    EXEC sp_executesql @ObjectInfoDDL
                     , N'@CipherType NCHAR(2) OUTPUT, @Colophon INT OUTPUT'
                     , @CipherType OUTPUT
                     , @Colophon OUTPUT;
    -- if guid of symmetric key not changed, rev the Edition 
    IF @Colophon = @ColophonOld
      SET @Edition = (SELECT MAX(Edition) + 1
                      FROM  $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
                      WHERE ServerName = @@SERVERNAME
                      AND Action = OBJECT_NAME(@@PROCID)
                      AND Status = 'Complete'
                      AND NodeName = @NodeName
                      AND Colophon = @Colophon );
    INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
      ( Id
      , DbName
      , Node
      , NodeName
      , BackupName
      , BackupNameBucket
      , UseHash
      , BackupPath
      , BackupPhraseVersion
      , KeyPhraseVersion 
      , Action
      , Status
      , Colophon
      , Edition
      , MAC
      , CipherType )
    VALUES ( @Id
           , @DbName
           , @Node
           , @NodeName
           , @BackupName
           , @BackupNameBucket
           , @UseHash 
           , @BackupPath
           , @BackupPhraseVersion
           , @KeyPhraseVersion 
           , OBJECT_NAME(@@PROCID)
           , 'Complete'
           , @Colophon
           , @Edition
           , @MAC
           , @CipherType );
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
          ( Id
          , DbName
          , Node
          , NodeName
          , BackupName
          , BackupNameBucket
          , UseHash
          , BackupPath 
          , BackupPhraseVersion
          , KeyPhraseVersion 
          , Action
          , Status
          , Colophon
          , Edition
          , MAC
          , CipherType
          , ErrorData )
        SELECT @Id 
             , ISNULL(@DbName,'')
             , @Node
		         , @NodeName
             , ISNULL( @BackupName, 0x0 )             
             , ISNULL( @BackupNameBucket, 0 )
             , ISNULL( @UseHash, 0 ) 
             , ISNULL( @BackupPath, 0x0 )
             , ISNULL( @BackupPhraseVersion, 0 )
             , ISNULL( @KeyPhraseVersion, 0 ) 
		         , OBJECT_NAME(@@PROCID)
		         , 'Error'
             , ISNULL( @Colophon, 0)
             , ISNULL( @Edition, 0)
             , ISNULL( @MAC, 0x0)
             , ISNULL( @CipherType, '')
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                         , ERROR_NUMBER()
                                         , ERROR_SEVERITY()
                                         , ERROR_STATE()
                                         , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                         , ERROR_LINE()
                                         , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH 
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).RestoreDatabaseMasterKey
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).BackupCertificate') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).BackupCertificate
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: backup a certificate  
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).BackupCertificate 
 ( @CertificateName NVARCHAR(128)
 , @DbName NVARCHAR(128) 
 , @BackupPhrase VARBINARY(8000) = NULL -- use stored value if exists 
 , @KeyPhrase VARBINARY(8000) = NULL    -- value needed only when type = PW
 , @UseHash BIT = 0                 -- use BackupName (0) clear text or BackupNameBucket (1) as file name
 , @ForceNew BIT = 0 )              -- if 1 backup even if backup of this uniquely identified key already on file
$(WITH_OPTIONS)
AS
BEGIN 
DECLARE @CertificateList TABLE (name NVARCHAR(128), thumbprint VARBINARY(36));
DECLARE @ActionType NVARCHAR(10) = 'Backup'
      , @BackupDDL NVARCHAR(MAX)
      , @BackupName VARBINARY(8000)
      , @BackupNameBucket INT
      , @BackupPath VARBINARY(8000)
      , @BackupPhraseVersion SMALLINT
      , @Backuptvp NAMEVALUETYPE
      , @CertificateListDDL NVARCHAR(256)
      , @Colophon INT
      , @CipherType NCHAR(2)
      , @DMKPhraseName VARBINARY(8000)
      , @DMKtvp NAMEVALUETYPE
      , @Edition SMALLINT = 1
      , @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @KeyPhraseVersion SMALLINT
      , @Keytvp NAMEVALUETYPE
      , @LastEHChild HIERARCHYID
      , @MAC VARBINARY(128)  
      , @Node HIERARCHYID  
      , @ObjectInfoDDL NVARCHAR(512)
      , @Parameters VARBINARY(8000)
      , @ParentName NVARCHAR(128) = 'Database Master Key' 
      , @ReturnCode INT;
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@CertificateName = ''%s''' 
								                                 + ', @DbName ''%s''' 
 												                         + ', @BackupPhrase ''%s''' 
												                         + ', @KeyPhrase ''%s''' 
												                         + ', @UseHash = %d' 
												                         + ', @ForceNew = %d'
                                                 , @CertificateName
                                                 , @DbName
                                                 , CAST ( DECRYPTBYKEY( @BackupPhrase ) AS NVARCHAR(128) )
                                                 , CAST ( DECRYPTBYKEY( @KeyPhrase ) AS NVARCHAR(128) )
												                         , IIF( @UseHash = 1, 1, 0 )
                                                 , IIF( @ForceNew = 1, 1, 0 ) )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR( $(MESSAGE_OFFSET)34, 16, 1, @@PROCID, @Id );
    -- Booking complete, keys open
    SET @Node = $(EHA_SCHEMA).GetNode ( @CertificateName, @DbName, @@SERVERNAME )
    -- verify @DbName and @CertificateName by using before parsing into query string 
    IF DB_ID(@DbName) IS NOT NULL   
      BEGIN
        SET @CertificateListDDL = 'SELECT name from ' + @DbName + '.sys.certificates'
        INSERT @CertificateList (name)    
        EXEC sp_executesql @CertificateListDDL;
      END
    -- @CertificateName is used in where clause first to stop any sql injection
    IF NOT EXISTS (SELECT name FROM @CertificateList WHERE name = @CertificateName)
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'Certificate', 'certificate not found');
    SET @ObjectInfoDDL = FORMATMESSAGE( $(MESSAGE_OFFSET)23
                                      , FORMATMESSAGE( $(MESSAGE_OFFSET)21
                                                     , '$(EHDB)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'Colophon'
                                                     , 'thumbprint' ) 
                                      , @DbName   
                                      , @CertificateName );
    EXEC sp_executesql @ObjectInfoDDL
               , N'@CertificateName NVARCHAR(128), @CipherType NCHAR(2) OUTPUT, @Colophon INT OUTPUT'
               , @CertificateName, @CipherType OUTPUT, @Colophon OUTPUT;
    IF (SELECT TOP(1) Colophon
        FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
        WHERE ServerName = @@SERVERNAME
        AND DbName = @DbName
        AND NodeName =  @CertificateName
        AND Action = OBJECT_NAME(@@PROCID)
        AND Status = 'Complete'
        ORDER BY CreateUTCDT DESC) = @Colophon   
      BEGIN
        IF @ForceNew <> 1
          RAISERROR($(MESSAGE_OFFSET)38, 16, 1, @DbName, @CertificateName ); 
        ELSE
          SET @Edition = (SELECT MAX(Edition) + 1
                          FROM  $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
                          WHERE ServerName = @@SERVERNAME
                          AND Action = OBJECT_NAME(@@PROCID)
                          AND Status = 'Complete'
                          AND Colophon = @Colophon );
      END   
    INSERT @Backuptvp 
      ( Name
      , Value) 
    SELECT EncryptedName
         , ENCRYPTBYKEY( KEY_GUID('$(VALUE_SYMMETRIC_KEY)')
                       , CAST( DECRYPTBYKEY( @BackupPhrase ) AS NVARCHAR(128) ) -- #SessionKey
                       , 1
                       , CAST( DECRYPTBYKEY( EncryptedName 
                                           , 1
                                           , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) ) 
                             AS NVARCHAR(448) ) ) 
    FROM (SELECT $(EHA_SCHEMA).GetEHPhraseName( @DbName
                                              , @CertificateName
                                              , @ActionType ) AS EncryptedName ) AS derived;
    EXEC $(EHA_SCHEMA).AddNameValue @Backuptvp, @BackupPhraseVersion OUTPUT;   
    IF @KeyPhrase IS NOT NULL
      BEGIN
        INSERT @Keytvp 
          ( Name
          , Value) 
        SELECT EncryptedName
             , ENCRYPTBYKEY( KEY_GUID('$(VALUE_SYMMETRIC_KEY)')
                           , CAST( DECRYPTBYKEY( @KeyPhrase ) AS NVARCHAR(128) ) -- #SessionKey
                           , 1
                           , CAST( DECRYPTBYKEY( EncryptedName 
                                               , 1
                                               , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) )
                                 AS NVARCHAR(448) ) ) 
        FROM (SELECT $(EHA_SCHEMA).GetEHPhraseName( @DbName
                                                  , @CertificateName
                                                  , 'Encryption' ) AS EncryptedName ) AS derived;
        EXEC $(EHA_SCHEMA).AddNameValue @Keytvp, @KeyPhraseVersion OUTPUT;
      END         
    SET @BackupName = $(EHA_SCHEMA).NewCertificateBackupName (@DbName, @CertificateName );
    SELECT @BackupNameBucket =  $(EHA_SCHEMA).AddSalt( '$(EHDB)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'BackupNameBucket' 
                                                     , BackupName )
    FROM ( SELECT CAST( DECRYPTBYKEY( @BackupName ) AS NVARCHAR(128) ) AS BackupName ) AS derived;



    SET @BackupPath = $(EHA_SCHEMA).BackupPath (@DbName);       
    -- build a batch to execute in the target database
    IF ISNULL( (SELECT TOP(1) CipherType         
                FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
                WHERE ServerName = @@SERVERNAME
                AND DbName = @DbName
                AND NodeName = 'Database Master Key'
                AND Action = 'BackupDatabaseMasterKey'
                AND Status = 'Complete'
                ORDER BY CreateUTCDT DESC ), 'NA') = 'PW'
      BEGIN
        SET @DMKPhraseName = $(EHA_SCHEMA).GetEHPhraseName(@DbName, @CertificateName, 'Encryption');
        INSERT @DMKtvp (Name, Value)
        EXEC $(EHA_SCHEMA).SelectNameValue @DMKPhraseName, NULL;
      END 
    SET @BackupDDL = (SELECT FORMATMESSAGE ( $(MESSAGE_OFFSET)27
                                           , @DbName 
                                           , CASE WHEN @DMKPhraseName IS NOT NULL -- need to open master key
                                                   THEN (SELECT FORMATMESSAGE ( $(MESSAGE_OFFSET)20
                                                                              , CAST( DECRYPTBYKEY( Value
                                                                                                 , 1
                                                                                                 , CAST ( DECRYPTBYKEY( Name ) AS NVARCHAR(448) ) 
                                                                                                 ) AS NVARCHAR(128) ) )
                                                         FROM @DMKtvp ) 
                                                   ELSE '' END
                                           , @Certificatename    
                                           , CAST(DecryptByKey(@BackupPath, 1, @DbName ) AS NVARCHAR(1024))  
                                           , CASE WHEN @UseHash = 1 
                                                   THEN CAST( @BackupNameBucket AS NVARCHAR(448) )
                                                   ELSE CAST( DecryptByKey( @BackupName ) AS NVARCHAR(448) ) 
                                                   END 
                                         , '$(PUBLIC_KEY_BACKUP_EXT)'
                                         , CASE WHEN @CipherType <> 'NA'  
                                                 THEN FORMATMESSAGE ( $(MESSAGE_OFFSET)28
                                                                   , CAST(DecryptByKey(@BackupPath, 1, @DbName ) AS NVARCHAR(1024)) 
                                                                   , CASE WHEN @UseHash = 1 
                                                                         THEN CAST( @BackupNameBucket AS NVARCHAR(448) )
                                                                         ELSE CAST( DecryptByKey( @BackupName ) AS NVARCHAR(448) ) 
                                                                         END 
                                                                   , '$(PRIVATE_KEY_BACKUP_EXT)'
                                                                   , ( SELECT CAST( DECRYPTBYKEY( Value
                                                                                                 , 1
                                                                                                 , CAST ( DECRYPTBYKEY( Name ) AS NVARCHAR(448) ) ) AS NVARCHAR(128) )
                                                                       FROM @BackupTvp )
                                                                   , CASE WHEN @CipherType = 'PW'    
                                                                           THEN (SELECT FORMATMESSAGE ( $(MESSAGE_OFFSET)29
                                                                                                     , CAST( DECRYPTBYKEY( Value
                                                                                                                         , 1
                                                                                                                         , CAST ( DECRYPTBYKEY( Name ) AS NVARCHAR(448) ) 
                                                                                                                           ) AS NVARCHAR(128) ) )  
                                                                                 FROM @KeyTvp )
                                                                           ELSE '' END )
                                                 ELSE '' END
                                           , CASE WHEN @DMKPhraseName IS NOT NULL -- open master key
                                                   THEN 'CLOSE MASTER KEY;'
                                                   ELSE '' END ) );                       
    EXEC @ReturnCode = sp_executesql @BackupDDL;
    IF @ReturnCode <> 0
      RAISERROR($(MESSAGE_OFFSET)12,16,1,'DATABASE', @DbName, 'CERTIFICATE', @CertificateName,'BACKUP',@ReturnCode);
    ELSE
      RAISERROR($(MESSAGE_OFFSET)11, 0,0,'DATABASE', @DbName, 'CERTIFICATE', @CertificateName,'BACKUP');
    INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
      ( Id
      , DbName
      , Node
      , NodeName
      , BackupName
      , BackupNameBucket
      , UseHash
      , BackupPath
      , BackupPhraseVersion
      , KeyPhraseVersion
      , Action
      , Status
      , Colophon
      , Edition
      , MAC
      , CipherType )
    SELECT @Id 
          , @DbName
          , @Node
          , @CertificateName
          , @BackupName
          , @BackupNameBucket
          , @UseHash
          , @BackupPath
          , @BackupPhraseVersion
          , @KeyPhraseVersion
          , OBJECT_NAME(@@PROCID)
          , 'Complete'
          , @Colophon
          , @Edition
          , @MAC
          , @CipherType;
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
          ( Id
          , DbName
          , Node
          , NodeName
          , BackupName
          , BackupNameBucket
          , UseHash
          , BackupPath
          , BackupPhraseVersion
          , KeyPhraseVersion
          , Action
          , Status
          , Colophon
          , Edition
          , MAC
          , CipherType
          , ErrorData )
        SELECT @Id
            , ISNULL( @DbName, '' )
            , @Node
            , ISNULL( @CertificateName, '' )
            , ISNULL( @BackupName, 0x0 ) 
            , ISNULL( @BackupNameBucket, 0 ) 
            , ISNULL( @UseHash, 0 ) 
            , ISNULL( @BackupPath, 0x0 )
            , ISNULL( @BackupPhraseVersion , 0 )
            , ISNULL( @KeyPhraseVersion, 0 )
            , OBJECT_NAME(@@PROCID)
            , 'Error'
            , ISNULL( @Colophon, 0 )
            , ISNULL( @Edition, 0 )
            , ISNULL( @MAC, 0x0 )
            , ISNULL( @CipherType, '' )
            , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                          , ErrorInfo 
                          , 1
                          , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH      
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).BackupCertificate
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).RestoreCertificate') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).RestoreCertificate
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: restore a certificate 
--    ASSERT: the backup is located in same folder as the .mdf of the database
--            and that the .mdf is never moved from that folder
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).RestoreCertificate 
 ( @CertificateName NVARCHAR(128)
 , @DbName NVARCHAR(128) 
 , @IdToRestore NCHAR(36) = NULL ) -- DEFAULT is most recent
$(WITH_OPTIONS)                  -- No @ForceReplace - cannot restore over in-use cert
AS
BEGIN 
DECLARE @BackupName VARBINARY(8000)
      , @BackupNameBucket INT
      , @BackupPath VARBINARY(8000)
      , @BackupPhraseName NVARCHAR(448)
      , @BackupPhraseVersion SMALLINT
      , @Backuptvp NAMEVALUETYPE
      , @CertificateId INT
      , @Colophon INT
      , @ColophonOld INT
      , @Edition SMALLINT
      , @CipherType NCHAR(2)
      , @Id NCHAR(36)
      , @KeyPhraseName NVARCHAR(448)
      , @KeyPhraseVersion SMALLINT
      , @Keytvp NAMEVALUETYPE
      , @MAC VARBINARY(128)
      , @Node HIERARCHYID
      , @ObjectInfoDDL NVARCHAR(512)
      , @Parameters VARBINARY(8000)
      , @RestoreDDL NVARCHAR(4000)
      , @Reason NVARCHAR(128)
      , @ReturnCode INT
      , @UseHash TINYINT
      , @ErrorData VARBINARY(8000);
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@CertificateName = ''%s''' 
								                 + ', @DbName ''%s''' 
												 + ', @IdToRestore = %d'
                                                 , @CertificateName
                                                 , @DbName
                                                 , @IdToRestore)
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    IF DB_ID(@DbName) IS NULL
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'Database', 'database not found');
    SELECT TOP(1) @BackupPath = BackupPath
                , @BackupName = BackupName
                , @BackupNameBucket = BackupNameBucket
                , @UseHash = UseHash
                , @CipherType = CipherType 
                , @ColophonOld = Colophon 
                , @Edition = Edition
                , @MAC = MAC
                , @Node = Node
    FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
    WHERE ServerName = CASE WHEN @IdToRestore IS NULL 
                            THEN @@SERVERNAME 
                            ELSE ServerName END 
    AND DbName = CASE WHEN @IdToRestore IS NULL 
                            THEN @DbName 
                            ELSE DbName END 
    AND NodeName = @CertificateName 
    AND Action = 'BackupCertificate'
    AND Status = 'Complete'
    AND Id = ISNULL(@IdToRestore, Id)
    ORDER BY CreateUTCDT DESC;   
    SET @ObjectInfoDDL = FORMATMESSAGE( $(MESSAGE_OFFSET)23
                                      , FORMATMESSAGE( $(MESSAGE_OFFSET)21
                                                     , '$(EHDB)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'Colophon'
                                                     , 'thumbprint' ) 
                                      , @DbName
                                      , @CertificateName );
    EXEC sp_executesql @ObjectInfoDDL
               , N'@CertificateName NVARCHAR(128), @CipherType NCHAR(2) OUTPUT, @Colophon INT OUTPUT'
               , @CertificateName, @CipherType OUTPUT, @Colophon OUTPUT;

    -- certs do not have a REGENERATE method - if a cert is in use it cannot be dropped
    IF (@CertificateId IS NOT NULL) -- certificate exist - cannot restore
      BEGIN
        SET @Reason = 'Certificate ' + @CertificateName + ' already exits in Db ' + @DbName; 
        RAISERROR($(MESSAGE_OFFSET)13,16,1,'DATABASE', @DbName, 'CERTIFICATE',@CertificateName,'RESTORE',@Reason);
      END

    SET @BackupPhraseName = $(EHA_SCHEMA).GetEHPhraseName(@DbName, @CertificateName, 'Backup' );
    INSERT @Backuptvp (Name, Value)
    EXEC $(EHA_SCHEMA).SelectNameValue @BackupPhraseName;

    SET @KeyPhraseName = $(EHA_SCHEMA).GetEHPhraseName(@DbName, @CertificateName, 'Encryption' );
    INSERT @Keytvp (Name, Value)
    EXEC $(EHA_SCHEMA).SelectNameValue @KeyPhraseName;

    SET @RestoreDDL = 'USE ' + @DbName + ';' 
-- need to deal with DMK better (as done in DMK restore proc) (have not at all here!)
-- NA            CREATE CERTIFICATE '%s' FROM FILE '%s%s%s'
-- PW            CREATE CERTIFICATE '%s' FROM FILE '%s%s%s' WITH PRIVATE KEY (File = '%s%s%s'  DECRYPTION BY PASSWORD = '%s')
--not NA or PW   CREATE CERTIFICATE '%s' FROM FILE '%s%s%s' WITH PRIVATE KEY (File = '%s%s%s'  DECRYPTION BY PASSWORD = '%s' , ENCRYPTION BY PASSWORD '%s') 
    SET @RestoreDDL += 'CREATE CERTIFICATE ' + @CertificateName + SPACE(1) 
                     + 'FROM FILE = ''' + CAST(DecryptByKey(@BackupPath, 1, @DbName ) AS NVARCHAR(1024)) 
                + CAST( CASE WHEN @UseHash = 1 
                             THEN @BackupNameBucket
                             ELSE DecryptByKey( @BackupName
                                              , 1
                                              , @Id )  
                             END AS NVARCHAR(448) ) + '$(PUBLIC_KEY_BACKUP_EXT)''';
    IF @CipherType <> 'NA'
      BEGIN
        SET @RestoreDDL  += (SELECT SPACE(1) + 'WITH PRIVATE KEY' + SPACE(1)
                                + '(FILE = ''' + CAST(DecryptByKey( @BackupPath
                                                                  , 1
                                                                  , @DbName ) AS NVARCHAR(1024)) 
                                 + CASE WHEN @UseHash = 1 
                                        THEN CAST( @BackupNameBucket AS NVARCHAR(448) ) 
                                        ELSE CAST( DECRYPTBYKEY( @BackupName ) AS NVARCHAR(448) )  
                                        END    
                                 + '$(PRIVATE_KEY_BACKUP_EXT)''' + SPACE(1) 
                                 + ', DECRYPTION BY PASSWORD = '''  
                                 + CAST( DECRYPTBYKEY( Value
                                                     , 1
                                                     , CAST ( DECRYPTBYKEY( Name ) 
                                                             AS NVARCHAR(448) ) 
                                                     ) AS NVARCHAR(128) ) + ''''
                             FROM @Backuptvp );
        IF @CipherType = 'PW'
          SET @RestoreDDL += (SELECT ', ENCRYPTION BY PASSWORD = ''' 
                                  + CAST( DECRYPTBYKEY( Value
                                                      , 1
                                                      , CAST ( DECRYPTBYKEY( Name ) 
                                                              AS NVARCHAR(448) ) 
                                                      ) AS NVARCHAR(128) ) + ''''
                              FROM @Keytvp ); 
        SET @RestoreDDL += ')'
      END
    SET @RestoreDDL += ';'
    EXEC @ReturnCode = sp_executesql @RestoreDDL
    IF @ReturnCode <> 0
      RAISERROR($(MESSAGE_OFFSET)12,16,1,'DATABASE', @DbName, 'CERTIFICATE', @CertificateName,'BACKUP', @ReturnCode);
    ELSE
      RAISERROR($(MESSAGE_OFFSET)11, 0,0,'DATABASE', @DbName, 'CERTIFICATE', @CertificateName,'BACKUP');
    SET @ObjectInfoDDL = FORMATMESSAGE( $(MESSAGE_OFFSET)23
                                      , FORMATMESSAGE( $(MESSAGE_OFFSET)21
                                                     , '$(EHDB)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'Colophon'
                                                     , 'thumbprint' ) 
                                      , @DbName
                                      , @CertificateName );
    EXEC sp_executesql @ObjectInfoDDL
                     , N'@CertificateName NVARCHAR(128), @CipherType NCHAR(2) OUTPUT, @Colophon INT OUTPUT'
                     , @CertificateName, @CipherType OUTPUT, @Colophon OUTPUT;
    -- if guid of symmetric key not changed, rev the Edition - can this happen ???
    IF @Colophon = @ColophonOld
      SET @Edition = (SELECT MAX(Edition) + 1
                      FROM  $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
                      WHERE ServerName = @@SERVERNAME
                      AND Action = OBJECT_NAME(@@PROCID)
                      AND Status = 'Complete'
                      AND NodeName = @CertificateName 
                      AND Colophon = @Colophon );
    INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
      ( Id
      , DbName
      , Node
      , NodeName
      , BackupName
      , BackupNameBucket
      , UseHash
      , BackupPath
      , BackupPhraseVersion
      , KeyPhraseVersion
      , Colophon
      , Edition
      , MAC
      , Action
      , Status
      , CipherType)
    VALUES ( @Id 
           , @DbName
           , @Node
           , @CertificateName
           , @BackupName
           , @BackupNameBucket
           , @UseHash
           , @BackupPath
           , @BackupPhraseVersion
           , @KeyPhraseVersion
           , @Colophon
           , @Edition
           , @MAC
           , OBJECT_NAME(@@PROCID)
           , 'Complete'
           , @CipherType );
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
          ( Id
          , DbName
          , Node
          , NodeName
          , BackupName
          , BackupNameBucket
          , UseHash
          , BackupPath
          , BackupPhraseVersion
          , KeyPhraseVersion
          , Colophon
          , Edition
          , MAC
          , Action
          , Status
          , CipherType
          , ErrorData )
        SELECT @Id
             , ISNULL( @DbName,'')
             , @Node
             , ISNULL( @CertificateName, '')
             , ISNULL( @BackupName, 0x0 )
             , ISNULL( @BackupNameBucket, 0 ) 
             , ISNULL( @UseHash, 0 )
             , ISNULL( @BackupPath, 0x0 )
             , ISNULL( @BackupPhraseVersion, 0 )
             , ISNULL( @KeyPhraseVersion, 0 )
             , ISNULL( @Colophon, 0 )
             , ISNULL( @Edition, 0 )
             , ISNULL( @MAC, 0x0 )
             , OBJECT_NAME(@@PROCID)
             , 'Error'
             , ISNULL( @CipherType, '' )
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).RestoreCertificate
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).BackupContainer') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).BackupContainer
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: copy the truecrypt Containers into the database
--        could be any file that the service account can access
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).BackupContainer
  ( @FilePath NVARCHAR(1024)  
  , @FileName NVARCHAR(128) 
  , @Tag NVARCHAR(128) = 'DEFAULT' )
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @ErrorData VARBINARY(8000)
      , @GetContainerDDL NVARCHAR(512)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128)
      , @Parameters VARBINARY (8000)
      , @ReturnCode INT
      , @StartDT DATETIME2 = SYSUTCDATETIME();
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@FilePath = ''%s'', @FileName = ''%s'', @Tag = ''%s'''
                                                 , @FilePath, @FileName, @Tag )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    -- process user must be able to read @FileName from @FilePath
    SET @GetContainerDDL = FORMATMESSAGE ( N'INSERT $(EHA_SCHEMA).$(CONTAINERS_TABLE) ( Id, FileImage, Signature )' + SPACE(1) 
                                         + N'SELECT @Id, CAST(c.bulkcolumn AS VARBINARY(MAX) )'
                                         + N', SIGNBYCERT(CERT_ID(''$(AUTHENTICITY_CERTIFICATE)''),  CAST(c.bulkcolumn AS VARBINARY(8000) ) )' + SPACE(1) 
                                         + N'FROM OPENROWSET(BULK ''%s%s'', SINGLE_BLOB ) AS c'
                                         , @FilePath, @FileName );
    EXEC @ReturnCode = sp_executesql @GetContainerDDL, N'@Id NCHAR(36)', @Id;
    IF @ReturnCode <> 0  
      RAISERROR($(MESSAGE_OFFSET)12,16,1,'@GetContainerDDL', @FilePath, @FileName, '', '' ,@ReturnCode);
    INSERT $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE) 
      ( Id
      , FileName
      , FilePath
      , SizeInBytes
      , MAC
      , Action
      , Status )
    SELECT  @Id
           , ENCRYPTBYKEY(KEY_GUID('$(FILE_SYMMETRIC_KEY)'),@FileName, 1, @Id )
           , ENCRYPTBYKEY(KEY_GUID('$(FILE_SYMMETRIC_KEY)'),@FilePath, 1, @FileName )
           , LEN(FileImage)  
           , @MAC
           , OBJECT_NAME(@@PROCID)
           , 'Complete'
     FROM $(EHA_SCHEMA).$(CONTAINERS_TABLE)
     WHERE Id = @Id;
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE) 
          ( Id
          , FileName
          , FilePath
          , SizeInBytes
          , MAC
          , Action
          , Status 
          , ErrorData )
        SELECT @Id
              , ISNULL( ENCRYPTBYKEY(KEY_GUID('$(FILE_SYMMETRIC_KEY)'),@FileName, 1, @Id ), 0x0 )
              , ISNULL( ENCRYPTBYKEY(KEY_GUID('$(FILE_SYMMETRIC_KEY)'),@FilePath, 1, @FileName ), 0x0 )
              , 0 
              , ISNULL( @MAC, 0x0 )
              , OBJECT_NAME(@@PROCID)
              , 'Error'
              , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                            , ErrorInfo 
                            , 1
                            , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).BackupContainer
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO

IF OBJECT_ID ('$(EHA_SCHEMA).SendOffsiteCDC') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).SendOffSiteCDC
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: copy changes offsite using change data capture
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).SendOffsiteCDC
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @CaptureInstance NVARCHAR(128)
      , @ErrorData VARBINARY(8000)
      , @GetContainerDDL NVARCHAR(512)
      , @Id NCHAR(36)
      , @LastTransferredUTCDT DATETIME2
      , @MAC VARBINARY(128)
      , @MaxLsn BINARY(10)
      , @MinLsn BINARY(10)
      , @MinLsnSinceTransfer BINARY(10)
      , @Parameters VARBINARY (8000)
      , @UTCOffset INT = DATEDIFF( hh, SYSUTCDATETIME(), SYSDATETIME() );
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , ''
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    -- bookings first to protect DRI at target
    CLOSE ALL SYMMETRIC KEYS;
    IF EXISTS (SELECT * FROM sys.dm_cdc_errors)
      RAISERROR( $(MESSAGE_OFFSET)35, 16, 1
               , 'ChangeDataCapture'
               , 'check sys.dm_cdc_errors');
    -- all booked activity up to - but excluding - the time this proc was booked
    SELECT @MaxLsn = sys.fn_cdc_map_time_to_lsn ( 'largest less than'
                                                , DATEADD( hh, @UTCOffset, CreateUTCDT ) )
    FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
    WHERE Id = @Id;
    IF @MaxLsn IS NULL
      RAISERROR( 2147483635, 16, 1
               , 'ChangeDataCapture'
               , 'no changes found');
    -- start just after the last transferred record for the capture instance
    SET @CaptureInstance = '$(EHA_SCHEMA)_$(BOOKINGS_TABLE)' 
    SET @LastTransferredUTCDT = ( SELECT TOP (1) DATEADD( hh, @UTCOffset, CreateUTCDT ) 
                                  FROM $(EHA_SCHEMA).$(LINK_BOOKINGS_SYNONYM)
                                  WHERE ServerName = @@SERVERNAME
                                  ORDER BY CreateUTCDT DESC );
    -- null if date range is not in capture set
    SET @MinLsnSinceTransfer = sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                          , @LastTransferredUTCDT )
    -- get_min_lsn will always return an LSN or 0x00000000000000000000, never null if valid    
    SET @MinLsn = sys.fn_cdc_get_min_lsn(@CaptureInstance); 
    IF @MinLsn < ISNULL( @MinLsnSinceTransfer , 0x0 )
      SET @MinLsn = @MinLsnSinceTransfer;
    INSERT $(EHA_SCHEMA).$(LINK_BOOKINGS_SYNONYM)
      ( Id
      , ServerName
      , ProcId
      , ObjectName
      , Parameters
      , Status
      , ErrorData
      , CreateUTCDT
      , CreateUser)
    SELECT Id
          , ServerName
          , ProcId
          , ObjectName
          , Parameters
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser 
    FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(BOOKINGS_TABLE)
                                          ( @MinLsn, @MaxLsn, 'all'); 
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , capture_instance
          , ISNULL( @MinLsn, 0x0 ) 
          , @MaxLsn
          , @@ROWCOUNT  
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete'
    FROM cdc.change_tables
    WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(BOOKINGS_TABLE)' );
    SET @CaptureInstance = '$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE)'
    SET @LastTransferredUTCDT = ( SELECT TOP (1) DATEADD( hh, @UTCOffset, CreateUTCDT ) 
                                  FROM  $(EHA_SCHEMA).$(LINK_BACKUP_ACTIVITY_SYNONYM)
                                  WHERE ServerName = @@SERVERNAME
                                  ORDER BY CreateUTCDT DESC );
    SET @MinLsnSinceTransfer = sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                          , @LastTransferredUTCDT )
       SET @MinLsn = sys.fn_cdc_get_min_lsn(@CaptureInstance); 
    IF @MinLsn < ISNULL( @MinLsnSinceTransfer , 0x0 )
      SET @MinLsn = @MinLsnSinceTransfer;
    INSERT $(EHA_SCHEMA).$(LINK_BACKUP_ACTIVITY_SYNONYM)
      ( Id
      , ServerName
      , DbName
      , Node
      , Level
      , NodeName
      , BackupName
      , BackupNameBucket
      , UseHash
      , BackupPath
      , BackupPhraseVersion
      , KeyPhraseVersion
      , Colophon
      , Edition
      , MAC
      , Action
      , Status
      , CipherType
      , ErrorData
      , CreateUTCDT
      , CreateUser)
    SELECT Id
          , ServerName
          , DbName
          , Node.ToString()
          , Level
          , NodeName
          , BackupName
          , BackupNameBucket
          , UseHash
          , BackupPath
          , BackupPhraseVersion
          , KeyPhraseVersion
          , Colophon
          , Edition
          , MAC
          , Action
          , Status
          , CipherType
          , ErrorData
          , CreateUTCDT
          , CreateUser 
    FROM cdc.fn_cdc_get_net_changes_$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE)
                                                ( @MinLsn, @MaxLsn, 'all'); 
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , capture_instance
          , ISNULL( @MinLsn, 0x0 )
          , @MaxLsn
          , @@ROWCOUNT  
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete'
    FROM cdc.change_tables
    WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)' );
    SET @CaptureInstance = '$(EHA_SCHEMA)_$(CONTAINERS_TABLE)';
    SET @LastTransferredUTCDT = ( SELECT TOP (1) DATEADD( hh, @UTCOffset, CreateUTCDT ) 
                                  FROM $(EHA_SCHEMA).$(LINK_CONTAINER_ACTIVITY_SYNONYM)
                                  WHERE ServerName = @@SERVERNAME
                                  ORDER BY CreateUTCDT DESC );
    SET @MinLsnSinceTransfer = sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                          , @LastTransferredUTCDT )
       SET @MinLsn = sys.fn_cdc_get_min_lsn(@CaptureInstance); 
    IF @MinLsn < ISNULL( @MinLsnSinceTransfer , 0x0 )
      SET @MinLsn = @MinLsnSinceTransfer;
    INSERT $(EHA_SCHEMA).$(LINK_CONTAINERS_SYNONYM)
      ( Id
      , ServerName
      , Tag
      , FileImage
      , Signature )
    SELECT Id
          , ServerName
          , Tag
          , FileImage
          , Signature
    FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(CONTAINERS_TABLE)
                                            ( @MinLsn, @MaxLsn, 'all'); 
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , capture_instance
          , ISNULL( @MinLsn, 0x0 )
          , @MaxLsn
          , @@ROWCOUNT  
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete' 
    FROM cdc.change_tables
    WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(CONTAINERS_TABLE)' );
    -- same last transfer info as Container
    SET @CaptureInstance = '$(EHA_SCHEMA)_$(CONTAINER_ACTIVITY_TABLE)';
    SET @MinLsn = sys.fn_cdc_get_min_lsn(@CaptureInstance); 
    IF @MinLsn < ISNULL( @MinLsnSinceTransfer , 0x0 )
      SET @MinLsn = @MinLsnSinceTransfer;
    INSERT $(EHA_SCHEMA).$(LINK_CONTAINER_ACTIVITY_SYNONYM)
      ( Id
      , ServerName
      , FileName
      , FilePath
      , SizeInBytes
      , MAC
      , Action
      , Status
      , ErrorData
      , CreateUTCDT
      , CreateUser )
    SELECT  Id
          , ServerName
          , FileName
          , FilePath
          , SizeInBytes
          , MAC
          , Action
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser 
    FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(CONTAINER_ACTIVITY_TABLE)
                                                    ( @MinLsn, @MaxLsn, 'all'); 
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , capture_instance
          , ISNULL( @MinLsn, 0x0 )
          , @MaxLsn
          , @@ROWCOUNT  
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete'
    FROM cdc.change_tables
    WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE)' );
    SET @CaptureInstance = '$(EHA_SCHEMA)_$(NAMEVALUES_TABLE)';
    SET @LastTransferredUTCDT = ( SELECT TOP (1) DATEADD( hh, @UTCOffset, CreateUTCDT ) 
                                  FROM $(EHA_SCHEMA).$(LINK_NAMEVALUES_SYNONYM)
                                  WHERE ServerName = @@SERVERNAME
                                  ORDER BY CreateUTCDT DESC );
    SET @MinLsnSinceTransfer = sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                          , @LastTransferredUTCDT )
    SET @MinLsn = sys.fn_cdc_get_min_lsn(@CaptureInstance); 
    IF @MinLsn < ISNULL( @MinLsnSinceTransfer , 0x0 )
      SET @MinLsn = @MinLsnSinceTransfer;
    INSERT $(EHA_SCHEMA).$(LINK_NAMEVALUES_SYNONYM)
      ( Id
      , ServerName
      , NameBucket
      , ValueBucket
      , Version
      , Name
      , Value
      , CreateUTCDT
      , CreateUser)
    SELECT  Id
          , ServerName
          , NameBucket
          , ValueBucket
          , Version
          , Name
          , Value
          , CreateUTCDT
          , CreateUser 
    FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(NAMEVALUES_TABLE)
                                            ( @MinLsn, @MaxLsn, 'all'); 
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , capture_instance
          , ISNULL( @MinLsn, 0x0 )
          , @MaxLsn
          , @@ROWCOUNT  
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete'
    FROM cdc.change_tables
    WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(NAMEVALUES_TABLE)' );
    SET @CaptureInstance = '$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)';
    SET @LastTransferredUTCDT = ( SELECT TOP (1) DATEADD( hh, @UTCOffset, CreateUTCDT ) 
                                  FROM $(EHA_SCHEMA).$(LINK_NAMEVALUE_ACTIVITY_SYNONYM)
                                  WHERE ServerName = @@SERVERNAME
                                  ORDER BY CreateUTCDT DESC );
    SET @MinLsnSinceTransfer = sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                          , @LastTransferredUTCDT )
   
    SET @MinLsn = sys.fn_cdc_get_min_lsn(@CaptureInstance); 
    IF @MinLsn < ISNULL( @MinLsnSinceTransfer , 0x0 )
      SET @MinLsn = @MinLsnSinceTransfer;
    INSERT $(EHA_SCHEMA).$(LINK_NAMEVALUE_ACTIVITY_SYNONYM)
      ( Id
      , ServerName
      , MAC
      , Action
      , Status
      , ErrorData
      , CreateUTCDT
      , CreateUser )
    SELECT Id
          , ServerName
          , MAC
          , Action
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser 
    FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)
                                                    ( @MinLsn, @MaxLsn, 'all'); 
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , capture_instance
          , ISNULL( @MinLsn, 0x0 )
          , @MaxLsn
          , @@ROWCOUNT  
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete' 
    FROM cdc.change_tables
    WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)' );
    SET @CaptureInstance = '$(EHA_SCHEMA)_$(NOTIFICATION_ACTIVITY_TABLE)';
    SET @LastTransferredUTCDT = ( SELECT TOP (1) DATEADD( hh, @UTCOffset, CreateUTCDT ) 
                                  FROM $(EHA_SCHEMA).$(LINK_NOTIFICATION_ACTIVITY_SYNONYM)
                                  WHERE ServerName = @@SERVERNAME
                                  ORDER BY CreateUTCDT DESC );
    SET @MinLsnSinceTransfer = sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                          , @LastTransferredUTCDT )
       SET @MinLsn = sys.fn_cdc_get_min_lsn(@CaptureInstance); 
    IF @MinLsn < ISNULL( @MinLsnSinceTransfer , 0x0 )
      SET @MinLsn = @MinLsnSinceTransfer;
    INSERT $(EHA_SCHEMA).$(LINK_NOTIFICATION_ACTIVITY_SYNONYM)
      ( Id
      , ServerName
      , ConversationHandle
      , ConversationGroupId
      , Message
      , Signature
      , MAC
      , Action
      , Status
      , ErrorData
      , CreateUTCDT
      , CreateUser )
    SELECT Id
          , ServerName
          , ConversationHandle
          , ConversationGroupId
          , CAST( Message AS IMAGE )
          , Signature
          , MAC
          , Action
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser 
    FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(NOTIFICATION_ACTIVITY_TABLE) 
                                                  ( @MinLsn, @MaxLsn, 'all' ); 
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , capture_instance
          , ISNULL( @MinLsn, 0x0 )
          , @MaxLsn
          , @@ROWCOUNT  
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete' 
    FROM cdc.change_tables
    WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)' );
    SET @CaptureInstance = '$(EHA_SCHEMA)_$(OFFSITE_ACTIVITY_TABLE)';
    SET @LastTransferredUTCDT = ( SELECT TOP (1) DATEADD( hh, @UTCOffset, CreateUTCDT ) 
                                  FROM $(EHA_SCHEMA).$(LINK_OFFSITE_ACTIVITY_SYNONYM)
                                  WHERE ServerName = @@SERVERNAME
                                  ORDER BY CreateUTCDT DESC );
    SET @MinLsnSinceTransfer = sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                          , @LastTransferredUTCDT )
   
    SET @MinLsn = sys.fn_cdc_get_min_lsn(@CaptureInstance); 
    IF @MinLsn < ISNULL( @MinLsnSinceTransfer , 0x0 )
      SET @MinLsn = @MinLsnSinceTransfer;
    INSERT $(EHA_SCHEMA).$(LINK_OFFSITE_ACTIVITY_SYNONYM)
      ( Id
      , ServerName
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , MAC
      , [RowCount]
      , Action
      , Status
      , ErrorData
      , CreateUTCDT
      , CreateUser)
    SELECT Id
          , ServerName
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , MAC
          , [RowCount]
          , Action
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser 
    FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(OFFSITE_ACTIVITY_TABLE) 
                                                  ( @MinLsn, @MaxLsn, 'all' ); 
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , capture_instance
          , ISNULL( @MinLsn, 0x0 )
          , @MaxLsn
          , @@ROWCOUNT  
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete'
    FROM cdc.change_tables
    WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)' );
    SET @CaptureInstance = '$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE)';
    SET @LastTransferredUTCDT = ( SELECT TOP (1) DATEADD( hh, @UTCOffset, CreateUTCDT ) 
                                  FROM $(EHA_SCHEMA).$(LINK_REPORT_ACTIVITY_SYNONYM)
                                  WHERE ServerName = @@SERVERNAME
                                  ORDER BY CreateUTCDT DESC );
    SET @MinLsnSinceTransfer = sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                          , @LastTransferredUTCDT )
       SET @MinLsn = sys.fn_cdc_get_min_lsn(@CaptureInstance); 
    IF @MinLsn < ISNULL( @MinLsnSinceTransfer , 0x0 )
      SET @MinLsn = @MinLsnSinceTransfer;
    INSERT $(EHA_SCHEMA).$(LINK_REPORT_ACTIVITY_SYNONYM)
      ( Id
      , ServerName
      , ReportProcedure
      , Duration_ms
      , RowsReturned
      , MAC
      , Status
      , ErrorData
      , CreateUTCDT
      , CreateUser )
    SELECT Id
          , ServerName
          , ReportProcedure
          , Duration_ms
          , RowsReturned
          , MAC
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser 
    FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE) 
                                                ( @MinLsn, @MaxLsn, 'all' ); 
    INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
      ( Id
      , CaptureInstance
      , MinLsn
      , MaxLsn
      , [RowCount]
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , capture_instance
          , ISNULL( @MinLsn, 0x0 )
          , @MaxLsn
          , @@ROWCOUNT  
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete'
    FROM cdc.change_tables
    WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)' );
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
          ( Id
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , [RowCount]
          , MAC
          , Action
          , Status 
          , ErrorData )
        SELECT @Id
             , ISNULL( @CaptureInstance, 'unknown' ) -- has to be unique
             , ISNULL( @MinLsn, 0x )
             , ISNULL( @MaxLsn, 0x )  
             , 0  
             , ISNULL( @MAC, 0x )
             , OBJECT_NAME(@@PROCID)
             , 'Error'
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).SendOffsiteCDC
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO

IF OBJECT_ID ('$(EHA_SCHEMA).SendOffsiteTC') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).SendOffSiteTC
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: copy changes offsite using track changes
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).SendOffsiteTC
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @BeginLsn BINARY(10)
      , @CaptureInstance NVARCHAR(128)
      , @ErrorData VARBINARY(8000)
      , @GetContainerDDL NVARCHAR(512)
      , @Id NCHAR(36)
      , @LastLsn BINARY(10) -- the previous MaxLsn
      , @MAC VARBINARY(128)
      , @MaxLsn BINARY(10)
      , @MinLsn BINARY(10)
      , @Parameters VARBINARY (8000)
      , @RowCount INT
      , @StartDT DATETIME2 = SYSUTCDATETIME();
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , ''
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    -- bookings first to protect DRI at target
    CLOSE ALL SYMMETRIC KEYS;

    IF EXISTS (SELECT * FROM sys.dm_cdc_errors)
      RAISERROR( $(MESSAGE_OFFSET)35, 16, 1
               ,'CDC state'
               ,'cdc_errors detected');
    -- no changes after this instant in time will be processesed at this time
    SET @Maxlsn = sys.fn_cdc_decrement_lsn(sys.fn_cdc_get_max_lsn());
    -- verify that first row to insert is not already on target
    SET @MinLsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(BOOKINGS_TABLE)');
    SET @LastLsn = 
        ISNULL( ( SELECT TOP (1) MaxLsn 
                  FROM $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(BOOKINGS_TABLE)'
                  ORDER BY CreateUTCDT DESC ), sys.fn_cdc_increment_lsn(0x000000000000000000) );
    IF NOT EXISTS (SELECT * 
                   FROM $(EHA_SCHEMA).$(LINK_BOOKINGS_SYNONYM)
                   WHERE Id = ( SELECT TOP (1) Id
                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(BOOKINGS_TABLE)
                                                                    ( @BeginLsn, @BeginLsn, 'all') 
                                ORDER BY __$start_lsn DESC ) 
                   AND @LastLsn > = @MinLsn ) -- means something is missing  
      BEGIN
        INSERT $(EHA_SCHEMA).$(LINK_BOOKINGS_SYNONYM)
          ( Id
          , ServerName
          , ProcId
          , ObjectName
          , Parameters
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser)
        SELECT Id
             , ServerName
             , ProcId
             , ObjectName
             , Parameters
             , Status
             , ErrorData
             , CreateUTCDT
             , CreateUser 
        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(BOOKINGS_TABLE)
                                             ( @BeginLsn, @MaxLsn, 'all'); 
        SET @RowCount = @@ROWCOUNT;
        INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
          ( Id
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , [RowCount]
          , MAC
          , Action
          , Status )
        SELECT @Id
             , capture_instance
             , @BeginLsn
             , @MaxLsn
             , @RowCount  
             , @MAC
             , OBJECT_NAME(@@PROCID)
             , 'Complete'
         FROM cdc.change_tables
         WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA).$(BOOKINGS_TABLE)');
      END
    -- verify that first row to insert is not already on target
    SET @MinLsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)');
    SET @LastLsn = 
        ISNULL( ( SELECT TOP (1) MaxLsn 
                  FROM $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE)'
                  ORDER BY CreateUTCDT DESC ), 0x000000000000000000 );
    SET @BeginLsn = sys.fn_cdc_increment_lsn(@LastLsn)
    IF NOT EXISTS (SELECT * 
                   FROM $(EHA_SCHEMA).$(LINK_BACKUP_ACTIVITY_SYNONYM)
                   WHERE Id = ( SELECT TOP (1) Id
                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE)
                                                                    ( @BeginLsn, @BeginLsn, 'all') 
                                ORDER BY __$start_lsn DESC ) 
                   AND @LastLsn > = @MinLsn ) -- means something is missing  
      BEGIN
        INSERT $(EHA_SCHEMA).$(LINK_BACKUP_ACTIVITY_SYNONYM)
          ( Id
          , ServerName
          , DbName
          , Node
          , Level
          , NodeName
          , BackupName
          , BackupNameBucket
          , UseHash
          , BackupPath
          , BackupPhraseVersion
          , KeyPhraseVersion
          , Colophon
          , Edition
          , MAC
          , Action
          , Status
          , CipherType
          , ErrorData
          , CreateUTCDT
          , CreateUser)
        SELECT Id
             , ServerName
             , DbName
             , Node.ToString()
             , Level
             , NodeName
             , BackupName
             , BackupNameBucket
             , UseHash
             , BackupPath
             , BackupPhraseVersion
             , KeyPhraseVersion
             , Colophon
             , Edition
             , MAC
             , Action
             , Status
             , CipherType
             , ErrorData
             , CreateUTCDT
             , CreateUser 
        FROM cdc.fn_cdc_get_net_changes_$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE)
                                                    ( @BeginLsn, @MaxLsn, 'all'); 
        SET @RowCount = @@ROWCOUNT;
        INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
          ( Id
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , [RowCount]
          , MAC
          , Action
          , Status )
        SELECT  @Id
               , @CaptureInstance
               , @BeginLsn
               , @MaxLsn
               , @RowCount  
               , @MAC
               , OBJECT_NAME(@@PROCID)
               , 'Complete'
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE)');
      END
    SET @Minlsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(CONTAINERS_TABLE)');
    SET @LastLsn = 
        ISNULL( ( SELECT TOP (1) MaxLsn 
                  FROM $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(CONTAINERS_TABLE)'
                  ORDER BY CreateUTCDT DESC ), 0x000000000000000000 );
    SET @BeginLsn = sys.fn_cdc_increment_lsn(@LastLsn)
    IF NOT EXISTS (SELECT * 
                   FROM $(EHA_SCHEMA).$(LINK_CONTAINERS_SYNONYM)
                   WHERE Id = ( SELECT TOP (1) Id
                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(CONTAINERS_TABLE)
                                                                    ( @BeginLsn, @BeginLsn, 'all') 
                                ORDER BY __$start_lsn DESC ) 
                   AND @LastLsn > = @MinLsn ) -- means something is missing  
      BEGIN
        INSERT $(EHA_SCHEMA).$(LINK_CONTAINERS_SYNONYM)
          ( Id
          , ServerName
          , Tag
          , FileImage
          , Signature)
        SELECT Id
             , ServerName
             , Tag
             , FileImage
             , Signature
        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(CONTAINERS_TABLE)
                                               ( @BeginLsn, @MaxLsn, 'all'); 
        SET @RowCount = @@ROWCOUNT;
        INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
          ( Id
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , [RowCount]
          , MAC
          , Action
          , Status )
        SELECT  @Id
               , @CaptureInstance
               , @BeginLsn
               , @MaxLsn
               , @RowCount  
               , @MAC
               , OBJECT_NAME(@@PROCID)
               , 'Complete'
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA)_$(CONTAINERS_TABLE)');
      END
    SET @Minlsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE)');
    SET @LastLsn = 
        ISNULL( ( SELECT TOP (1) MaxLsn 
                  FROM $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(CONTAINER_ACTIVITY_TABLE)'
                  ORDER BY CreateUTCDT DESC ), 0x000000000000000000 );
    SET @BeginLsn = sys.fn_cdc_increment_lsn(@LastLsn)
    IF NOT EXISTS (SELECT * 
                   FROM $(EHA_SCHEMA).$(LINK_CONTAINER_ACTIVITY_SYNONYM)
                   WHERE Id = ( SELECT TOP (1) Id
                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(CONTAINER_ACTIVITY_TABLE)
                                                                    ( @BeginLsn, @BeginLsn, 'all') 
                                ORDER BY __$start_lsn DESC ) 
                   AND @LastLsn > = @MinLsn ) -- means something is missing  
      BEGIN
        INSERT $(EHA_SCHEMA).$(LINK_CONTAINER_ACTIVITY_SYNONYM)
          ( Id
          , ServerName
          , FileName
          , FilePath
          , SizeInBytes
          , MAC
          , Action
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser )
        SELECT Id
             , ServerName
             , FileName
             , FilePath
             , SizeInBytes
             , MAC
             , Action
             , Status
             , ErrorData
             , CreateUTCDT
             , CreateUser 
        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(CONTAINER_ACTIVITY_TABLE)
                                                       ( @BeginLsn, @MaxLsn, 'all'); 
        SET @RowCount = @@ROWCOUNT;
        INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
          ( Id
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , [RowCount]
          , MAC
          , Action
          , Status )
        SELECT  @Id
               , @CaptureInstance
               , @BeginLsn
               , @MaxLsn
               , @RowCount  
               , @MAC
               , OBJECT_NAME(@@PROCID)
               , 'Complete'
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA)_$(CONTAINER_ACTIVITY_TABLE)');
      END
    SET @Minlsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(NAMEVALUES_TABLE)');
    SET @LastLsn = 
        ISNULL( ( SELECT TOP (1) MaxLsn 
                  FROM $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(NAMEVALUES_TABLE)'
                  ORDER BY CreateUTCDT DESC ), 0x000000000000000000 );
    SET @BeginLsn = sys.fn_cdc_increment_lsn(@LastLsn)
    IF NOT EXISTS (SELECT * 
                   FROM $(EHA_SCHEMA).$(LINK_NAMEVALUES_SYNONYM)
                   WHERE Id = ( SELECT TOP (1) Id
                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(NAMEVALUES_TABLE)
                                                                    ( @BeginLsn, @BeginLsn, 'all') 
                                ORDER BY __$start_lsn DESC ) 
                   AND @LastLsn > = @MinLsn ) -- means something is missing  
      BEGIN
        INSERT $(EHA_SCHEMA).$(LINK_NAMEVALUES_SYNONYM)
          ( Id
          , ServerName
          , NameBucket
          , ValueBucket
          , Version
          , Name
          , Value
          , CreateUTCDT
          , CreateUser)
        SELECT Id
             , ServerName
             , NameBucket
             , ValueBucket
             , Version
             , Name
             , Value
             , CreateUTCDT
             , CreateUser 
        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(NAMEVALUES_TABLE)
                                                ( @BeginLsn, @MaxLsn, 'all'); 
        SET @RowCount = @@ROWCOUNT;
        INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
          ( Id
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , [RowCount]
          , MAC
          , Action
          , Status )
        SELECT  @Id
               , @CaptureInstance
               , @BeginLsn
               , @MaxLsn
               , @RowCount  
               , @MAC
               , OBJECT_NAME(@@PROCID)
               , 'Complete'
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA)_$(NAMEVALUES_TABLE)');
      END
    SET @Minlsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)');
    SET @LastLsn = 
        ISNULL( ( SELECT TOP (1) MaxLsn 
                  FROM $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)'
                  ORDER BY CreateUTCDT DESC ), 0x000000000000000000 );
    SET @BeginLsn = sys.fn_cdc_increment_lsn(@LastLsn)
    IF NOT EXISTS (SELECT * 
                   FROM $(EHA_SCHEMA).$(LINK_NAMEVALUE_ACTIVITY_SYNONYM)
                   WHERE Id = ( SELECT TOP (1) Id
                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)
                                                                    ( @BeginLsn, @BeginLsn, 'all') 
                                ORDER BY __$start_lsn DESC ) 
                   AND @LastLsn > = @MinLsn ) -- means something is missing  
      BEGIN
        INSERT $(EHA_SCHEMA).$(LINK_NAMEVALUE_ACTIVITY_SYNONYM)
          ( Id
          , ServerName
          , MAC
          , Action
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser )
        SELECT Id
             , ServerName
             , MAC
             , Action
             , Status
             , ErrorData
             , CreateUTCDT
             , CreateUser 
        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)
                                                        ( @MinLsn, @MaxLsn, 'all'); 
        SET @RowCount = @@ROWCOUNT;
        INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
          ( Id
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , [RowCount]
          , MAC
          , Action
          , Status )
        SELECT  @Id
               , @CaptureInstance
               , @BeginLsn
               , @MaxLsn
               , @RowCount  
               , @MAC
               , OBJECT_NAME(@@PROCID)
               , 'Complete'
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)');
      END
    SET @Minlsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)');
    SET @LastLsn = 
        ISNULL( ( SELECT TOP (1) MaxLsn 
                  FROM $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(OFFSITE_ACTIVITY_TABLE)'
                  ORDER BY CreateUTCDT DESC ), 0x000000000000000000 );
    SET @BeginLsn = sys.fn_cdc_increment_lsn(@LastLsn)
    IF NOT EXISTS (SELECT * 
                   FROM $(EHA_SCHEMA).$(LINK_OFFSITE_ACTIVITY_SYNONYM)
                   WHERE Id = ( SELECT TOP (1) Id
                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(OFFSITE_ACTIVITY_TABLE)
                                                                    ( @BeginLsn, @BeginLsn, 'all') 
                                ORDER BY __$start_lsn DESC ) 
                   AND @LastLsn > = @MinLsn ) -- means something is missing  
      BEGIN
        INSERT $(EHA_SCHEMA).$(LINK_OFFSITE_ACTIVITY_SYNONYM)
          ( Id
          , ServerName
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , MAC
          , [RowCount]
          , Action
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser)
        SELECT Id
             , ServerName
             , CaptureInstance
             , MinLsn
             , MaxLsn
             , MAC
             , [RowCount]
             , Action
             , Status
             , ErrorData
             , CreateUTCDT
             , CreateUser 
        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(OFFSITE_ACTIVITY_TABLE) 
                                                     ( @BeginLsn, @MaxLsn, 'all'); 
        SET @RowCount = @@ROWCOUNT;
        INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
          ( Id
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , [RowCount]
          , MAC
          , Action
          , Status )
        SELECT  @Id
               , @CaptureInstance
               , @BeginLsn
               , @MaxLsn
               , @RowCount  
               , @MAC
               , OBJECT_NAME(@@PROCID)
               , 'Complete'
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA)_$(OFFSITE_ACTIVITY_TABLE)');
      END
    SET @Minlsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)');
    SET @LastLsn = 
        ISNULL( ( SELECT TOP (1) MaxLsn 
                  FROM $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE)'
                  ORDER BY CreateUTCDT DESC ), 0x000000000000000000 );
    SET @BeginLsn = sys.fn_cdc_increment_lsn(@LastLsn)
    IF NOT EXISTS (SELECT * 
                   FROM $(EHA_SCHEMA).$(LINK_REPORT_ACTIVITY_SYNONYM)
                   WHERE Id = ( SELECT TOP (1) Id
                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE)
                                                                    ( @BeginLsn, @BeginLsn, 'all') 
                                ORDER BY __$start_lsn DESC ) 
                   AND @LastLsn > = @MinLsn ) -- means something is missing  
      BEGIN
        INSERT $(EHA_SCHEMA).$(LINK_REPORT_ACTIVITY_SYNONYM)
          ( Id
          , ServerName
          , ReportProcedure
          , Duration_ms
          , RowsReturned
          , MAC
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser )
        SELECT Id
             , ServerName
             , ReportProcedure
             , Duration_ms
             , RowsReturned
             , MAC
             , Status
             , ErrorData
             , CreateUTCDT
             , CreateUser 
        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE) 
                                                   ( @BeginLsn, @MaxLsn, 'all'); 
        SET @RowCount = @@ROWCOUNT;
        INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
          ( Id
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , [RowCount]
          , MAC
          , Action
          , Status )
        SELECT @Id
             , capture_instance
             , @MinLsn
             , @MaxLsn
             , @RowCount  
             , @MAC
             , OBJECT_NAME(@@PROCID)
             , 'Complete'
         FROM cdc.change_tables
         WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)');
      END
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) 
          ( Id
          , CaptureInstance
          , MinLsn
          , MaxLsn
          , [RowCount]
          , MAC
          , Action
          , Status 
          , ErrorData )
        SELECT @Id
             , ISNULL( @CaptureInstance, CAST(NEWID() AS NVARCHAR(128) ) )
             , ISNULL( @BeginLsn, 0x )
             , ISNULL( @MaxLsn, 0x )  
             , ISNULL( @MAC, 0x )
             , ISNULL( @RowCount, 0 )
             , OBJECT_NAME(@@PROCID)
             , 'Error'
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).SendOffsiteTC
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO

IF OBJECT_ID ('$(EHA_SCHEMA).RecallContainer') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).RecallContainer
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: copy the truecrypt Containers from offsite store into the database
--        eha.Restore FileTable space
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).RecallContainer
  ( @RecallId NCHAR(36) )-- if null download but do not restore
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @FileName NVARCHAR(128) 
      , @FilePath VARBINARY(8000)  
      , @MAC VARBINARY(128)
      , @Parameters VARBINARY (8000)
      , @RowCount INT
      , @SourceServer NVARCHAR(128)
      , @StartDT DATETIME2 = SYSUTCDATETIME();
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@Id = ''%s'', @FileName = ''%s'''
                                                 , @Id, @FileName )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    -- validate the synonym before using it, can't sign it so hardcode at create
    -- the ODBC DSN and user definition could still be changed
    -- BIG man-in-the-middle hole
    IF NOT EXISTS ( SELECT * 
                    FROM sys.synonyms syn
                    CROSS JOIN sys.servers ser  
                    WHERE syn.name =  '$(LINK_CONTAINERS_SYNONYM)'
                    AND syn.schema_id = SCHEMA_ID( '$(EHA_SCHEMA)' )
                    AND syn.base_object_name = 
      '[$(LINK_SERVER)].[$(LINK_EHDB)].[$(EHA_SCHEMA)].[$(CONTAINERS_TABLE)]'
                    AND ser.Name = '$(LINK_SERVER)'
                    AND ser.data_source = '$(LINK_SERVER_ODBC_DSN)' ) 
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'$(LINK_CONTAINERS_SYNONYM)','not found');
    INSERT $(EHA_SCHEMA).$(RESTORE_FILETABLE) 
      ( stream_id, file_stream, name)
    SELECT @Id, FileImage, FORMATMESSAGE('%s_%s',ServerName, Tag) 
    FROM $(EHA_SCHEMA).$(LINK_CONTAINERS_SYNONYM)
    WHERE Id = @RecallId
    AND VerifySignedByCert( CERT_ID('$(OBJECT_CERTIFICATE)')
                          , CAST( FileImage AS VARBINARY(8000) )
                          , Signature ) = 1
    IF @@ROWCOUNT <> 1 
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'remote container','not verified');
      SELECT @SourceServer = ServerName
        , @FileName = CAST( DECRYPTBYKEY( FileName
                                        , 1
                                        , CAST(Id AS NCHAR(36) ) ) AS NVARCHAR(128) )
        , @FilePath = FilePath
    FROM $(EHA_SCHEMA).$(LINK_CONTAINER_ACTIVITY_SYNONYM)
    WHERE Id = @RecallId;
    INSERT $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE) 
      ( Id
      , ServerName
      , FileName
      , FilePath
      , SizeInBytes
      , MAC
      , Action
      , Status )
    SELECT @Id
         , @SourceServer
         , ENCRYPTBYKEY( KEY_GUID( '$(FILE_SYMMETRIC_KEY)' )
                       , @FileName
                       , 1
                       , @Id )
         , @FilePath
         , LEN(FileImage)
         , @MAC
         , OBJECT_NAME(@@PROCID)
         , 'Complete'
     FROM $(EHA_SCHEMA).$(CONTAINERS_TABLE)
     WHERE Id = @RecallId;
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE) 
          ( Id
          , FileName
          , FilePath
          , SizeInBytes
          , MAC
          , Action
          , Status 
          , ErrorData )
        SELECT @Id
              , ISNULL ( ENCRYPTBYKEY(KEY_GUID('$(FILE_SYMMETRIC_KEY)'), @FileName, 1, @Id ), 0x0 )
              , ISNULL ( @FilePath, 0x0 )
              , 0
              , ISNULL ( @MAC, 0x0 )
              , OBJECT_NAME(@@PROCID)
              , 'Error'
              , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                            , ErrorInfo 
                            , 1
                            , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                  , ERROR_LINE()
                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).RecallContainer
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO

---------------------
-- Reporting procs
---------------------
IF OBJECT_ID ('$(EHA_SCHEMA).CertificateBackupsByThumbprint') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).CertificateBackupsByThumbprint
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: list all certificate backups for the provided thumbprint 
--  missing or corrupt certificates provide thumbprint in failure message
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).CertificateBackupsByThumbprint
 ( @Thumbprint VARBINARY(20) )
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @MAC VARBINARY(128)
      , @Id NCHAR(36)
      , @Parameters VARBINARY (8000)
      , @RowCount INT
      , @ErrorData VARBINARY(8000)
      , @StartDT DATETIME2 = SYSUTCDATETIME();
SET NOCOUNT ON;
  BEGIN TRY
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@Thumbprint = %s'
                                                 , sys.fn_varbintohexstr(@Thumbprint) )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    SELECT ServerName
        , DbName
        , Node 
        , NodeName
        , Action
        , Status
        , MAC
        , CipherType
        , Colophon
        , DECRYPTBYKEY( ErrorData
                      , 1 
                      , CAST(Id as CHAR(36) ) )
        , CreateUTCDT
        , CreateUser
    FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
    WHERE Colophon = @Thumbprint
    ORDER BY Edition, CreateUTCDT DESC;
    SET @RowCount = @@ROWCOUNT;
    INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
      ( Id
      , ReportProcedure
      , Status
      , Duration_ms
      , RowsReturned)
    VALUES ( @Id
           , OBJECT_NAME(@@PROCID)
           , 'Complete'
           , DATEDIFF(ms, @StartDT, SYSUTCDATETIME()) 
           , @RowCount );
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
          ( Id
          , ReportProcedure
          , Status
          , Duration_ms
          , RowsReturned
          , ErrorData )
        SELECT @Id
             , OBJECT_NAME(@@PROCID)
             , 'Error'
             , DATEDIFF(ms, @StartDT, SYSUTCDATETIME())
             , @RowCount
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
         FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                   , ERROR_NUMBER()
                                   , ERROR_SEVERITY()
                                   , ERROR_STATE()
                                   , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                   , ERROR_LINE()
                                   , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).CertificateBackupsByThumbprint
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).ReportServerSummary') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).ReportServerSummary
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: list all EH objects on this server to consider for backup 
--        cross referenced to the last EHAdmin action for that object 
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).ReportServerSummary
  ( @ServerName NVARCHAR(128) = NULL )
$(WITH_OPTIONS)
AS
BEGIN
SET NOCOUNT ON;
DECLARE @MAC VARBINARY(128)
      , @Id NCHAR(36)
      , @RowCount INT
      , @Parameters VARBINARY(8000)
      , @ErrorData VARBINARY(8000)
      , @StartDT DATETIME2 = SYSUTCDATETIME();
  BEGIN TRY
    EXEC $(EHA_SCHEMA).OpenSession;
    IF @ServerName IS NULL
      SET @ServerName = @@SERVERNAME;
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@ServerName = ''%s''', @ServerName )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    CREATE TABLE #Survey
        ( ServerName NVARCHAR(128)
        , DbName NVARCHAR(128)
        , Name NVARCHAR(128)
        , CipherType NCHAR(2)
        , Colophon INT 
        , pvt_key_last_backup_date DATETIME );
    INSERT #Survey 
      ( ServerName
      , DbName
      , Name
      , CipherType
      , Colophon
      , pvt_key_last_backup_date) 
    EXEC sp_MSforEachDb 'USE ?; 
       SELECT @@SERVERNAME
         , ''master''
         , ''Service Master Key''
         , ''DP''
         , ABS( CHECKSUM( HASHBYTES( ''$(HASHBYTES_ALGORITHM)'', CAST( key_guid AS NCHAR(36) ) ) ) )
         , NULL
       FROM sys.symmetric_keys sk
       WHERE sk.name = ''##MS_ServiceMasterKey##''
        UNION ALL
       SELECT @@SERVERNAME
         , DB_NAME()
         , ''Database Master Key''
                --WHEN ''ESKS'' THEN ''SY'' -- Symmetric Key  
                --WHEN ''ESKP'' THEN ''PW'' -- Password 
                --WHEN ''ESUC'' THEN ''CT'' -- Certificate  
                --WHEN ''ESUA'' THEN ''AY'' -- Asymmetric Key  
                --WHEN ''ESKM'' THEN ''MK'' -- Master Key
         , CASE WHEN ke.count = 2 AND ke.type1 = ''ESKM'' AND ke.type2 = ''ESKP'' THEN ''SP''
                WHEN ke.count = 1 AND ke.type1 = ''ESKP'' THEN ''PW'' ELSE ''SM'' END
         , HASHBYTES( ''$(HASHBYTES_ALGORITHM)'', CAST( key_guid AS NCHAR(36) ) )
         , NULL
        FROM sys.symmetric_keys sk
        LEFT JOIN ( SELECT key_id
                         , MIN(crypt_type) AS type1 
                         , MAX(crypt_type) as type2
                         , COUNT(*) as count
                    FROM sys.key_encryptions 
                    GROUP BY key_id ) ke
        ON sk.symmetric_key_id = ke.key_id
        WHERE sk.name = ''##MS_DatabaseMasterKey##''
        UNION ALL
       SELECT @@SERVERNAME
          , DB_NAME()
         , name
         , pvt_key_encryption_type
         , ABS( CHECKSUM( HASHBYTES( ''$(HASHBYTES_ALGORITHM)'', CAST( thumbprint AS NCHAR(36) ) ) ) )
         , pvt_key_last_backup_date 
       FROM sys.certificates
       WHERE Name NOT LIKE ''##MS__%Certificate%##''';
   -- backfill the last backup dates for the DMKs 
    SELECT ISNULL(s.ServerName, k.ServerName) AS ServerName
         , COALESCE(s.DbName, k.DbName,'') AS DbName
         , ISNULL(s.Name, k.NodeName) AS Name
         , ISNULL(k.Action,'No Backup') AS Action 
         , CASE WHEN s.ServerName IS NULL THEN 'Orphan' 
                ELSE ISNULL(k.Status, 'Pending') END AS Status
         , k.Node.ToString() AS Node
         , s.pvt_key_last_backup_date
         , k.CreateUTCDT AS LastEHAdminDT 
         , k.Count AS EHAdminCount
    FROM #Survey s    -- the most rescent backup or restore
    FULL OUTER JOIN ( SELECT ServerName, DbName, Node, NodeName, Action, Status 
                           , Colophon, MAX(CreateUTCDT) AS CreateUTCDT, COUNT(*) AS [Count]
	                     FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
	                     WHERE ( Action LIKE 'Backup%'
	                             OR Action LIKE 'Restore%' )
                      AND Status = 'Complete'
	                     GROUP BY ServerName, DbName, Node, NodeName, Action, Status, Colophon ) k
    ON s.ServerName = k.ServerName
    AND (s.DbName = k.DbName OR (s.DbName IS NULL AND k.DbName IS NULL))
    AND k.NodeName = s.Name  
    ORDER BY Node, LastEHAdminDT DESC;
    SET @rowcount = @@ROWCOUNT;
    INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
      ( Id
      , ReportProcedure
      , MAC
      , Status
      , Duration_ms
      , RowsReturned)
      VALUES ( @Id
             , OBJECT_NAME(@@PROCID)
             , @MAC
             , 'Complete'
             , DATEDIFF(ms, @StartDT, SYSUTCDATETIME()) 
             , @RowCount );
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
          ( Id
          , ReportProcedure
          , MAC
          , Status
          , Duration_ms
          , RowsReturned
          , ErrorData )
        SELECT @Id
             , OBJECT_NAME(@@PROCID)
             , ISNULL( @MAC, 0x0 )
             , 'Error'
             , DATEDIFF( ms, @StartDT, SYSUTCDATETIME() )
             , @RowCount   
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
         FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                   , ERROR_NUMBER()
                                   , ERROR_SEVERITY()
                                   , ERROR_STATE()
                                   , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                   , ERROR_LINE()
                                   , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).ReportServerSummary
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).ReportErrors') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).ReportErrors
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: list latest EH errors on this server  
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).ReportErrors
  ( @ServerName NVARCHAR(128) = NULL )
$(WITH_OPTIONS)
AS
BEGIN
SET NOCOUNT ON;
DECLARE @Id NCHAR(36)
      , @ErrorData VARBINARY(8000)
      , @MAC VARBINARY(128)
      , @Parameters VARBINARY(8000)
      , @RowCount INT
      , @StartDT DATETIME2 = SYSUTCDATETIME();
  BEGIN TRY
    EXEC $(EHA_SCHEMA).OpenSession;
    IF @ServerName IS NULL
      SET @ServerName = @@SERVERNAME;
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@ServerName = ''%s''', @ServerName )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
    RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    OPEN SYMMETRIC KEY ErrorKey
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    SELECT  ServerName AS ServerName
          , '$(BOOKINGS_TABLE)' AS Entity
          , DB_NAME() AS DbName
	        , ObjectName AS Action
	        , Status
          , CreateUTCDT 
          , CreateUser 
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorInfo
    FROM eha.$(BOOKINGS_TABLE) 
    WHERE Status <> 'OK'
    AND ServerName = @ServerName
    UNION ALL
    SELECT  ServerName 
          , '$(BACKUP_ACTIVITY_TABLE)'
          , DbName
	        , FORMATMESSAGE( '%s_%s', Action, NodeName )
	        , Status
          , CreateUTCDT 
          , CreateUser 
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorInfo
    FROM eha.$(BACKUP_ACTIVITY_TABLE) 
    WHERE Status = 'Error'
    AND ServerName = @ServerName
    UNION ALL
    SELECT  ServerName 
          , '$(CONTAINER_ACTIVITY_TABLE)'
          , DB_NAME()
	        , FORMATMESSAGE( '%s_%s', Action, DECRYPTBYKEY( FileName, 1, CAST( Id AS NCHAR(36) ) ) )
	        , Status
          , CreateUTCDT 
          , CreateUser 
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorData 
    FROM eha.$(CONTAINER_ACTIVITY_TABLE)     
    WHERE Status = 'Error'
    AND ServerName = @ServerName
    UNION ALL
    SELECT  ServerName 
          , '$(NAMEVALUE_ACTIVITY_TABLE)'  
          , DB_NAME()
	        , Action
	        , Status
          , CreateUTCDT
          , CreateUser 
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorInfo
    FROM eha.$(NAMEVALUE_ACTIVITY_TABLE)
    WHERE Status = 'Error'
    AND ServerName = @ServerName
    UNION ALL
    SELECT  ServerName 
          , '$(OFFSITE_ACTIVITY_TABLE)'
          , DB_NAME()
	        , CaptureInstance
	        , Status
          , CreateUTCDT 
          , CreateUser 
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorData 
    FROM eha.$(OFFSITE_ACTIVITY_TABLE)     
    WHERE Status = 'Error'
    AND ServerName = @ServerName
    UNION ALL
    SELECT  ServerName 
          , '$(NOTIFICATION_ACTIVITY_TABLE)'
          , DB_NAME()
	        , Action
	        , Status
          , CreateUTCDT 
          , CreateUser 
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorData 
    FROM eha.$(NOTIFICATION_ACTIVITY_TABLE)     
    WHERE Status = 'Error'
    AND ServerName = @ServerName
    UNION ALL
    SELECT  ServerName 
          , '$(REPORT_ACTIVITY_TABLE)'
          , DB_NAME()
	        , ReportProcedure
	        , Status
          , CreateUTCDT 
          , CreateUser 
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorData 
    FROM eha.$(REPORT_ACTIVITY_TABLE)     
    WHERE Status = 'Error'
    AND ServerName = @ServerName
    ORDER BY CreateUTCDT DESC;
    SET @RowCount = @@ROWCOUNT;
    INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
      ( Id
      , ReportProcedure
      , Status
      , MAC
      , Duration_ms
      , RowsReturned )
    VALUES 
      ( @Id
      , OBJECT_NAME(@@PROCID)
      , 'Complete'
      , @MAC
      , DATEDIFF( ms, @StartDT, SYSUTCDATETIME() ) 
      , @RowCount );
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
          ( Id
          , ReportProcedure
          , MAC
          , Status
          , Duration_ms
          , RowsReturned
          , ErrorData )
        SELECT @Id
             , OBJECT_NAME(@@PROCID)
             , ISNULL( @MAC, 0x0 )
             , 'Error'
             , DATEDIFF( ms, @StartDT, SYSUTCDATETIME() )
             , @RowCount
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
         FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                   , ERROR_NUMBER()
                                   , ERROR_SEVERITY()
                                   , ERROR_STATE()
                                   , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                   , ERROR_LINE()
                                   , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).ReportErrors
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).ReportActivityHistory') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).ReportActivityHistory
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: list recorded activity history   
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).ReportActivityHistory
 ( @ServerName NVARCHAR(128) = NULL )
$(WITH_OPTIONS)
AS
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NCHAR(36)
      , @MAC VARBINARY(128)
      , @Parameters VARBINARY(8000)
      , @RowCount INT
      , @StartDT DATETIME2 = SYSUTCDATETIME()
  BEGIN TRY
    EXEC $(EHA_SCHEMA).OpenSession;
    IF @ServerName IS NULL
      SET @ServerName = @@SERVERNAME;
    SET @Parameters = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                  , FORMATMESSAGE( '@ServerName = ''%s''', @ServerName )
                                  , 1
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book  @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
                    AND ObjectName = OBJECT_NAME(@@PROCID) 
                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                          , CAST(CHECKSUM( Id
                                                         , @@PROCID   
                                                         , ObjectName
                                                         , @Parameters
                                                         , KeyGuid
                                                         , Status ) AS NVARCHAR(128) )
                                          , @MAC ) = 1 ) 
      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    SELECT Id
         , Name
         , Category
         , Action
         , BookingStatus 
         , ActionStatus
         , CAST( DECRYPTBYKEY( ErrorData, 1, Id ) AS NVARCHAR(4000) ) AS ErrorInfo      
         , BookingUTCDT
         , LogUTCDt
         , CreateUser
    FROM (SELECT CAST( b.Id AS NCHAR(36) ) AS Id
               , COALESCE( ba.NodeName
                         , ra.ReportProcedure
                         , oa.CaptureInstance
                         , c.Tag
                         , DECRYPTBYKEY(nv.Name ,1,CAST(nv.Id AS NCHAR(36) ) )
                         , '' ) AS Name
               , CASE WHEN nva.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)'
                      WHEN ba.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)'
                      WHEN ca.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE)' 
                      WHEN na.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)' 
                      WHEN oa.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)' 
                      WHEN ra.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)' 
                      END AS [Category] 
               , b.ObjectName AS Action
               , b.Status AS BookingStatus
               , COALESCE(ba.Status, nva.Status, ca.Status, ra.Status, oa.Status) AS ActionStatus
               , COALESCE( b.ErrorData, ba.ErrorData, nva.ErrorData, ca.ErrorData, oa.ErrorData, ra.ErrorData) AS ErrorData
               , ISNULL( ba.CipherType, '' ) AS CipherType
               , b.CreateUTCDT AS BookingUTCDT
               , COALESCE(ba.CreateUTCDT, nva.CreateUTCDT, ca.CreateUTCDT, oa.CreateUTCDT, ra.CreateUTCDT) AS LogUTCDT 
               , COALESCE(ba.CreateUser, nva.CreateUser, ca.CreateUser, oa.CreateUser, ra.CreateUser) AS CreateUser 
          FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) b
          LEFT JOIN $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) ba
          ON b.Id = ba.Id
          LEFT JOIN $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE) ca
          ON b.Id = ca.Id
          LEFT JOIN $(EHA_SCHEMA).$(CONTAINERS_TABLE) c
          ON ca.Id = c.Id
          LEFT JOIN $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) nva
          ON b.Id = nva.Id
          LEFT JOIN $(EHA_SCHEMA).$(NAMEVALUEs_TABLE) nv
          ON nva.Id = nv.Id
          LEFT JOIN $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE) na
          ON b.Id = na.Id 
          LEFT JOIN $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE) oa
          ON b.Id = oa.Id 
          LEFT JOIN $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) ra
          ON b.Id = ra.Id ) AS derived;
    SET @RowCount = @@ROWCOUNT;
    INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
      ( Id
      , ReportProcedure
      , Status
      , Duration_ms
      , RowsReturned
      , MAC )
      VALUES ( @Id
             , OBJECT_NAME(@@PROCID)
             , 'Complete'
             , DATEDIFF(ms, @StartDT, SYSUTCDATETIME()) 
             , @RowCount 
             , @MAC );
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
          ( Id
          , ReportProcedure
          , Status
          , Duration_ms
          , RowsReturned
          , MAC
          , ErrorData )
        SELECT @Id
             , OBJECT_NAME(@@PROCID)
             , 'Error'
             , DATEDIFF(ms, @StartDT, SYSUTCDATETIME())
             , @RowCount
             , ISNULL(@MAC, 0x0)
             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                           , ErrorInfo 
                           , 1
                           , @Id )
         FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                   , ERROR_NUMBER()
                                   , ERROR_SEVERITY()
                                   , ERROR_STATE()
                                   , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                   , ERROR_LINE()
                                   , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).ReportActivityHistory
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
-------------------------------------------------------------------------------
-- Start DDL trigger data access monitoring 
-------------------------------------------------------------------------------
-- Prevent all - including sysadmin and dbo - that are not members of  
-- $(EHADMIN_ROLE) role from changing the designated EHAdmin db 
-- any sysadmin that understands how it all works will be able
-- to disable the trigger - and if they plan to come back without being 
-- noticed may even re-enable it when done to cover tracks. 
-- DDL trigger cannot be signed. System encryption is the only protection  
-- a second DDL trigger provides DDL_TRIGGER_EVENTS protection against unauth 
-- DROP TRIGGER but both triggers can still be simultaniously disabled by any 
-- sysadmin event queue activation is watching for 
-- AUDIT_DATABASE_OBJECT_MANAGEMENT_EVENT when found will shred EVENTDATA and 
-- re-enable if unauthorized DISABLE TRIGGER before storing as cipher-text  
-------------------------------------------------------------------------------
IF EXISTS (SELECT * FROM sys.triggers
           WHERE name = 'trg_ddl_$(EHDB)' )
  DROP TRIGGER trg_ddl_$(EHDB) ON DATABASE;

GO
CREATE TRIGGER trg_ddl_$(EHDB)
ON DATABASE 
WITH ENCRYPTION, EXECUTE AS SELF
FOR DDL_DATABASE_LEVEL_EVENTS 
AS 
BEGIN
DECLARE @LogRecord NVARCHAR(2048); 
  BEGIN TRY
    IF NOT EXISTS ( SELECT *
                    FROM (SELECT ddl.event.value('LoginName[1]'
                                                , 'NVARCHAR(128)') AS LoginName
                          FROM (SELECT EVENTDATA() AS change) this
                          CROSS APPLY change.nodes('/EVENT_INSTANCE') AS ddl(event) ) q
                    JOIN sys.database_role_members r
                    ON q.LoginName = USER_NAME(r.member_principal_id)
                    WHERE r.role_principal_id = USER_ID('$(EHADMIN_ROLE)') )
    AND USER_NAME() <> 'cdc'
      BEGIN
        SET @LogRecord = FORMATMESSAGE( '%2048.2048s' 
                                      , CAST( EVENTDATA() AS VARCHAR(MAX) ) );
        -- the user will NOT see this message
        EXEC xp_logevent $(MESSAGE_OFFSET)36, @LogRecord, 'ERROR';
        -- the user will see this message
        RAISERROR ('Unable to continue', 16, 1 ) 
      END
  END TRY
  BEGIN CATCH
    ROLLBACK;
    -- the user will see this message
    RAISERROR('Request failed',20,1) WITH LOG;
  END CATCH
END
GO
IF EXISTS (SELECT * FROM sys.triggers
           WHERE name = 'trg_trg_$(EHDB)' )
  DROP TRIGGER trg_trg_$(EHDB) ON DATABASE;
GO
CREATE TRIGGER trg_trg_$(EHDB)
ON DATABASE 
WITH ENCRYPTION, EXECUTE AS SELF
FOR DDL_TRIGGER_EVENTS 
AS 
BEGIN
DECLARE @LogRecord NVARCHAR(2048); 
  BEGIN TRY
    IF NOT EXISTS ( SELECT *
                    FROM (SELECT ddl.event.value('LoginName[1]'
                                                , 'NVARCHAR(128)') AS LoginName
                          FROM (SELECT EVENTDATA() AS change) this
                          CROSS APPLY change.nodes('/EVENT_INSTANCE') AS ddl(event) ) q
                    JOIN sys.database_role_members r
                    ON q.LoginName = USER_NAME(r.member_principal_id)
                    WHERE r.role_principal_id = USER_ID('$(EHADMIN_ROLE)') )
    AND USER_NAME() <> 'cdc'
      BEGIN
        SET @LogRecord = FORMATMESSAGE( '%2048.2048s' 
                                      , CAST( EVENTDATA() AS VARCHAR(MAX) ) );
        -- the user will NOT see this message
        EXEC xp_logevent $(MESSAGE_OFFSET)36, @LogRecord, 'ERROR';
        -- the user will see this message
        RAISERROR ('Unable to continue', 16, 1 ) 
      END
  END TRY
  BEGIN CATCH
    ROLLBACK;
    -- the user will see this message
    RAISERROR('Request failed',20,1) WITH LOG;
  END CATCH
END
GO
---- If the values provided are incorrect or objects are added/removed nothing 
---- will work if this is not valid at install 
---- synonyms cannot be signed, filetable cannot 
--SELECT 'OBJECT_COUNT', $(OBJECT_COUNT)
--UNION ALL
--SELECT 'TABLE_COUNT', $(TABLE_COUNT)
--UNION ALL
--SELECT 'DDL_TRIGGERS', COUNT(*)
--FROM sys.triggers
--WHERE parent_id = 0
--UNION ALL
--SELECT 'DML_TRIGGERS', COUNT(*)
--FROM sys.triggers
--WHERE OBJECT_SCHEMA_NAME(parent_id)  = 'eha'
--UNION ALL
--SELECT 'UNSIGNED_SYNONYMS', COUNT(*) 
--FROM sys.synonyms
--WHERE OBJECT_SCHEMA_NAME (object_id) = 'eha'
--UNION ALL
--SELECT s.type, COUNT(*)
--FROM sys.certificates c
--OUTER APPLY sys.fn_check_object_signatures ( 'CERTIFICATE', c.thumbprint ) s
--WHERE c.name = '$(OBJECT_CERTIFICATE)'
--AND c.pvt_key_encryption_type = 'PW'
--AND OBJECT_SCHEMA_NAME (s.entity_id) = 'eha'
--AND is_signature_valid = 1	
--GROUP BY s.type;
GO
------------------------------------------------------------------------------------------------------
-- a SESSION_SYMMETRIC_KEY must be open before any white-listed procedure is run
-- and every white-listed procedure ends with CLOSE ALL SYMMETRIC KEYS
-- the key is always a temp object encrypted by the   
------------------------------------------------------------------------------------------------------
EXEC $(EHA_SCHEMA).OpenSession; 
INSERT INTO $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
  ( Id
  , ProcId
  , ObjectName
  , Parameters
  , KeyGuid
  , Status )
VALUES ( '00000000-0000-0000-0000-000000000000'
       , 0   
       , 'InstallSpoke.sql'
       , ENCRYPTBYKEY( KEY_GUID( '$(AUDIT_SYMMETRIC_KEY)')
                               , LEFT ( 
N'AUDIT_CERTIFICATE "$(AUDIT_CERTIFICATE)"
AUDIT_CERTIFICATE_ENCRYPTION_PHRASE "$(AUDIT_CERTIFICATE_ENCRYPTION_PHRASE)"
AUDIT_CERTIFICATE_BACKUP_PHRASE "$(AUDIT_CERTIFICATE_BACKUP_PHRASE)"
AUDIT_SYMMETRIC_KEY "$(AUDIT_SYMMETRIC_KEY)"
AUDIT_KEY_ENCRYPTION_ALGORITHM "$(AUDIT_KEY_ENCRYPTION_ALGORITHM)"
AUTHENTICITY_CERTIFICATE "$(AUTHENTICITY_CERTIFICATE)"
AUTHENTICITY_CERTIFICATE_BACKUP_PHRASE "$(AUTHENTICITY_CERTIFICATE_BACKUP_PHRASE)"
CONTAINER_CERTIFICATE "$(CONTAINER_CERTIFICATE)"
CONTAINER_CERTIFICATE_BACKUP_PHRASE "$(CONTAINER_CERTIFICATE_BACKUP_PHRASE)"
EHDB_DMK_BACKUP_PHRASE "$(EHDB_DMK_BACKUP_PHRASE)"
EHDB_DMK_ENCRYPTION_PHRASE "$(EHDB_DMK_ENCRYPTION_PHRASE)"
ERROR_SYMMETRIC_KEY "$(ERROR_SYMMETRIC_KEY)"
ERROR_KEY_ENCRYPTION_ALGORITHM "$(ERROR_KEY_ENCRYPTION_ALGORITHM)"
ERROR_KEY_ENCRYPTION_PHRASE "$(ERROR_KEY_ENCRYPTION_PHRASE)"
ERROR_KEY_SOURCE "$(ERROR_KEY_SOURCE)"
ERROR_KEY_IDENTITY "$(ERROR_KEY_IDENTITY)"
EVENT_CERTIFICATE "$(EVENT_CERTIFICATE)"
EVENT_CERTIFICATE_BACKUP_PHRASE "$(EVENT_CERTIFICATE_BACKUP_PHRASE)"
FILE_CERTIFICATE "$(FILE_CERTIFICATE)"
FILE_CERTIFICATE_ENCRYPTION_PHRASE "$(FILE_CERTIFICATE_ENCRYPTION_PHRASE)"
FILE_CERTIFICATE_BACKUP_PHRASE "$(FILE_CERTIFICATE_BACKUP_PHRASE)"
FILE_SYMMETRIC_KEY "$(FILE_SYMMETRIC_KEY)"
FILE_KEY_ENCRYPTION_ALGORITHM "$(FILE_KEY_ENCRYPTION_ALGORITHM)"
HASHBYTES_ALGORITHM "$(HASHBYTES_ALGORITHM)"
KEY_CONTAINER_PATH "$(KEY_CONTAINER_PATH)"
KEY_CONTAINER_FILE "$(KEY_CONTAINER_FILE)"
LINK_EHDB "$(LINK_EHDB)"
LINK_PASSWORD "$(LINK_PASSWORD)"
LINK_SERVER_ODBC_DSN "$(LINK_SERVER_ODBC_DSN)"
LINK_SERVER "$(LINK_SERVER)"
LINK_USER "$(LINK_USER)"
master_DMK_ENCRYPTION_PHRASE "$(master_DMK_ENCRYPTION_PHRASE)"
master_DMK_BACKUP_PHRASE "$(master_DMK_BACKUP_PHRASE)"
MESSAGE_OFFSET "$(MESSAGE_OFFSET)"
MIN_PHRASE_LENGTH "$(MIN_PHRASE_LENGTH)"
NAME_CERTIFICATE "$(NAME_CERTIFICATE)"
NAME_CERTIFICATE_ENCRYPTION_PHRASE "$(NAME_CERTIFICATE_ENCRYPTION_PHRASE)"
NAME_CERTIFICATE_BACKUP_PHRASE "$(NAME_CERTIFICATE_BACKUP_PHRASE)"
NAME_KEY_ENCRYPTION_ALGORITHM "$(NAME_KEY_ENCRYPTION_ALGORITHM)"
NAME_SYMMETRIC_KEY "$(NAME_SYMMETRIC_KEY)"
OBJECT_CERTIFICATE "$(OBJECT_CERTIFICATE)"
OBJECT_CERTIFICATE_ENCRYPTION_PHRASE "$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)"
OBJECT_CERTIFICATE_BACKUP_PHRASE "$(OBJECT_CERTIFICATE_BACKUP_PHRASE)"
PRIVATE_ENCRYPTION_PHRASE "$(PRIVATE_ENCRYPTION_PHRASE)"
SESSION_SYMMETRIC_KEY "$(SESSION_SYMMETRIC_KEY)"
SESSION_KEY_SOURCE "$(SESSION_KEY_SOURCE)"
SESSION_KEY_IDENTITY "$(SESSION_KEY_IDENTITY)"
SMK_BACKUP_PHRASE "$(SMK_BACKUP_PHRASE)"
TDE_CERTIFICATE "$(TDE_CERTIFICATE)"
TDE_CERTIFICATE_ALGORITHM "$(TDE_CERTIFICATE_ALGORITHM)"
TDE_CERTIFICATE_BACKUP_PHRASE "$(TDE_CERTIFICATE_BACKUP_PHRASE)"
TRUECRYPT_CONTAINER_ENCRYPTION_PHRASE "$(TRUECRYPT_CONTAINER_ENCRYPTION_PHRASE)"
TRUECRYPT_EXE "$(TRUECRYPT_EXE)"
USE_HASH_FOR_FILENAME "$(USE_HASH_FOR_FILENAME)"
VALUE_CERTIFICATE "$(VALUE_CERTIFICATE)"
VALUE_CERTIFICATE_BACKUP_PHRASE "$(VALUE_CERTIFICATE_BACKUP_PHRASE)"
VALUE_KEY_ENCRYPTION_ALGORITHM "$(VALUE_KEY_ENCRYPTION_ALGORITHM)"
VALUE_SYMMETRIC_KEY "$(VALUE_SYMMETRIC_KEY)"
VHD_LETTER "$(VHD_LETTER)"

BOOKINGS_TABLE "$(BOOKINGS_TABLE)"
BACKUP_ACTIVITY_TABLE "$(BACKUP_ACTIVITY_TABLE)"
CONTAINER_ACTIVITY_TABLE "$(CONTAINER_ACTIVITY_TABLE)"
CONTAINERS_TABLE "$(EHA_SCHEMA)"
EHA_SCHEMA "$(EHA_SCHEMA)"
EHADMIN_ROLE "$(EHADMIN_ROLE)"
EHDB "$(EHDB)"
EVENT_NOTIFICATION "$(EVENT_NOTIFICATION)"
FILESTREAM_FILEGROUP "$(FILESTREAM_FILEGROUP)"
FILESTREAM_FILE "$(FILESTREAM_FILE)"
FILETABLE_BACKUPS "$(FILETABLE_BACKUPS)"
FILETABLE_DIRECTORY "$(FILETABLE_DIRECTORY)"
LINK_BOOKINGS_SYNONYM "$(LINK_BOOKINGS_SYNONYM)"
LINK_BACKUP_ACTIVITY_SYNONYM "$(LINK_BACKUP_ACTIVITY_SYNONYM)"
LINK_CONTAINERS_SYNONYM "$(LINK_CONTAINERS_SYNONYM)"
LINK_CONTAINER_ACTIVITY_SYNONYM "$(LINK_CONTAINER_ACTIVITY_SYNONYM)"
LINK_NAMEVALUES_SYNONYM "$(LINK_NAMEVALUES_SYNONYM)"
LINK_NAMEVALUE_ACTIVITY_SYNONYM "$(LINK_NAMEVALUE_ACTIVITY_SYNONYM)"
LINK_NOTIFICATION_ACTIVITY_SYNONYM "$(LINK_NOTIFICATION_ACTIVITY_SYNONYM)"
LINK_OFFSITE_ACTIVITY_SYNONYM "$(LINK_OFFSITE_ACTIVITY_SYNONYM)"
LINK_REPORT_ACTIVITY_SYNONYM "$(LINK_REPORT_ACTIVITY_SYNONYM)"
MASTER_KEY_BACKUP_EXT "$(MASTER_KEY_BACKUP_EXT)"
NAMEVALUE_ACTIVITY_TABLE "$(NAMEVALUE_ACTIVITY_TABLE)"
NAMEVALUES_TABLE "$(NAMEVALUES_TABLE)"
NOTIFICATION_ACTIVITY_TABLE "$(NOTIFICATION_ACTIVITY_TABLE)"
OBJECT_COUNT "$(OBJECT_COUNT)"
OFFSITE_ACTIVITY_TABLE "$(OFFSITE_ACTIVITY_TABLE)"
PRIVATE_KEY_BACKUP_EXT "$(PRIVATE_KEY_BACKUP_EXT)"
PUBLIC_KEY_BACKUP_EXT "$(PUBLIC_KEY_BACKUP_EXT)"
REPORT_ACTIVITY_TABLE "$(REPORT_ACTIVITY_TABLE)"
RESTORE_FILETABLE "$(RESTORE_FILETABLE)"
TABLE_COUNT "$(TABLE_COUNT)"'
                                      , 4000 )
                               , 1  
                               , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) ) )
       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NCHAR(36) )
       , 'OK' );
-- initialize the hierarchy
-- colophon is validated in Book - this node must exist to add nodes
-- each SQL Instance will be a first generation descendent of the root
INSERT  $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
  ( Id
  , DbName
  , Node
  , NodeName
  , BackupName
  , BackupNameBucket
  , UseHash
  , BackupPath
  , BackupPhraseVersion
  , KeyPhraseVersion
  , Colophon
  , Edition
  , MAC
  , Action
  , Status
  , CipherType )
SELECT  Id
      , '' AS DbName
      , HIERARCHYID::GetRoot()
      , 'root'
      , 0x0 AS BackupName
      , 0 AS BackupNameBucket
      , 0 AS UseHash
      , 0x0 AS BackupPath
      , 0 AS BackupPhraseVersion
      , 0 AS KeyPhraseVersion
      , (SELECT CHECKSUM_AGG(BINARY_CHECKSUM(text)) 
         FROM sys.messages 
         WHERE message_id BETWEEN $(MESSAGE_OFFSET)00 AND $(MESSAGE_OFFSET)50 ) AS Colophon
      , 1 AS Edition
      , SignByCert( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                  , CAST(CHECKSUM( Id
                        , ProcId   
                        , ObjectName
                        , Parameters
                        , Status ) AS NVARCHAR(128) ) )
      , 'Install'
      , 'Complete'
      , '' AS CipherType 
FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
WHERE Id = '00000000-0000-0000-0000-000000000000'; 
CLOSE ALL SYMMETRIC KEYS;
GO
-- generate and the salt seed for all hash columns and save in NAMEVALUE_TABLE
EXEC $(EHA_SCHEMA).OpenSession;
EXEC $(EHA_SCHEMA).MakeSalt '$(EHDB)', '$(EHA_SCHEMA)', '$(BACKUP_ACTIVITY_TABLE)', 'BackupNameBucket';
GO
EXEC $(EHA_SCHEMA).OpenSession;
EXEC $(EHA_SCHEMA).MakeSalt '$(EHDB)', '$(EHA_SCHEMA)', '$(BACKUP_ACTIVITY_TABLE)', 'Colophon';
GO
EXEC $(EHA_SCHEMA).OpenSession;
EXEC $(EHA_SCHEMA).MakeSalt '$(EHDB)', '$(EHA_SCHEMA)', '$(NAMEVALUES_TABLE)', 'NameBucket';
GO
EXEC $(EHA_SCHEMA).OpenSession;
EXEC $(EHA_SCHEMA).MakeSalt '$(EHDB)', '$(EHA_SCHEMA)', '$(NAMEVALUES_TABLE)', 'ValueBucket';
GO
-- initialize the container, image and offsite with keys and certificates created by this script
------------------------------------------------------------------------------------------------------
-- SQL Trace "assignment obfuscation" is ineffective for call stored procedures and sp_executesql 
-- SP:Starting of the crypto-objects backups will reveal the secrets 
--http://blogs.msdn.com/b/sqlsecurity/archive/2009/06/10/filtering-obfuscating-sensitive-text-in-sql-server.aspx
-- a temp session symmetric key is used to encrypt before passing - this relies upon crypto-DDL obfuscation
-- the key goes away forever when the user closes the install script's SQL Server connection
-- interesting thing about the temp key is it serializes white-listed procedures due to a key name
-- in use or you do not have permission exception.  
------------------------------------------------------------------------------------------------------
DECLARE @BackupPhrase AS VARBINARY(8000); 
DECLARE @KeyPhrase AS VARBINARY(8000); 
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(SMK_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupServiceMasterKey @BackupPhrase = @BackupPhrase
                                        , @UseHash = $(USE_HASH_FOR_FILENAME)
                                        , @ForceNew = DEFAULT;    
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(master_DMK_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
SET @KeyPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(master_DMK_ENCRYPTION_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupDatabaseMasterKey @DbName = N'master'
                                         , @BackupPhrase = @BackupPhrase
                                         , @KeyPhrase = @KeyPhrase
                                         , @UseHash = $(USE_HASH_FOR_FILENAME)
                                         , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(EHDB_DMK_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
SET @KeyPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(EHDB_DMK_ENCRYPTION_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupDatabaseMasterKey @DbName = N'$(EHDB)'
                                         , @BackupPhrase = @BackupPhrase
                                         , @KeyPhrase = @KeyPhrase
                                         , @UseHash = $(USE_HASH_FOR_FILENAME)
                                         , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(TDE_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
-- Master Key encrypted certs need only a backup file encryption password 
-- password encrypted certs MUST PROVIDE the private key encryption password at time of export 
IF EXISTS (SELECT * FROM master.sys.certificates 
           WHERE name = N'$(TDE_CERTIFICATE)')
    EXEC $(EHA_SCHEMA).BackupCertificate @CertificateName = N'$(TDE_CERTIFICATE)'
                                       , @DbName = N'master'
                                       , @BackupPhrase = @BackupPhrase
                                       , @KeyPhrase = DEFAULT
                                       , @UseHash = $(USE_HASH_FOR_FILENAME)
                                       , @ForceNew = DEFAULT;
-- EHDB backups
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(NAME_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @CertificateName = N'$(NAME_CERTIFICATE)'
                                   , @DbName = N'$(EHDB)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = DEFAULT
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(VALUE_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @CertificateName = N'$(VALUE_CERTIFICATE)'
                                   , @DbName = N'$(EHDB)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = DEFAULT
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(FILE_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @CertificateName = N'$(FILE_CERTIFICATE)'
                                   , @DbName = N'$(EHDB)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = DEFAULT
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(AUTHENTICITY_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @Certificatename = N'$(AUTHENTICITY_CERTIFICATE)'
                                   , @DbName = N'$(EHDB)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = DEFAULT
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(AUDIT_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
SET @KeyPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(AUDIT_CERTIFICATE_ENCRYPTION_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @CertificateName = N'$(AUDIT_CERTIFICATE)'
                                   , @DbName = N'$(EHDB)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = @KeyPhrase
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(EVENT_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @Certificatename = N'$(EVENT_CERTIFICATE)'
                                   , @DbName = N'$(EHDB)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = DEFAULT
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(OBJECT_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
SET @KeyPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @CertificateName = N'$(OBJECT_CERTIFICATE)'
                                   , @DbName = N'$(EHDB)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = @KeyPhrase
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
GO
DECLARE @PrivatePhrase VARBINARY(8000)
      , @KeyIdentity VARBINARY(8000) 
      , @KeySource VARBINARY(8000) 
      , @Value VARBINARY(8000)  
-- SESSION_SYMMETRIC_KEY uses DMK
EXEC $(EHA_SCHEMA).OpenSession;
SET @KeyIdentity = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                       ,  CAST( '$(ERROR_KEY_IDENTITY)' AS NVARCHAR(128) ) ) );
SET @KeySource = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                     ,  CAST( '$(ERROR_KEY_SOURCE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).SavePortableSymmetricKey @KeyName = '$(ERROR_SYMMETRIC_KEY)'
                                          , @KeyIdentity = @KeyIdentity
                                          , @KeySource = @KeySource;
EXEC $(EHA_SCHEMA).OpenSession;
SET @PrivatePhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                         ,  CAST( '$(PRIVATE_ENCRYPTION_PHRASE)' AS NVARCHAR(128) ) ) );
SET @Value = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                 ,  CAST( '$(LINK_PASSWORD)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).SavePrivateValue @Name = 'LINK_PASSWORD'
                                  , @Value = @Value
                                  , @EncryptionPhrase = @PrivatePhrase
                                  , @AuditPrivateData = DEFAULT;
-- already have @PrivatePhrase
EXEC $(EHA_SCHEMA).OpenSession;
SET @Value = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                 ,  CAST( '$(TRUECRYPT_CONTAINER_ENCRYPTION_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).SavePrivateValue @Name = 'TRUECRYPT_CONTAINER_ENCRYPTION_PHRASE'
                                  , @Value = @Value
                                  , @EncryptionPhrase = @PrivatePhrase
                                  , @AuditPrivateData = DEFAULT;
GO
-- dismount and backup Truecrypt container file
:!!if exist $(VHD_LETTER):\ "$(TRUECRYPT_EXE)" /q /s /d X /f)\
--:!!if exist $(FILETABLE_MAPPED_DRIVE_LETTER):\ net use $(FILETABLE_MAPPED_DRIVE_LETTER): /DELETE
GO
EXEC $(EHA_SCHEMA).OpenSession;
EXEC $(EHA_SCHEMA).BackupContainer  '$(KEY_CONTAINER_PATH)'
                                  , '$(KEY_CONTAINER_FILE)'
                                  , 'KeyContainer';
GO
-- re-mount
:!!$(TRUECRYPT_EXE) /v $(KEY_CONTAINER_PATH)$(KEY_CONTAINER_FILE) /l$(VHD_LETTER) /p "$(TRUECRYPT_CONTAINER_ENCRYPTION_PHRASE)" /q /s /m
GO
EXEC $(EHA_SCHEMA).OpenSession;
IF PATINDEX('%[Developer,Enterprise]%', CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128) ) ) > 0 
  EXEC $(EHA_SCHEMA).SendOffsiteCDC    -- ChangeDataCaptuue
ELSE
  EXEC $(EHA_SCHEMA).SendOffsiteTC;  -- Track Changes
GO
DECLARE @RecallId NCHAR(36);
EXEC $(EHA_SCHEMA).OpenSession;
-- only expecting one row
SET @RecallId = ( SELECT TOP (1) Id
                  FROM $(EHA_SCHEMA).$(LINK_CONTAINERS_SYNONYM ) );  
EXEC $(EHA_SCHEMA).RecallContainer @RecallId;
GO
SELECT  @@SERVERNAME + CHAR(46) + DB_NAME() + CHAR(46) + 'ReportErrors' AS [Report]; 
EXEC $(EHA_SCHEMA).ReportErrors;
GO
SELECT  @@SERVERNAME + CHAR(46) + DB_NAME() + CHAR(46) + 'ReportServerSummary' AS [Report] 
EXEC $(EHA_SCHEMA).ReportServerSummary;
GO
SELECT  @@SERVERNAME + CHAR(46) + DB_NAME() + CHAR(46) + 'ReportActivityHistory' AS [Report] 
EXEC $(EHA_SCHEMA).ReportActivityHistory;
GO
-- no keys should be open now
SELECT * FROM sys.openkeys;  
CLOSE ALL SYMMETRIC KEYS;
GO


