:on error exit
-------------------------------------------------------------------------------
-- Encryption Hierarchy Administration Spoke  
-------------------------------------------------------------------------------
-- Pre-requisites 
--  1. SQL Server 2012.
--  2. 10MB reservered secure storage - encrypted disk recommended - at EXPORT_PATH with 
--     read/write access to service account  
--  3. hub database (InstallHub.sql) on SQL Server, SQL Azure or ? 
--     with SPOKE_ADMIN & SPOKE_BROKER users and connectivity to spoke 
--  4. Usable ODBC System DSN to hub database on spoke server 
--  5. Security Log access to service account for SQL Audit is preferred  
--     see BOL: http://msdn.microsoft.com/en-us/library/cc645889.aspx
--     requires enabled application generated|audit object access audit policy setting 
--       auditpol /set /subcategory:"application generated" /success:enable /failure:enable
--     and "generate security audits" permission to users in group policy
--     less secure but can also target Application Event Log without policy changes 
--     or no access to group policy
-- Other notes:
--  *  This script exploits built-in event obfuscation to protect the required secrets 
--     from compromise once entered in the script's template tokens:
--       A. ONLY Use this script in an SSMS/SSDT query window that supports SQLCMD mode 
--       B. ALWAYS replace the example template tokens with YOUR secrets  
--       C. NEVER save this script once YOUR secrets have been entered 
--  *  Database Master Key and certificate for TDE are added to master database of  
--     TDE capable SKUs by this script. (Developer, Enterprise, DataCenter) 
--  *  enables CLR if not already enabled for recall from offsite processing 
--  *  'max text repl size (B)' is set to -1 (size limited only by type)  
--  *  User database is created if specified database does not exist by name
--  *  the owner of this database will be set to sql user with no login by this script   
--  *  Database Master Key is created in this user database if not found   
--  *  passphrase hardness is checked in the CheckPhrase() function
--  *  Algorithm defaults are best practice or otherwise called out as preferred 
--     in current industry and privacy standards, e.g. NIST: FIPS 140-2, PCI-DSS, 
--     SAE16, etc. see: 
--     http://blogs.msdn.com/b/ace_team/archive/2007/09/07/aes-vs-3des-block-ciphers.aspx
--  *  Enterprise, DataCenter, Developer or Evaluation Edition SQL Server 
--     required for TDE, Change Data Capture, SPARSE, FILESTREAM, ?
--  *  SQL Server 2012 required for FileTable, declarative assignment, 
--     THROW, FORMATMESSAGE usage, FORMAT, SHA2_512, ALTER ROLE ADD MEMBER, 
--     AES SMK encryption, ?
--  *  (localdb) will not work FILESTREAM and LinkedServer require instance 
--     running as a service, ?
--  ** This script is a work in progress... 
-------------------------------------------------------------------------------
SET NOCOUNT ON;
GO
-- SQLCMD variable assignments are not exposed in trace output but the batch that runs SET NOCOUNT ON will be! 
-- in live environments use "WITH EXECUTE AS CALLER, ENCRYPTION" 
-- in dev/test use "WITH EXECUTE AS CALLER" to enable debugging 
:setvar WITH_OPTIONS                           "WITH EXECUTE AS CALLER" -- "<[WITH_OPTIONS],VARCHAR,WITH EXECUTE AS CALLER, ENCRYPTION>"                  
-- activation procedures always EXECUTE AS SPOKE_BROKER
:setvar WITH_OPTIONS_FOR_ACTIVATION            ""                       -- "<[WITH_OPTIONS_FOR_ACTIVATION],VARCHAR,, ENCRYPTION>"                         
-- ONLY PHRASE YOU MUST REMEMBER! personalized obfuscation, adds private encryption layer th    
:setvar PRIVATE_ENCRYPTION_PHRASE              "y0ur secreT goes here!" -- "<[PASSPHRASE_ENCRYPTION_PHRASE],VARCHAR,y0ur secreT goes here!>"              
-- key backups go here - read/write req'd by SQL Server service account. restores from hub are located in FileTable subfolder under this location
-- Local path, shared storage of a Windows active-passive cluster, at primary replica of availability group 
:setvar EXPORT_PATH                            "G:\"                    -- "<[EXPORT_PATH],SYSNAME,>"                                                     
-- the life of the key is the life of the user's connection,  lives in tempdb like any # temp object 
:setvar SESSION_SYMMETRIC_KEY                  "#SessionSymmetricKey"    -- "<[SESSION_SYMMETRIC_KEY],SYSNAME,#SessionSymmetricKey>"                      
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
:setvar AUDIT_TO                               "APPLICATION"            -- "<[AUDIT_TO],SYSNAME,APPLICATION|SECURITY>"                                    
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
-- for run-time schema validation - must be correct and unchanged since install or last valid update   
:setvar OBJECT_COUNT                           "58"                     -- "<[OBJECT_COUNT],INT,58>"                                                      
:setvar DELTA                                  "10"                     -- "<[DELTA],INT,10>"                                                             
-- number of active traces allowed during a white listed proc's execution (if default trace enabled set to 1)
:setvar MAX_TRACE_COUNT                        "1"                      -- "<[MAX_TRACE_COUNT,TINYINT,1>"                                                 
-- use the namebucket for the file name (1) or the clear text (0)
:setvar USE_HASH_FOR_FILENAME                  "0"                      -- "<[USE_HASH_FOR_FILENAME],BIT,0>"                                              
-- prefix for event notifications
:setvar EVENT_NOTIFICATION                     "DDLChanges"             -- "<[EVENT_NOTIFICATION],SYSNAME,DDLChanges>"                                    
-- dialog time to wait between data change pushes to hub (basically a scheduled job using service broker)
:setvar TIMER_TIMEOUT                          "120"                    -- "<[TIMER_TIMEOUT],SECONDS,120>                                                 
-- uses DATASOURCE if SQL Azure SERVER_NAME if on-premise, virtual machine or private cloud 
:setvar HUB_DATASOURCE                         "Hub"                    -- "<[HUB_DATASOURCE],SYSNAME,Hub>"                                               
:setvar HUB_SERVER_NAME                        "BWUNDER-PC\ELEVEN"      -- "<[HUB_DATASOURCE],SYSNAME,>"                                                  
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
-- tables
:setvar BOOKINGS_TABLE                         "Bookings"              
:setvar BACKUPS_TABLE                          "Backups"               
:setvar BACKUP_ACTIVITY_TABLE                  "BackupActivity"        
:setvar HUB_ACTIVITY_TABLE                     "HubActivity"           -- created on hub only  
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
IF LEFT('$(SPOKE_DATABASE)',1) = '$' AND PATINDEX('%Management Studio%', APP_NAME() ) > 0
  RAISERROR('Execute this script using SSMS query window in SQLCMD mode.',16,1);
GO
IF LEFT('$(SESSION_SYMMETRIC_KEY)',1) <> '#'
  RAISERROR('The SESSION_SYMMETRIC_KEY must be a session scoped temporary object (e.g., prefixed with one "#" character).',16,1);
GO
USE master;
GO
IF ISNULL(PARSENAME ( CONVERT(NVARCHAR(128), SERVERPROPERTY('ProductVersion')) , 4 ), 0) < 11
  RAISERROR('SQL Server 2012 or later is required.',16, 1);
IF NOT EXISTS( SELECT * 
               FROM sys.server_principals 
               WHERE name = ORIGINAL_LOGIN() 
               AND type = 'U'
               AND IS_SRVROLEMEMBER('sysadmin') = 1 )
  RAISERROR('A Windows authenticated member of the sysadmin fixed server role must execute this script.',16, 1);
-- self-signed certificates are easier prey for authentication relay exploits (aka man in the middle)
IF (SELECT UPPER(encrypt_option) FROM sys.dm_exec_connections WHERE session_id = @@spid) = 'FALSE'
  RAISERROR('Consider a server signed certificate if SSL is unavailable. Unencrypted connections increase risks for data exposure on the wire.  see http://msdn.microsoft.com/en-us/library/ms191192.aspx' ,0 ,0);
-- Configure filestream at install or in SQL Configuration Manger
-- Enable the configuration using sp_configure 'filestream access level', 2; RECONFIGURE;
IF NOT EXISTS ( SELECT * FROM sys.configurations 
                WHERE name = 'filestream access level'
                AND value = 2)
  RAISERROR('FILESTREAM for Transact-SQL and Win32 streaming access must be configured and enabled.',16, 1);
RAISERROR('Verify that no key-logging device or software has captured your PASSPHRASEs  see http://wskills.blogspot.com/2007/01/how-to-find-fight-keyloggers.html and http://msdn.microsoft.com/en-us/library/ff648641.aspx',0,0);
IF NOT ($(MESSAGE_OFFSET) BETWEEN 500 AND 21474836)
  RAISERROR('MESSAGE_OFFSET must be between 500 and 21474836.',16, 1);
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
IF DB_ID('$(SPOKE_DATABASE)') IS NULL
  CREATE DATABASE $(SPOKE_DATABASE); 
GO
USE $(SPOKE_DATABASE);
GO
IF DB_NAME() <> '$(SPOKE_DATABASE)' 
  RAISERROR('Database $(SPOKE_DATABASE) not found. Script aborted.',16, 1);
GO
IF SCHEMA_ID('$(EHA_SCHEMA)') IS NULL
  BEGIN
    EXEC sp_executesql N'CREATE SCHEMA [$(EHA_SCHEMA)]';
    -- with Common Criteria enabled this overrides any column level GRANT too 
    DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::$(EHA_SCHEMA) TO PUBLIC;
  END
GO
-- for local authorization
IF SUSER_SID ( '$(SPOKE_ADMIN)' ) IS NULL
  CREATE LOGIN [$(SPOKE_ADMIN)] WITH PASSWORD = '$(SPOKE_ADMIN_PASSWORD)';  
IF USER_ID ('$(SPOKE_ADMIN)') IS NULL
  CREATE USER [$(SPOKE_ADMIN)] FROM LOGIN $(SPOKE_ADMIN);  
-- for hub access
IF USER_ID ('$(SPOKE_BROKER)') IS NULL
  CREATE USER [$(SPOKE_BROKER)] WITHOUT LOGIN;  
GO
-- enough of the broker infrastructure to start DDL event notifications  
IF NOT EXISTS ( SELECT * FROM sys.service_queues 
                WHERE name = 'TargetQueue'
                AND schema_id = SCHEMA_ID( '$(EHA_SCHEMA)' ) ) 
  CREATE QUEUE [$(EHA_SCHEMA)].[TargetQueue] 
  WITH RETENTION = ON;
GO
IF NOT EXISTS ( SELECT * FROM sys.services 
                WHERE name = '$(EHA_SCHEMA)TargetService' )
  CREATE SERVICE $(EHA_SCHEMA)TargetService AUTHORIZATION [$(SPOKE_ADMIN)]
  ON QUEUE $(EHA_SCHEMA).TargetQueue 
    ( [http://schemas.microsoft.com/SQL/Notifications/PostEventNotification] );
GO
IF NOT EXISTS (SELECT * FROM sys.event_notifications WHERE name = '$(EVENT_NOTIFICATION)Db')
  CREATE EVENT NOTIFICATION $(EVENT_NOTIFICATION)Db 
  ON DATABASE 
  FOR DDL_DATABASE_LEVEL_EVENTS 
  TO SERVICE '$(EHA_SCHEMA)TargetService', 'current database' ;
GO
IF NOT EXISTS (SELECT * FROM sys.server_event_notifications WHERE name = '$(EVENT_NOTIFICATION)Srv')
  CREATE EVENT NOTIFICATION $(EVENT_NOTIFICATION)Srv 
  ON SERVER 
  FOR AUDIT_DATABASE_OBJECT_MANAGEMENT_EVENT
    , ALTER_CERTIFICATE
    , CREATE_CERTIFICATE
    , ALTER_MASTER_KEY
    , CREATE_MASTER_KEY
    , ALTER_SERVICE_MASTER_KEY  
  TO SERVICE '$(EHA_SCHEMA)TargetService', 'current database' ;
GO
-- used for tvps to pass encrypted name/value 
IF TYPE_ID('NAMEVALUETYPE') IS NULL
  CREATE TYPE NAMEVALUETYPE AS TABLE
	  ( Name VARBINARY(8000) NOT NULL
	  , Value VARBINARY(8000) NOT NULL ); 	 
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
ALTER DATABASE $(SPOKE_DATABASE) SET AUTO_CLOSE ON;    
GO
-- intended for use only by mad scientists at M$ labs and the catatonically insane me thinks
ALTER DATABASE $(SPOKE_DATABASE) SET TRUSTWORTHY OFF;    
GO
-- prevents elevation of authority attacks by users connected to other databases within the SQL Server 
ALTER DATABASE $(SPOKE_DATABASE) SET DB_CHAINING OFF; 
GO
-- provides the ability to review state after the fact using point-in-time restore
ALTER DATABASE $(SPOKE_DATABASE) SET RECOVERY FULL;  
GO
--FileTable does not like row versioning - always use WITH (READCOMMITTED LOCKS_ hint to query the FileTable
ALTER DATABASE $(SPOKE_DATABASE) SET READ_COMMITTED_SNAPSHOT ON;
GO
-- move dbo to sa so no conflicts when current user added to role
-- sa should also be disabled, and may also be renamed 
-- SQL authentication should also be disabled.
IF NOT EXISTS ( SELECT * FROM sys.databases
                WHERE name = '$(SPOKE_DATABASE)' 
                AND owner_sid = USER_SID(USER_ID('$(SPOKE_BROKER)') ) )
  BEGIN
    IF (SELECT name FROM sys.server_principals WHERE sid = 0x01) = 'sa'
      RAISERROR('Consider renaming login [sa].  see http://blogs.msdn.com/b/data_otaku/archive/2011/06/22/secure-the-authentication-process.aspx', 0, 0);
    IF (SELECT is_disabled FROM sys.server_principals WHERE sid = 0x01) = 0
      RAISERROR('Consider disabling server principal [0x01] (by default named sa) see http://lmgtfy.com/?q=brute+force+sa+password+attack',0 ,0); 
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
      RAISERROR('Consider enabling Common Criteria (CC) compliance, even if you do not download, install and enable the Common Criteria Trace.  see http://msdn.microsoft.com/en-us/library/bb326650(v=SQL.110).aspx', 0, 0);
    ALTER AUTHORIZATION ON DATABASE::$(SPOKE_DATABASE) TO $(SPOKE_BROKER); 
  END
GO

IF NOT EXISTS ( SELECT * FROM sys.database_principals 
                WHERE name = N'$(SPOKE_ADMIN_ROLE)' 
                AND type = 'R')
  CREATE ROLE [$(SPOKE_ADMIN_ROLE)]

GRANT SELECT, INSERT ON SCHEMA::$(EHA_SCHEMA) TO $(SPOKE_ADMIN_ROLE);
DENY UPDATE, DELETE ON SCHEMA::$(EHA_SCHEMA) TO $(SPOKE_ADMIN_ROLE);

ALTER ROLE [$(SPOKE_ADMIN_ROLE)]
ADD MEMBER $(SPOKE_ADMIN);

IF NOT EXISTS ( SELECT * 
                FROM sys.database_principals 
                WHERE name = ORIGINAL_LOGIN() ) 
  BEGIN
    DECLARE @CreateUserDDL NVARCHAR(512);
    SET @CreateUserDDL = 'CREATE USER [' + ORIGINAL_LOGIN() + '] FROM LOGIN [' + ORIGINAL_LOGIN() + '];'
                       + 'ALTER ROLE $(SPOKE_ADMIN_ROLE) ADD MEMBER [' + ORIGINAL_LOGIN() + '];';
    EXEC sp_executesql @CreateUserDDL;
  END 
GO
-- linked server uses ODBC DSN using ODBCad32.exe 
IF NOT EXISTS (SELECT * FROM sys.servers
                WHERE NAME = N'$(HUB_LINKED_SERVER_NAME)' )
  IF SERVERPROPERTY('Edition') = 'SQL Azure'
    EXEC dbo.sp_addlinkedserver @server = N'$(HUB_LINKED_SERVER_NAME)'
                              , @srvproduct = N'Any'
                              , @provider=N'MSDASQL'
                              , @datasrc=N'$(HUB_DATASOURCE)'; -- ODBC DSN to Hub
  ELSE 
    EXEC dbo.sp_addlinkedserver @server = N'$(HUB_LINKED_SERVER_NAME)'
                              , @srvproduct = N''
                              , @provider=N'SQLNCLI'
                              , @datasrc=N'$(HUB_SERVER_NAME)'; -- @@SERVERNAME of Hub
  
GO
IF NOT EXISTS (SELECT * 
               FROM sys.linked_logins l
               JOIN sys.servers s
               ON l.server_id = s.server_id
               WHERE s.name = N'$(HUB_LINKED_SERVER_NAME)' 
               AND l.remote_name = N'$(SPOKE_ADMIN)')
  EXEC dbo.sp_addlinkedsrvlogin @rmtsrvname = N'$(HUB_LINKED_SERVER_NAME)'
                              , @useself = N'False'
                              , @locallogin = N'$(SPOKE_ADMIN)'
                              , @rmtuser = N'$(SPOKE_ADMIN)'
                              , @rmtpassword='$(SPOKE_ADMIN_PASSWORD)';
GO
IF NOT EXISTS (SELECT * 
               FROM sys.linked_logins l
               JOIN sys.servers s
               ON l.server_id = s.server_id
               WHERE s.name = N'$(HUB_LINKED_SERVER_NAME)' 
               AND l.remote_name = N'$(SPOKE_BROKER)')
  EXEC dbo.sp_addlinkedsrvlogin @rmtsrvname = N'$(HUB_LINKED_SERVER_NAME)'
                              , @useself = N'False'
                              , @locallogin = N'$(SPOKE_BROKER)'
                              , @rmtuser = N'$(SPOKE_BROKER)'
                              , @rmtpassword='$(SPOKE_BROKER_PASSWORD)';
GO
-- in-line crypto-functions will always obfuscate in event output
USE master;
-- only TDE capable - e.g. Developer, Enterprise, and Data Center SKUs
IF PATINDEX('%[Developer,Enterprise]%', CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128) ) ) > 0 
  BEGIN
    -- Certificate in master for TDE encrypted by master DMK (which is encrypted by the SMK (DPAPI)) 
    IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE symmetric_key_id = 101)
      CREATE MASTER KEY ENCRYPTION BY PASSWORD = '$(master_DMK_ENCRYPTION_PHRASE)'
    ELSE 
      OPEN MASTER KEY DECRYPTION BY PASSWORD = '$(master_DMK_ENCRYPTION_PHRASE)';
    IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = '$(TDE_CERTIFICATE)')
      CREATE CERTIFICATE $(TDE_CERTIFICATE) WITH SUBJECT = '$(SPOKE_DATABASE) TDE DEK';
  END
GO
USE $(SPOKE_DATABASE);
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
IF CERT_ID ('$(FILE_CERTIFICATE)') IS NULL
  CREATE CERTIFICATE $(FILE_CERTIFICATE) 
  WITH SUBJECT = 'File System literal Column Encryption';
IF KEY_GUID ('$(FILE_SYMMETRIC_KEY)') IS NULL
	CREATE SYMMETRIC KEY $(FILE_SYMMETRIC_KEY) 
	WITH ALGORITHM = $(FILE_KEY_ENCRYPTION_ALGORITHM) 
	ENCRYPTION BY CERTIFICATE $(FILE_CERTIFICATE);
IF CERT_ID ('$(NAME_CERTIFICATE)') IS NULL
  CREATE CERTIFICATE $(NAME_CERTIFICATE) 
  WITH SUBJECT = 'Name Column Encryption';
IF KEY_GUID ('$(NAME_SYMMETRIC_KEY)') IS NULL
	CREATE SYMMETRIC KEY $(NAME_SYMMETRIC_KEY) 
	WITH ALGORITHM = $(NAME_KEY_ENCRYPTION_ALGORITHM) 
	ENCRYPTION BY CERTIFICATE $(NAME_CERTIFICATE);
IF CERT_ID ('$(VALUE_CERTIFICATE)') IS NULL
  CREATE CERTIFICATE $(VALUE_CERTIFICATE) 
  WITH SUBJECT = 'Value Column Encryption';
IF KEY_GUID ('$(VALUE_SYMMETRIC_KEY)') IS NULL
	CREATE SYMMETRIC KEY $(VALUE_SYMMETRIC_KEY) 
	WITH ALGORITHM = $(VALUE_KEY_ENCRYPTION_ALGORITHM) 
	ENCRYPTION BY CERTIFICATE $(VALUE_CERTIFICATE);
-- signed cert is not a dependant of the DMK - only the one(s) responsible for change
-- should to be allowed to open this certificate or view its secrets 
IF CERT_ID ('$(OBJECT_CERTIFICATE)') IS NULL
  CREATE CERTIFICATE $(OBJECT_CERTIFICATE)
	ENCRYPTION BY PASSWORD = N'$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)'
  WITH SUBJECT = N'Encryption Hieararchy Administrator db object Signing';
-- with no password on the cert and the DMK not encrypted by the SMK, the DMK must be open to use
-- only the data owner(s) should be allowed to open this certificate , i.e. have the DMK PASSPHRASE
IF CERT_ID ('$(AUTHENTICITY_CERTIFICATE)') IS NULL
  CREATE CERTIFICATE $(AUTHENTICITY_CERTIFICATE) 
  WITH SUBJECT = 'Encryption Hieararchy Administrator Booking Gauntlet T-shirt';
-- with no password on the cert and the DMK not encrypted by the SMK, the DMK must be open to use
-- only the data owner(s) should be allowed to open this certificate , i.e. have the DMK PASSPHRASE
IF CERT_ID ('$(EVENT_CERTIFICATE)') IS NULL
  CREATE CERTIFICATE $(EVENT_CERTIFICATE) 
  WITH SUBJECT = 'Signature of EventData applied at activation';
-- error cert is independant from DMK and portable 
-- create same key on any SQL Server 2005/2008/2012 by providing name, source and identity
-- not as secure becasue if anyone gets name, source and identity they can see the cipher text in clear text
-- not quite as bad as a shared password but close, very important to rotate encryption password often
IF KEY_GUID ('$(ERROR_SYMMETRIC_KEY)') IS NULL
	CREATE SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY) 
    WITH ALGORITHM = $(ERROR_KEY_ENCRYPTION_ALGORITHM)
     , KEY_SOURCE = '$(ERROR_KEY_SOURCE)'
     , IDENTITY_VALUE =  '$(ERROR_KEY_IDENTITY)'
	ENCRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
-- audit certificate is independent FROM DMK 
IF CERT_ID('$(AUDIT_CERTIFICATE)') IS NULL
  CREATE CERTIFICATE $(AUDIT_CERTIFICATE) 
	ENCRYPTION BY PASSWORD = '$(AUDIT_CERTIFICATE_ENCRYPTION_PHRASE)'
  WITH SUBJECT = 'Encryption Hierarchy Administrator Audit Trail';
-- audit key is sticky to the database 
IF KEY_GUID ('$(AUDIT_SYMMETRIC_KEY)') IS NULL
	CREATE SYMMETRIC KEY $(AUDIT_SYMMETRIC_KEY) 
	WITH ALGORITHM = $(AUDIT_KEY_ENCRYPTION_ALGORITHM) 
	ENCRYPTION BY CERTIFICATE $(AUDIT_CERTIFICATE);
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
        , KeyGuid NVARCHAR(36) NOT NULL
        , Status NVARCHAR (36) NOT NULL
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
-- record backup and restore attempts to BACKUP_ACTIVITY_TABLE upon completion/failure
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
		    , BackupName VARBINARY(8000) NOT NULL -- CalculateCipherLen('ValueKey',896,1)=964 NVARCHAR(448)
		    , BackupNameBucket INT NOT NULL 
        , UseHash BIT NOT NULL          
		    , BackupPath VARBINARY(8000) NOT NULL -- CalculateCipherLen('ValueKey',2048,1)=2116 NVARCHAR(1024)
		    , BackupPhraseVersion SMALLINT NOT NULL
		    , KeyPhraseVersion SMALLINT NULL
        , Colophon INT NOT NULL  -- checksum of the hash of key guids and cert thumbprints- not presumed unique
        , Edition SMALLINT NOT NULL  -- sequence of backups made for the current Colophon       
		      CONSTRAINT dft_$(BACKUP_ACTIVITY_TABLE)__Version 
		      DEFAULT (1)
        , MAC VARBINARY (128) NOT NULL
		    , Action NVARCHAR (128) NOT NULL
		    , Status NVARCHAR (36) NOT NULL
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
    CREATE NONCLUSTERED INDEX ixn_$(BACKUP_ACTIVITY_TABLE)__Node__ServerName      -- this gives a warning but low risk of even 5 byte HIERARCHYIDs here
    ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)(Node, ServerName);                  -- 38 bits for 6 level 100,000 nodes acc'd BOL (~5 bytes), only 4 level here
    CREATE NONCLUSTERED INDEX ixn_$(BACKUP_ACTIVITY_TABLE)__Level__Node__ServerName -- breadth-first index - same warning as depth first index
    ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)(Level, Node, ServerName);             
    CREATE NONCLUSTERED INDEX ixn_$(BACKUP_ACTIVITY_TABLE)__Colophon__Edition__ServerName
    ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) (Colophon, Edition, ServerName); 
    CREATE NONCLUSTERED INDEX ixn_$(BACKUP_ACTIVITY_TABLE)__BackupNameBucket__ServerName
    ON $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) (BackupNameBucket, ServerName); 
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
-- every procedure that writes to or reads from NAMEVALUES_TABLE gets a row upon completion
IF OBJECT_ID('$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)') IS NULL
  BEGIN
	  CREATE TABLE $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
		  ( Id UNIQUEIDENTIFIER NOT NULL ROWGUIDCOL 
      , ServerName NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(NAMEVALUE_ACTIVITY_TABLE)__ServerName
		    DEFAULT ( @@SERVERNAME )
      , MAC VARBINARY(128) NOT NULL
		  , Action VARCHAR (128) NOT NULL
		  , Status NVARCHAR (36) NOT NULL
            CONSTRAINT ck_$(NAMEVALUE_ACTIVITY_TABLE)__Status 
            CHECK (Status IN ( 'Complete'
                             , 'Error'
                             , 'Instead'
                             , 'Invalid'
                             , 'Valid' ) )
		  , ErrorData VARBINARY(8000) SPARSE NULL 
		  , CreateUTCDT DATETIME NOT NULL
		    CONSTRAINT dft_$(NAMEVALUE_ACTIVITY_TABLE)__CreateUTCDT
		    DEFAULT ( SYSUTCDATETIME() )
		  , CreateUser NVARCHAR(128)
		    CONSTRAINT dft_$(NAMEVALUE_ACTIVITY_TABLE)__CreateUser
		    DEFAULT ( ORIGINAL_LOGIN() )  
		  , CONSTRAINT pk_$(NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName
		    PRIMARY KEY ( Id, ServerName )
		  , CONSTRAINT fk_$(NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
		    FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );
    ADD SIGNATURE TO $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
  END
GO
-- the send offsite is automated by Service Broker and Change Data Capture (preferred) or Change Tracking (if CDC not available) 
-- the recall and restore to FileTable always happen together but each gets its own log record and to different logging tables 
IF OBJECT_ID('$(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)') IS NULL
  BEGIN
    CREATE TABLE $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)
      ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR(128) NOT NULL 
	      CONSTRAINT dft_$(SPOKE_ACTIVITY_TABLE)__ServerName
	      DEFAULT (@@SERVERNAME)
      , MAC VARBINARY(128) NOT NULL
      , Action NVARCHAR (128)
      , Status NVARCHAR (36)
        CONSTRAINT ck_$(SPOKE_ACTIVITY_TABLE)__Status 
        CHECK ( Status IN ( 'Complete'
                          , 'Error' ) )
      , ErrorData VARBINARY(8000) SPARSE NULL
      , CreateUTCDT DATETIME
        CONSTRAINT dft_$(SPOKE_ACTIVITY_TABLE)__CreateUTCDT
		    DEFAULT (SYSUTCDATETIME())
	    , CreateUser NVARCHAR(128) NOT NULL
		    CONSTRAINT dft_$(SPOKE_ACTIVITY_TABLE)__CreateUser
		    DEFAULT ( ORIGINAL_LOGIN() ) 
      , CONSTRAINT pk_$(SPOKE_ACTIVITY_TABLE)__Id__ServerName
        PRIMARY KEY (Id, ServerName ) 
      , CONSTRAINT fk_$(SPOKE_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
        FOREIGN KEY ( Id, ServerName ) 
        REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );   
    ADD SIGNATURE TO $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
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
      , Action NVARCHAR (128)
      , Status NVARCHAR (36)
        CONSTRAINT ck_$(NOTIFICATION_ACTIVITY_TABLE)__Status 
        CHECK ( Status IN ( 'Complete'
                          , 'No Changes'
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
	    , Status NVARCHAR (36) NOT NULL
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
-- steps to a filetable
-- 1. enable FILESTREAM on instance level 
--    (SQL Confg. Mgr. or SQL install by Windows Admin)
-- 2. add FILESTREAM file group
  IF NOT EXISTS ( SELECT * FROM sys.filegroups
                  WHERE name = '$(FILESTREAM_FILEGROUP)' )
    ALTER DATABASE $(SPOKE_DATABASE)
    ADD FILEGROUP $(FILESTREAM_FILEGROUP) 
    CONTAINS FILESTREAM;
  GO
-- 3. Add a file to the file group 
  IF NOT EXISTS ( SELECT * FROM sys.database_files
                  WHERE name = '$(FILETABLE_DIRECTORY)' )
      ALTER DATABASE $(SPOKE_DATABASE)
      ADD FILE 
      (
          NAME = '$(FILETABLE_DIRECTORY)',
          FILENAME = '$(EXPORT_PATH)$(FILETABLE_DIRECTORY)'
      )
      TO FILEGROUP $(FILESTREAM_FILEGROUP);
GO
-- 4. Set directory's file system access 
  IF NOT EXISTS ( SELECT * 
                  FROM sys.database_filestream_options
                  WHERE database_id = DB_ID()
                  AND directory_name = '$(FILETABLE_DIRECTORY)' 
                  AND non_transacted_access = 2) 
    ALTER DATABASE $(SPOKE_DATABASE)
    SET FILESTREAM ( NON_TRANSACTED_ACCESS = FULL               
                   , DIRECTORY_NAME = '$(FILETABLE_DIRECTORY)' );
GO
  -- 5. Add a FileTable 
  IF NOT EXISTS ( SELECT * 
                  FROM sys.filetables
                  WHERE directory_name = '$(RESTORES_FILETABLE)' ) 
  BEGIN
    CREATE TABLE $(EHA_SCHEMA).$(RESTORES_FILETABLE) AS FileTable;
    ADD SIGNATURE TO $(EHA_SCHEMA).$(RESTORES_FILETABLE) 
    BY CERTIFICATE $(OBJECT_CERTIFICATE)
    WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
  END
GO
-----------------------------------------------------------------
-- Offsite 
-- change data capture if available else change tracking
-----------------------------------------------------------------
CREATE SYNONYM [$(EHA_SCHEMA)].[$(BOOKINGS_SYNONYM)] 
  FOR [$(HUB_LINKED_SERVER_NAME)].[$(HUB_DATABASE)].[$(EHA_SCHEMA)].[$(BOOKINGS_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(BACKUP_ACTIVITY_SYNONYM)] 
  FOR [$(HUB_LINKED_SERVER_NAME)].[$(HUB_DATABASE)].[$(EHA_SCHEMA)].[$(BACKUP_ACTIVITY_TABLE)]
GO
-- table only exists at hub
CREATE SYNONYM [$(EHA_SCHEMA)].[$(HUB_ACTIVITY_SYNONYM)] 
  FOR [$(HUB_LINKED_SERVER_NAME)].[$(HUB_DATABASE)].[$(EHA_SCHEMA)].[$(HUB_ACTIVITY_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(NAMEVALUES_SYNONYM)] 
  FOR [$(HUB_LINKED_SERVER_NAME)].[$(HUB_DATABASE)].[$(EHA_SCHEMA)].[$(NAMEVALUES_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(NAMEVALUE_ACTIVITY_SYNONYM)] 
  FOR [$(HUB_LINKED_SERVER_NAME)].[$(HUB_DATABASE)].[$(EHA_SCHEMA)].[$(NAMEVALUE_ACTIVITY_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(NOTIFICATION_ACTIVITY_SYNONYM)] 
  FOR [$(HUB_LINKED_SERVER_NAME)].[$(HUB_DATABASE)].[$(EHA_SCHEMA)].[$(NOTIFICATION_ACTIVITY_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(SPOKE_ACTIVITY_SYNONYM)] 
  FOR [$(HUB_LINKED_SERVER_NAME)].[$(HUB_DATABASE)].[$(EHA_SCHEMA)].[$(SPOKE_ACTIVITY_TABLE)]
GO
CREATE SYNONYM [$(EHA_SCHEMA)].[$(REPORT_ACTIVITY_SYNONYM)] 
  FOR [$(HUB_LINKED_SERVER_NAME)].[$(HUB_DATABASE)].[$(EHA_SCHEMA)].[$(REPORT_ACTIVITY_TABLE)]
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
                                 , @role_name = '$(SPOKE_ADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(BACKUP_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(BACKUP_ACTIVITY_TABLE)' 
                                 , @role_name = '$(SPOKE_ADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(NAMEVALUES_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(NAMEVALUES_TABLE)' 
                                 , @role_name = '$(SPOKE_ADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(NAMEVALUE_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(NAMEVALUE_ACTIVITY_TABLE)' 
                                 , @role_name = '$(SPOKE_ADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(NOTIFICATION_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(NOTIFICATION_ACTIVITY_TABLE)' 
                                 , @role_name = '$(SPOKE_ADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(SPOKE_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(SPOKE_ACTIVITY_TABLE)' 
                                 , @role_name = '$(SPOKE_ADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
    IF ( SELECT is_tracked_by_cdc FROM sys.tables
         WHERE name = '$(REPORT_ACTIVITY_TABLE)'
         AND schema_id = SCHEMA_ID('$(EHA_SCHEMA)') ) = 0 
      EXEC sys.sp_cdc_enable_table @source_schema = '$(EHA_SCHEMA)'
                                 , @source_name = '$(REPORT_ACTIVITY_TABLE)' 
                                 , @role_name = '$(SPOKE_ADMIN_ROLE)'
                                 , @supports_net_changes = 1; 
  END
ELSE -- change tracking 
  BEGIN
    ALTER DATABASE $(SPOKE_DATABASE)
    SET CHANGE_TRACKING = ON
    (AUTO_CLEANUP = OFF); --(CHANGE_RETENTION = 2 DAYS, AUTO_CLEANUP = ON)
    ALTER TABLE $(EHA_SCHEMA).$(BOOKINGS_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = OFF);
    ALTER TABLE $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = OFF);
    ALTER TABLE $(EHA_SCHEMA).$(NAMEVALUES_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = OFF);
    ALTER TABLE $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = OFF);
    ALTER TABLE $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = OFF);
    ALTER TABLE $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = OFF);
    ALTER TABLE $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)
    ENABLE CHANGE_TRACKING
    WITH (TRACK_COLUMNS_UPDATED = OFF);
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
EXEC sp_addmessage $(MESSAGE_OFFSET)36, 16, 'Authorization failure DbName: $(SPOKE_DATABASE) Schema:$(EHA_SCHEMA): User %s  Action:%s', 'us_english', 'TRUE' , 'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)37, 16, 'ANSI_PADDING must be ON for SQL Server encryption.', 'us_english','FALSE' ,'replace'
EXEC sp_addmessage $(MESSAGE_OFFSET)38, 16, 'A duplicate encryption hierarchy node Backup must specify @ForceNew = 1 (%s %s)', 'us_english','FALSE' ,'replace'
GO
-- DEK encrypted by cert in master db shares no dependency with the phrase encrypted DMK    
IF PATINDEX('%[Developer,Enterprise]%', CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128) ) ) > 0
  BEGIN
    DECLARE @TDEDDL NVARCHAR(1024);
    SET @TDEDDL = 'IF NOT EXISTS ( SELECT *' + SPACE(1) 
                +                 'FROM sys.dm_database_encryption_keys' + SPACE(1) 
                +                 'WHERE database_id = DB_ID()' + SPACE(1)
                +                 'AND DB_NAME() = ''$(SPOKE_DATABASE)'' )' + SPACE(1) 
                +   'BEGIN' + SPACE(1) 
                +     'CREATE DATABASE ENCRYPTION KEY' + SPACE(1)
                +     'WITH ALGORITHM = $(TDE_CERTIFICATE_ALGORITHM)' + SPACE(1)
                +     'ENCRYPTION BY SERVER CERTIFICATE $(TDE_CERTIFICATE);' + SPACE(1)
                +     'ALTER DATABASE $(SPOKE_DATABASE)' + SPACE(1)
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
    IF (SELECT IIF ( COUNT(s.entity_id) = $(OBJECT_COUNT) - $(DELTA), 1, 0 ) 
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
                      WHERE [role_principal_id] = USER_ID('$(SPOKE_ADMIN_ROLE)')
                      AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                      AND SYSTEM_USER = ORIGINAL_LOGIN() ) ) = 1
      BEGIN
        -- valid schema+user always gets an open audit key for booking
        OPEN SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)]
        DECRYPTION BY CERTIFICATE [$(AUDIT_CERTIFICATE)]
        WITH PASSWORD = '$(AUDIT_CERTIFICATE_ENCRYPTION_PHRASE)';

        -- start session only if proc called from command line or 
        IF KEY_GUID('$(SESSION_SYMMETRIC_KEY)') IS NULL
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
  , @Id NVARCHAR(36) OUTPUT
  , @MAC VARBINARY(128) OUTPUT )
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @Thumbprint VARBINARY(32)
      , @Reason NVARCHAR (36)
      , @ErrorData VARBINARY(8000);
DECLARE @output TABLE (Id NVARCHAR(36), CkSum NVARCHAR(128) );
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
        AND SUM ( ISNULL( s.is_signature_valid, 0 ) ) = $(OBJECT_COUNT) - $(DELTA) ) <> 1
      RAISERROR($(MESSAGE_OFFSET)30,16,1);
    SET @Reason = 'messages';
    -- text of any of our sys.messages is changed from the same value computed at install 
    -- in and stored in the colophon of the 0 row or the 0 row does not exist
    IF ( SELECT CHECKSUM_AGG( BINARY_CHECKSUM(text) )  
          FROM sys.messages
          WHERE message_id between $(MESSAGE_OFFSET)00 AND $(MESSAGE_OFFSET)50 ) 
         <>
        ( SELECT a.Colophon
          FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) AS a
          JOIN $(EHA_SCHEMA).$(BOOKINGS_TABLE) AS b 
          ON a.Id = b.Id
          AND a.ServerName = b.ServerName
          WHERE a.Id = b.KeyGuid -- install uses guid of the session key as Id
          AND b.ServerName = @@SERVERNAME ) 
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
         WHERE is_default <> 1 ) > $(MAX_TRACE_COUNT)-- could also check for known vulnerable events    
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
                    WHERE [role_principal_id] = USER_ID('$(SPOKE_ADMIN_ROLE)')
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
                                     , 'BackupDatabaseMasterKey' 
                                     , 'BackupServiceMasterKey' 
                                     , 'CertificateBackupsByThumbprint' 
                                     , 'GetPortableSymmetricKey'
                                     , 'GetPrivateValue'
                                     , 'MakeSalt' 
                                     , 'ReportActivityHistory' 
                                     , 'ReportErrors' 
                                     , 'ReportServerSummary'
                                     , 'RestoreCertificate' 
                                     , 'RestoreDatabaseMasterKey' 
                                     , 'RestoreServiceMasterKey' 
                                     , 'AddPortableSymmetricKey'
                                     , 'AddPrivateValue'
                                     , 'PushChanges' 
                                     , 'SelectNameValue' 
                                     , 'ValidateNameValue' 
                                     , '$(EVENT_NOTIFICATION)Activation'
                                     , 'trg_$(BOOKINGS_TABLE)'
                                     , 'trg_$(NAMEVALUES_TABLE)'
                                     , 'trg_$(NAMEVALUE_ACTIVITY_TABLE)'
                                     , 'trg_$(BACKUP_ACTIVITY_TABLE)'
                                     , 'trg_$(NOTIFICATION_ACTIVITY_TABLE)'
                                     , 'trg_$(SPOKE_ACTIVITY_TABLE)'
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
           , CAST( KEY_GUID( '$(SESSION_SYMMETRIC_KEY)' ) AS NVARCHAR(36) )
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
         , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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

----------
-- Audit
----------
USE master ;
GO
IF NOT EXISTS (SELECT * FROM sys.server_audits 
                WHERE name = '$(EHA_SCHEMA)SchemaAudit' ) 
  CREATE SERVER AUDIT $(EHA_SCHEMA)SchemaAudit
        TO $(AUDIT_TO)_LOG;
GO
ALTER SERVER AUDIT ehaSchemaAudit 
WITH (STATE = ON) ;
GO
USE $(SPOKE_DATABASE);
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
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
           , 'Instead'
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
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
         , FORMATMESSAGE ( 'Instead %s: Id: %s' 
                         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
                         , CAST( d.Id AS NVARCHAR(36) ) )
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
         , FORMATMESSAGE ( 'Instead %s: Id: %s' 
                         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
                         , CAST( d.Id AS NVARCHAR(36) ) )
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
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
         , FORMATMESSAGE ( 'Instead %s: Id: %s' 
                         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
                         , CAST( d.Id AS NVARCHAR(36) ) )
         , 'Complete'  
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
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
         , FORMATMESSAGE ( 'Instead %s: Id: %s' 
                         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
                         , CAST( d.Id AS NVARCHAR(36) ) )
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
         , FORMATMESSAGE ( 'Instead %s: Id: %s' 
                         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
                         , CAST( d.Id AS NVARCHAR(36) ) )
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
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
         , 'Instead' 
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
IF OBJECT_ID('$(EHA_SCHEMA).trg_$(SPOKE_ACTIVITY_TABLE)') IS NOT NULL
 DROP TRIGGER $(EHA_SCHEMA).trg_$(SPOKE_ACTIVITY_TABLE)
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: make note of all update and delete attempts 
--    ASSERT: the caller has opened the Database Master Key  
-------------------------------------------------------------------------------
CREATE TRIGGER $(EHA_SCHEMA).trg_$(SPOKE_ACTIVITY_TABLE) 
ON $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)
$(WITH_OPTIONS)
INSTEAD OF UPDATE, DELETE
AS 
BEGIN
SET NOCOUNT ON;
DECLARE @ErrorData VARBINARY(8000)
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
    INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    SELECT @Id
         , @MAC 
         , FORMATMESSAGE ( 'Instead %s: Id: %s' 
                         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
                         , CAST( d.Id AS NVARCHAR(36) ) )
         , 'Complete' 
    FROM deleted d
    LEFT JOIN inserted i
    on d.Id = i.Id;
  END TRY
  BEGIN CATCH
    OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
    DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
    INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status 
      , ErrorData )
    SELECT @Id
         , ISNULL( @MAC, 0x0 ) 
         , FORMATMESSAGE ( 'Instead %s: Id: %s' 
                         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
                         , CAST( d.Id AS NVARCHAR(36) ) )
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
ADD SIGNATURE TO $(EHA_SCHEMA).trg_$(SPOKE_ACTIVITY_TABLE) 
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
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128);
  BEGIN TRY
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , 0x0 -- @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
         , FORMATMESSAGE ( 'Instead %s: Id: %s' 
                         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
                         , CAST( d.Id AS NVARCHAR(36) ) )
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
         , FORMATMESSAGE ( 'Instead %s: Id: %s' 
                         , CASE WHEN i.Id IS NULL THEN 'DELETE' ELSE 'UPDATE' END
                         , CAST( d.Id AS NVARCHAR(36) ) )
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
                      WHERE [role_principal_id] = USER_ID('$(SPOKE_ADMIN_ROLE)')
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
                              , CAST( '$(EXPORT_PATH)' AS NVARCHAR(1024) )
                              , 1
                              , @DbName )   
            FROM sys.certificates AS c
            JOIN sys.crypt_properties AS cp
            ON c.thumbprint = cp.thumbprint
            CROSS JOIN ( SELECT TOP(1) KeyGuid 
                         FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                         ORDER BY CreateUTCDt DESC, Id DESC ) b
            CROSS JOIN sys.database_role_members r
            WHERE r.role_principal_id = DATABASE_PRINCIPAL_ID ( '$(SPOKE_ADMIN_ROLE)' ) 
            AND r.member_principal_id = DATABASE_PRINCIPAL_ID ( ORIGINAL_LOGIN() )  
            AND b.KeyGuid = KEY_GUID( '$(SESSION_SYMMETRIC_KEY)' )
            AND c.name = '$(OBJECT_CERTIFICATE)'
            AND c.pvt_key_encryption_type = 'PW'
            AND cp.major_id = @@PROCID 
            AND @@NESTLEVEL > 1        
            AND DB_ID(@DBName) IS NOT NULL
            AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'CERTIFICATE', c.thumbprint) = 1
            AND EXISTS (SELECT * FROM sys.database_role_members 
                        WHERE [role_principal_id] = USER_ID('$(SPOKE_ADMIN_ROLE)')
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
                                       WHERE BackupNameBucket = $(EHA_SCHEMA).AddSalt( '$(SPOKE_DATABASE)'
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
                            WHERE [role_principal_id] = USER_ID('$(SPOKE_ADMIN_ROLE)')
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
  ( Status NVARCHAR (36)
  , Signature VARBINARY(128) )
$(WITH_OPTIONS)
AS
BEGIN
  DECLARE @Status NVARCHAR (36)
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
              WHERE r.role_principal_id = DATABASE_PRINCIPAL_ID ( '$(SPOKE_ADMIN_ROLE)' ) 
              AND r.member_principal_id = DATABASE_PRINCIPAL_ID ( ORIGINAL_LOGIN() )  
              AND c.name = 'ObjectCertificate'
              AND c.pvt_key_encryption_type = 'PW'
              AND cp.major_id = @@PROCID 
              AND @@NESTLEVEL > 1 -- no direct exec of function 
              AND IS_OBJECTSIGNED('OBJECT', @@PROCID, 'CERTIFICATE', c.thumbprint) = 1
              AND EXISTS ( SELECT * FROM sys.database_role_members 
                            WHERE [role_principal_id] = USER_ID('$(SPOKE_ADMIN_ROLE)')
                            AND USER_NAME ([member_principal_id]) = SYSTEM_USER 
                            AND SYSTEM_USER = ORIGINAL_LOGIN() ) )        
    BEGIN
      SET @Status = 'decode';
      SET @Name = ( SELECT DECRYPTBYKEY( Name 
                                       , 1
                                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) 
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
                                  WHERE ValueBucket = $(EHA_SCHEMA).AddSalt( '$(SPOKE_DATABASE)'
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
                                     AS NVARCHAR(36) ) ) 
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
                        WHERE [role_principal_id] = USER_ID('$(SPOKE_ADMIN_ROLE)')
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
-- hierarchy is 4 levels root-srv-db-cert
-- identify objects added/dropped from the instance
-- node connector key:
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
                        WHERE [role_principal_id] = USER_ID('$(SPOKE_ADMIN_ROLE)')
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
                                  WHERE [role_principal_id] = USER_ID('$(SPOKE_ADMIN_ROLE)')
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
                                  WHERE [role_principal_id] = USER_ID('$(SPOKE_ADMIN_ROLE)')
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
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128)
      , @Name NVARCHAR(448)
      , @NameBucket INT
      , @Parameters VARBINARY(8000)
      , @Status NVARCHAR (36)
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
                          , 1, CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
        FROM (SELECT CAST( DECRYPTBYKEY( Name 
                                       , 1
                                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) AS NVARCHAR(448) ) AS Name
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
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                                           , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) 
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
        SET @NameBucket = $(EHA_SCHEMA).AddSalt( '$(SPOKE_DATABASE)'
                                               , '$(EHA_SCHEMA)'
                                               , '$(NAMEVALUES_TABLE)'
                                               , 'NameBucket' 
                                               , @Name );
        SET @ValueBucket = $(EHA_SCHEMA).AddSalt( '$(SPOKE_DATABASE)'
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
DECLARE @Id NVARCHAR(36)
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
                                                          , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) )
                           , 1
                           , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
    WHERE NameBucket =  $(EHA_SCHEMA).AddSalt( '$(SPOKE_DATABASE)'
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
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128)
      , @Name NVARCHAR(448)
      , @Parameters VARBINARY(8000)
      , @Status NVARCHAR (36)
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
                          , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
                        FROM @tvp);
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                                                              ELSE $(EHA_SCHEMA).AddSalt( '$(SPOKE_DATABASE)'
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
                              ELSE $(EHA_SCHEMA).AddSalt( '$(SPOKE_DATABASE)'
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
                                            , CAST( tab.Id AS NVARCHAR(36) ) 
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
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
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
IF OBJECT_ID ('$(EHA_SCHEMA).AddPortableSymmetricKey') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).AddPortableSymmetricKey
GO
-------------------------------------------------------------------------------
-- bwunder at yahoo dot com
-- Desc: Save the Identity and Source of a symmetric key to NameValues
-- The Phrase may also be stored in NameValues idenpendently (not done here)
-- Save the phrase as a private value and use that private value phrase as
-- authorization to decipher any existing data encrypted buy the portable key
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).AddPortableSymmetricKey 
 ( @KeyName NVARCHAR(128) 
 , @KeyIdentity VARBINARY(8000)
 , @KeySource VARBINARY(8000) )
$(WITH_OPTIONS)
AS
BEGIN 
DECLARE @MAC VARBINARY(128)
      , @Parameters VARBINARY(8000)
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
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
                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
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
ADD SIGNATURE TO $(EHA_SCHEMA).AddPortableSymmetricKey
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
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                        , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
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
                        , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
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
IF OBJECT_ID ('$(EHA_SCHEMA).AddPrivateValue') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).AddPrivateValue
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: save a value to namevalues encrypted by a private passphrase 
--      privately encrypted value is fed to AddNameValue
--      by default, phrase and clear text value are not persisted      
--      to save private data in the audit trail specify 
--          @AuditPrivateData = 1 
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).AddPrivateValue 
 ( @Name NVARCHAR(448) 
 , @Value VARBINARY(8000) 
 , @EncryptionPhrase VARBINARY(8000) 
 , @AuditPrivateData TINYINT = 0 ) -- tiny because formatmessage does not speak BIT  
$(WITH_OPTIONS)
AS
BEGIN 
DECLARE @DbName NVARCHAR(128)
      , @ErrorData VARBINARY(8000)  
      , @Id NVARCHAR(36) 
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS 
        ( SELECT *
          FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
          WHERE Id = @Id
          AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                       , Name 
                       , 1
                       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) 
         , ENCRYPTBYKEY( KEY_GUID( '$(VALUE_SYMMETRIC_KEY)' ) 
                       , Value
                       , 1
                       , Name )
    FROM (SELECT CAST( ISNULL( @Name, REPLACE( ORIGINAL_LOGIN(), '\','$') ) + '.Private' AS NVARCHAR(128) ) AS Name
               , CAST( DECRYPTBYKEY ( @Value ) AS NVARCHAR(128) ) AS Value) AS derived;                    
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
ADD SIGNATURE TO $(EHA_SCHEMA).AddPrivateValue
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
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS 
        ( SELECT *
          FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
          WHERE Id = @Id
          AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
      , @Backup VARBINARY(8000) 
      , @BackupDDL NVARCHAR(MAX)
      , @BackupName VARBINARY(8000)
      , @BackupNameBucket INT
      , @BackupPath VARBINARY(8000)
      , @BackupPhraseName NVARCHAR(448)
      , @BackupPhraseVersion SMALLINT
      , @BulkLoadDDL NVARCHAR(1280)
      , @CipherType NCHAR(2)
      , @Colophon INT
      , @ConversationHandle UNIQUEIDENTIFIER
      , @DbName NVARCHAR(128) = 'master'
      , @Edition SMALLINT = 1
      , @ErrorData VARBINARY(8000)  
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
    SELECT @BackupNameBucket =  $(EHA_SCHEMA).AddSalt( '$(SPOKE_DATABASE)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'BackupNameBucket' 
                                                     , Word )
    FROM ( SELECT CAST( DECRYPTBYKEY( @BackupName ) AS NVARCHAR(128) ) AS Word ) AS derived;
    SET @BackupPath = $(EHA_SCHEMA).BackupPath(@DbName);
    SET @ObjectInfoDDL = FORMATMESSAGE( $(MESSAGE_OFFSET)22
                                      , FORMATMESSAGE( $(MESSAGE_OFFSET)21
                                                     , '$(SPOKE_DATABASE)'
                                                     , '$(EHA_SCHEMA)'
                                                     , '$(BACKUP_ACTIVITY_TABLE)'
                                                     , 'Colophon'
                                                     , 'key_guid' ) 
                                      , @DbName
                                      , '##MS_ServiceMasterKey##' );
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
                                           , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) 
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

    -- all keys - all versions
    BEGIN DIALOG CONVERSATION @ConversationHandle
    FROM SERVICE $(EHA_SCHEMA)InitiatorService
    TO SERVICE '$(EHA_SCHEMA)TargetService'
             , 'CURRENT DATABASE' 
    ON CONTRACT [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/SendtoHub];

    SEND ON CONVERSATION @ConversationHandle
    MESSAGE TYPE [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/Backup] (@Id);

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
  ( @IdToRestore NVARCHAR(36) = NULL   -- default is most recent
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
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS  ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                     WHERE Id = @Id
                     AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                                                     , '$(SPOKE_DATABASE)'
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
    , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                                                     , '$(SPOKE_DATABASE)'
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
                                           , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) 
                             AS NVARCHAR(448) ) ) 
    FROM (SELECT $(EHA_SCHEMA).GetEHPhraseName( @DbName
                                              , @NodeName
                                              , @ActionType ) AS EncryptedName ) AS derived;
    EXEC $(EHA_SCHEMA).AddNameValue @Backuptvp, @BackupPhraseVersion OUTPUT;   
    SET @BackupName = $(EHA_SCHEMA).NewMasterKeyBackupName( @DbName );
    SELECT @BackupNameBucket =  $(EHA_SCHEMA).AddSalt( '$(SPOKE_DATABASE)'
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
                                               , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)' ) AS NVARCHAR(36) ) ) 
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
 , @IdToRestore NVARCHAR(36) = NULL  -- if null use most recent
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
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                                                     , '$(SPOKE_DATABASE)'
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
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                                                     , '$(SPOKE_DATABASE)'
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
                                           , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) 
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
                                               , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
                                 AS NVARCHAR(448) ) ) 
        FROM (SELECT $(EHA_SCHEMA).GetEHPhraseName( @DbName
                                                  , @CertificateName
                                                  , 'Encryption' ) AS EncryptedName ) AS derived;
        EXEC $(EHA_SCHEMA).AddNameValue @Keytvp, @KeyPhraseVersion OUTPUT;
      END         
    SET @BackupName = $(EHA_SCHEMA).NewCertificateBackupName (@DbName, @CertificateName );
    SELECT @BackupNameBucket =  $(EHA_SCHEMA).AddSalt( '$(SPOKE_DATABASE)'
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
    -- how would you like to support this
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
                                                                                                 , CAST ( DECRYPTBYKEY( Name
                                                                                                                      , 1
                                                                                                                      , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) AS NVARCHAR(448) ) ) AS NVARCHAR(128) )
                                                                       FROM @BackupTvp )
                                                                   , CASE WHEN @CipherType = 'PW'    
                                                                           THEN (SELECT FORMATMESSAGE ( $(MESSAGE_OFFSET)29
                                                                                                     , CAST( DECRYPTBYKEY( Value
                                                                                                                         , 1
                                                                                                                         , CAST ( DECRYPTBYKEY( Name 
                                                                                                                                              , 1
                                                                                                                                              , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) AS NVARCHAR(448) ) 
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
            , ENCRYPTBYKEY( KEY_GUID( '$(ERROR_SYMMETRIC_KEY)' )
                          , ErrorInfo 
                          , 1
                          , @Id )
        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                  , ERROR_NUMBER()
                                  , ERROR_SEVERITY()
                                  , ERROR_STATE()
                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc' )
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
 , @IdToRestore NVARCHAR(36) = NULL ) -- DEFAULT is most recent
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
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
                                                     , '$(SPOKE_DATABASE)'
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
                                                     , '$(SPOKE_DATABASE)'
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
IF OBJECT_ID ('$(EHA_SCHEMA).OffloadBackup') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).OffloadBackup
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: load the binary content of a file to a varbinary var for
--        export to hub and/or offsite
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).OffloadBackup
  ( @BackupId NVARCHAR(36) )
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @ErrorData VARBINARY(8000)
      , @GetExportDDL NVARCHAR(512)
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128)
      , @Parameters VARBINARY (8000) 
          = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                        , FORMATMESSAGE( '@BackupId = ''%s''', @BackupId )
                        , 1
                        , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
      , @ReturnCode INT
      , @StartDT DATETIME2 = SYSUTCDATETIME();
SET NOCOUNT ON;
  BEGIN TRY
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
    SET @GetExportDDL = ( SELECT FORMATMESSAGE ( N'SELECT %s'
                                               + N' , c.bulkcolumn ' + SPACE(1) 
                                               + N'FROM OPENROWSET( BULK ''%s%s'', SINGLE_BLOB ) AS c'
                                               , CAST( Id AS NVARCHAR(36) )
                                               , CAST( DECRYPTBYKEY( BackupPath ) AS NVARCHAR(1024) )
                                               , CAST( DECRYPTBYKEY( BackupName ) AS NVARCHAR(128) ) )
                          FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
                          WHERE Id = @BackupId );
    -- all keys - all versions
    INSERT $(EHA_SCHEMA).$(BACKUPS_SYNONYM) ( Id, Export )
    EXEC @ReturnCode = sp_executesql @GetExportDDL;
    IF @ReturnCode <> 0  
      RAISERROR($(MESSAGE_OFFSET)12,16,1,'@GetExportDDL', @BackupId, '', '', '' ,@ReturnCode);
    INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete'
     FROM $(EHA_SCHEMA).$(BACKUPS_SYNONYM) AS syn
     JOIN $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) AS tab
     ON syn.Id = tab.Id
     WHERE tab.Id = @BackupId;
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status 
          , ErrorData )
        SELECT @Id
              , ISNULL( @MAC, 0x0 )
              , OBJECT_NAME(@@PROCID)
              , 'Error'
              , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
                            , derived.ErrorInfo 
                            , 1
                            , @Id )
        FROM ( SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                   , ERROR_NUMBER()
                                   , ERROR_SEVERITY()
                                   , ERROR_STATE()
                                   , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
                                   , ERROR_LINE()
                                   , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived
        CROSS JOIN $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) AS tab
        WHERE tab.Id = @BackupId;
        CLOSE ALL SYMMETRIC KEYS;
      END
  END CATCH
END
GO
ADD SIGNATURE TO $(EHA_SCHEMA).OffloadBackup
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO

IF OBJECT_ID ('$(EHA_SCHEMA).PushChanges') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).PushChanges
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: Offload hierarchy backup catalog changes 
-- for Change Data Capture or change tracking
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).PushChanges
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @ErrorData VARBINARY(8000)
      , @Id NVARCHAR(36)
      , @CaptureInstanceId NVARCHAR(36)
      , @MAC VARBINARY(128)
      , @MaxLsn BINARY(10)
      , @MinLsn BINARY(10)
      , @Parameters VARBINARY (8000) 
          = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                        , ''
                        , 1
                        , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ) 
      , @UTCOffset INT = DATEDIFF( hh, SYSUTCDATETIME(), SYSDATETIME() );
SET NOCOUNT ON;
  BEGIN TRY
    -- do not close AUDIT_SYMMETRIC_KEY - used multiple times
    -- Will also need to book more Ids this one is used again at completion and in CATCH block 
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
    IF EXISTS (SELECT * FROM sys.dm_cdc_errors)
      RAISERROR( $(MESSAGE_OFFSET)35, 16, 1
               , 'ChangeDataCapture'
               , 'check sys.dm_cdc_errors');
    -- all booked activity up to, but excluding, the minute in which current session was booked
    SELECT @MaxLsn = sys.fn_cdc_map_time_to_lsn ( 'largest less than'
                                                , CAST ( DATEADD( hh
                                                                , @UTCOffset
                                                                , CreateUTCDT ) AS SMALLDATETIME ) )
    FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
    WHERE Id = @Id;
    IF @MaxLsn IS NOT NULL
      BEGIN
        -- rolling transfer by table with MinLsn on demand
        -- a remote onesy to get the datetime of the last transferred change for the table
        SET @MinLsn = ( SELECT ISNULL ( ( SELECT sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                                            , DATEADD( hh, @UTCOffset, lnk.CreateUTCDT ) ) 
                                          FROM (SELECT TOP (1) CreateUTCDT
                                                FROM $(EHA_SCHEMA).$(BOOKINGS_SYNONYM)
                                                WHERE ServerName = @@SERVERNAME
                                                ORDER BY CreateUTCDT DESC, Id DESC ) AS lnk )
                                      , sys.fn_cdc_get_min_lsn( '$(EHA_SCHEMA)_$(BOOKINGS_TABLE)' ) ) );
        SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                      , FORMATMESSAGE( 'CaptureInstance: [%s], @MinLsn = %s, @MaxLsn = %s'
                                                     , '$(EHA_SCHEMA)_$(BOOKINGS_TABLE)'  
                                                     , sys.fn_varbintohexstr(@MinLsn)
                                                     , sys.fn_varbintohexstr(@MaxLsn) ) 
                                      , 1
                                      , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )); 
        EXEC $(EHA_SCHEMA).Book @@PROCID
                              , @Parameters
                              , @CaptureInstanceId OUTPUT
                              , @MAC OUTPUT; 
        IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                        WHERE Id = @CaptureInstanceId
                        AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
                        AND ObjectName = OBJECT_NAME(@@PROCID) 
                        AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                              , CAST(CHECKSUM( Id
                                                             , @@PROCID   
                                                             , ObjectName
                                                             , @Parameters
                                                             , KeyGuid
                                                             , Status ) AS NVARCHAR(128) )
                                              , @MAC ) = 1 ) 
          RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@CaptureInstanceId);
        INSERT $(EHA_SCHEMA).$(BOOKINGS_SYNONYM)
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
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status )
        SELECT  @CaptureInstanceId
              , @MAC
              , FORMATMESSAGE( 'send %d %s changes', @@ROWCOUNT, capture_instance )
              , 'Complete'
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA)_$(BOOKINGS_TABLE)' );

        SET @MinLsn = ( SELECT ISNULL ( ( SELECT sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                                            , DATEADD( hh, @UTCOffset, lnk.CreateUTCDT ) ) 
                                          FROM (SELECT TOP (1) CreateUTCDT
                                                FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_SYNONYM)
                                                WHERE ServerName = @@SERVERNAME
                                                ORDER BY CreateUTCDT DESC, Id DESC ) AS lnk )
                                      , sys.fn_cdc_get_min_lsn( '$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE)' ) ) );
        SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                      , FORMATMESSAGE( '$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE) @MinLsn = %s, @MaxLsn = %s'
                                                      , sys.fn_varbintohexstr(@MinLsn)
                                                      , sys.fn_varbintohexstr(@MaxLsn) ) 
                                      , 1
                                      , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ); 
        EXEC $(EHA_SCHEMA).Book @@PROCID
                              , @Parameters
                              , @CaptureInstanceId OUTPUT
                              , @MAC OUTPUT; 
        IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                        WHERE Id = @CaptureInstanceId
                        AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
                        AND ObjectName = OBJECT_NAME(@@PROCID) 
                        AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                              , CAST(CHECKSUM( Id
                                                              , @@PROCID   
                                                              , ObjectName
                                                              , @Parameters
                                                              , KeyGuid
                                                              , Status ) AS NVARCHAR(128) )
                                              , @MAC ) = 1 ) 
          RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@CaptureInstanceId);
        INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_SYNONYM)
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
        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE)( @MinLsn, @MaxLsn, 'all'); 
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status )
        SELECT  @CaptureInstanceId
              , @MAC
              , FORMATMESSAGE( 'send %d $(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE) changes', @@ROWCOUNT )
              , 'Complete'
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)' );
        SET @MinLsn = ( SELECT ISNULL ( ( SELECT sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                                            , DATEADD( hh, @UTCOffset, lnk.CreateUTCDT ) ) 
                                          FROM (SELECT TOP (1) CreateUTCDT
                                                FROM $(EHA_SCHEMA).$(NAMEVALUES_SYNONYM)
                                                WHERE ServerName = @@SERVERNAME
                                                ORDER BY CreateUTCDT DESC, Id DESC ) AS lnk )
                                      , sys.fn_cdc_get_min_lsn( '$(EHA_SCHEMA)_$(NAMEVALUES_TABLE)' ) ) );

SELECT FORMATMESSAGE( '$(EHA_SCHEMA)_$(NAMEVALUES_TABLE) @MinLsn = %s, @MaxLsn = %s'
                    , sys.fn_varbintohexstr(@MinLsn)
                    , sys.fn_varbintohexstr(@MaxLsn) );
SELECT [sys].[fn_cdc_check_parameters]('$(EHA_SCHEMA)_$(NAMEVALUES_TABLE)', @MinLsn, @MaxLsn, 'all',0);

        SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                      , FORMATMESSAGE( '$(EHA_SCHEMA)_$(NAMEVALUES_TABLE) @MinLsn = %s, @MaxLsn = %s'
                                                      , sys.fn_varbintohexstr(@MinLsn)
                                                      , sys.fn_varbintohexstr(@MaxLsn) ) 
                                      , 1
                                      , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ); 
        EXEC $(EHA_SCHEMA).Book @@PROCID
                              , @Parameters
                              , @CaptureInstanceId OUTPUT
                              , @MAC OUTPUT; 
        IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                        WHERE Id = @CaptureInstanceId
                        AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
                        AND ObjectName = OBJECT_NAME(@@PROCID) 
                        AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                              , CAST(CHECKSUM( Id
                                                              , @@PROCID   
                                                              , ObjectName
                                                              , @Parameters
                                                              , KeyGuid
                                                              , Status ) AS NVARCHAR(128) )
                                              , @MAC ) = 1 ) 
          RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@CaptureInstanceId);
        INSERT $(EHA_SCHEMA).$(NAMEVALUES_SYNONYM)
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
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status )
        SELECT  @CaptureInstanceId
              , @MAC
              , FORMATMESSAGE( 'send %d $(EHA_SCHEMA)_$(NAMEVALUES_TABLE) changes', @@ROWCOUNT )
              , 'Complete'
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(NAMEVALUES_TABLE)' );
        SET @MinLsn = ( SELECT ISNULL ( ( SELECT sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                                            , DATEADD( hh, @UTCOffset, lnk.CreateUTCDT ) ) 
                                          FROM (SELECT TOP (1) CreateUTCDT
                                                FROM $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_SYNONYM)
                                                WHERE ServerName = @@SERVERNAME
                                                ORDER BY CreateUTCDT DESC, Id DESC ) AS lnk )
                                      , sys.fn_cdc_get_min_lsn( '$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)' ) ) );

SELECT FORMATMESSAGE( '$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE) @MinLsn = %s, @MaxLsn = %s'
                    , sys.fn_varbintohexstr(@MinLsn)
                    , sys.fn_varbintohexstr(@MaxLsn) );
SELECT [sys].[fn_cdc_check_parameters]('$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)', @MinLsn, @MaxLsn, 'all',0);
        SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                      , FORMATMESSAGE( '$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE) @MinLsn = %s, @MaxLsn = %s'
                                                      , sys.fn_varbintohexstr(@MinLsn)
                                                      , sys.fn_varbintohexstr(@MaxLsn) ) 
                                      , 1
                                      , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ); 
        EXEC $(EHA_SCHEMA).Book @@PROCID
                            , @Parameters
                            , @CaptureInstanceId OUTPUT
                            , @MAC OUTPUT; 
        IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                        WHERE Id = @CaptureInstanceId
                        AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
                        AND ObjectName = OBJECT_NAME(@@PROCID) 
                        AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                              , CAST(CHECKSUM( Id
                                                              , @@PROCID   
                                                              , ObjectName
                                                              , @Parameters
                                                              , KeyGuid
                                                              , Status ) AS NVARCHAR(128) )
                                              , @MAC ) = 1 ) 
          RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@CaptureInstanceId);
        INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_SYNONYM)
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
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status )
        SELECT  @CaptureInstanceId
              , @MAC
              , FORMATMESSAGE( 'send %d $(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE) changes', @@ROWCOUNT )
              , 'Complete' 
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)' );

        SET @MinLsn = ( SELECT ISNULL ( ( SELECT sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                                            , DATEADD( hh, @UTCOffset, lnk.CreateUTCDT ) ) 
                                          FROM (SELECT TOP (1) CreateUTCDT
                                                FROM $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_SYNONYM)
                                                WHERE ServerName = @@SERVERNAME
                                                ORDER BY CreateUTCDT DESC, Id DESC ) AS lnk )
                                      , sys.fn_cdc_get_min_lsn( '$(EHA_SCHEMA)_$(NOTIFICATION_ACTIVITY_TABLE)' ) ) );

SELECT FORMATMESSAGE( '$(EHA_SCHEMA)_$(NOTIFICATION_ACTIVITY_TABLE) @MinLsn = %s, @MaxLsn = %s'
                    , sys.fn_varbintohexstr(@MinLsn)
                    , sys.fn_varbintohexstr(@MaxLsn) );
SELECT [sys].[fn_cdc_check_parameters]('$(EHA_SCHEMA)_$(NOTIFICATION_ACTIVITY_TABLE)', @MinLsn, @MaxLsn, 'all',0);

        SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                      , FORMATMESSAGE( '(EHA_SCHEMA)_$(NOTIFICATION_ACTIVITY_TABLE) @MinLsn = %s, @MaxLsn = %s'
                                                      , sys.fn_varbintohexstr(@MinLsn)
                                                      , sys.fn_varbintohexstr(@MaxLsn) ) 
                                      , 1
                                      , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ); 
        EXEC $(EHA_SCHEMA).Book @@PROCID
                              , @Parameters
                              , @CaptureInstanceId OUTPUT
                              , @MAC OUTPUT; 
        IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                        WHERE Id = @CaptureInstanceId
                        AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
        INSERT $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_SYNONYM)
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
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status )
        SELECT  @CaptureInstanceId
              , @MAC
              , FORMATMESSAGE( 'send %d $(EHA_SCHEMA)_$(NOTIFICATION_ACTIVITY_TABLE) changes', @@ROWCOUNT )
              , 'Complete' 
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)' );

        SET @MinLsn = ( SELECT ISNULL ( ( SELECT sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                                            , DATEADD( hh, @UTCOffset, lnk.CreateUTCDT ) ) 
                                          FROM (SELECT TOP (1) CreateUTCDT
                                                FROM $(EHA_SCHEMA).$(SPOKE_ACTIVITY_SYNONYM)
                                                WHERE ServerName = @@SERVERNAME
                                                ORDER BY CreateUTCDT DESC, Id DESC ) AS lnk )
                                      , sys.fn_cdc_get_min_lsn( '$(EHA_SCHEMA)_$(SPOKE_ACTIVITY_TABLE)' ) ) );
        SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                      , FORMATMESSAGE( '(EHA_SCHEMA)_$(SPOKE_ACTIVITY_TABLE) @MinLsn = %s, @MaxLsn = %s'
                                                      , sys.fn_varbintohexstr(@MinLsn)
                                                      , sys.fn_varbintohexstr(@MaxLsn) ) 
                                      , 1
                                      , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ); 
        EXEC $(EHA_SCHEMA).Book @@PROCID
                              , @Parameters
                              , @CaptureInstanceId OUTPUT
                              , @MAC OUTPUT; 
        IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                        WHERE Id = @CaptureInstanceId
                        AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
                        AND ObjectName = OBJECT_NAME(@@PROCID) 
                        AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                              , CAST(CHECKSUM( Id
                                                              , @@PROCID   
                                                              , ObjectName
                                                              , @Parameters
                                                              , KeyGuid
                                                              , Status ) AS NVARCHAR(128) )
                                              , @MAC ) = 1 ) 
          RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@CaptureInstanceId);
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_SYNONYM)
          ( Id
          , ServerName
          , MAC
          , Action
          , Status
          , ErrorData
          , CreateUTCDT
          , CreateUser)
        SELECT Id
              , ServerName
              , MAC
              , Action
              , Status
              , ErrorData
              , CreateUTCDT
              , CreateUser 
        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(SPOKE_ACTIVITY_TABLE) 
                                                      ( @MinLsn, @MaxLsn, 'all' ); 
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status )
        SELECT  @CaptureInstanceId
              , @MAC
              , FORMATMESSAGE( 'send %d $(EHA_SCHEMA)_$(SPOKE_ACTIVITY_TABLE) changes', @@ROWCOUNT )
              , 'Complete'
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)' );

        SET @MinLsn = ( SELECT ISNULL ( ( SELECT sys.fn_cdc_map_time_to_lsn ( 'smallest greater than or equal'
                                                                            , DATEADD( hh, @UTCOffset, lnk.CreateUTCDT ) ) 
                                          FROM (SELECT TOP (1) CreateUTCDT
                                                FROM $(EHA_SCHEMA).$(REPORT_ACTIVITY_SYNONYM)
                                                WHERE ServerName = @@SERVERNAME
                                                ORDER BY CreateUTCDT DESC, Id DESC ) AS lnk )
                                      , sys.fn_cdc_get_min_lsn( '$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE)' ) ) );
        SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                      , FORMATMESSAGE( '$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE) @MinLsn = %s, @MaxLsn = %s'
                                                      , sys.fn_varbintohexstr(@MinLsn)
                                                      , sys.fn_varbintohexstr(@MaxLsn) ) 
                                      , 1
                                      , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) ); 
        EXEC $(EHA_SCHEMA).Book @@PROCID
                              , @Parameters
                              , @CaptureInstanceId OUTPUT
                              , @MAC OUTPUT; 
        IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                        WHERE Id = @CaptureInstanceId
                        AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
                        AND ObjectName = OBJECT_NAME(@@PROCID) 
                        AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
                                              , CAST(CHECKSUM( Id
                                                              , @@PROCID   
                                                              , ObjectName
                                                              , @Parameters
                                                              , KeyGuid
                                                              , Status ) AS NVARCHAR(128) )
                                              , @MAC ) = 1 ) 
          RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@CaptureInstanceId);
        INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_SYNONYM)
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
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status )
        SELECT  @CaptureInstanceId
              , @MAC
              , FORMATMESSAGE( 'send %d $(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE) changes', @@ROWCOUNT )
              , IIF(@MaxLsn IS NULL, 'No Changes', 'Complete')
        FROM cdc.change_tables
        WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)' );

      END -- @MaxLsn not null

    INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
      ( Id
      , MAC
      , Action
      , Status )
    SELECT  @Id
          , @MAC
          , OBJECT_NAME(@@PROCID)
          , 'Complete'
    FROM cdc.change_tables
    WHERE source_object_id = OBJECT_ID( '$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)' );

    CLOSE ALL SYMMETRIC KEYS;

  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status 
          , ErrorData )
        SELECT @Id
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
ADD SIGNATURE TO $(EHA_SCHEMA).PushChanges
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO

--IF OBJECT_ID ('$(EHA_SCHEMA).PushTrackedChanges') IS NOT NULL
--   DROP PROCEDURE $(EHA_SCHEMA).PushTrackedChanges
--GO
---------------------------------------------------------------------------------
----  bwunder at yahoo dot com
----  Desc: copy changes offsite using track changes
---------------------------------------------------------------------------------
--CREATE PROCEDURE $(EHA_SCHEMA).PushTrackedChanges
--$(WITH_OPTIONS)
--AS
--BEGIN
--DECLARE @CaptureInstance NVARCHAR(128)
--      , @ErrorData VARBINARY(8000)
--      , @Id NVARCHAR(36)
--      , @LastSyncVersion BIGINT 
--      , @MAC VARBINARY(128)
--      , @Parameters VARBINARY (8000) = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
--                                                   , ''
--                                                   , 1
--                                                   , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
--      , @RowCount INT
--      , @StartDT DATETIME2 = SYSUTCDATETIME()
--      , @SyncVersion BIGINT;
--SET NOCOUNT ON;
--  BEGIN TRY
--    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
--    EXEC $(EHA_SCHEMA).Book @@PROCID
--                          , @Parameters
--                          , @Id OUTPUT
--                          , @MAC OUTPUT; 
--    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
--                    WHERE Id = @Id
--                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
--                    AND ObjectName = OBJECT_NAME(@@PROCID) 
--                    AND VERIFYSIGNEDBYCERT( CERT_ID('$(AUTHENTICITY_CERTIFICATE)')
--                                          , CAST(CHECKSUM( Id
--                                                         , @@PROCID   
--                                                         , ObjectName
--                                                         , @Parameters
--                                                         , KeyGuid
--                                                         , Status ) AS NVARCHAR(128) )
--                                          , @MAC ) = 1 ) 
--      RAISERROR($(MESSAGE_OFFSET)34,16,1,@@PROCID,@Id);
--    -- bookings first to protect DRI at target
--    CLOSE ALL SYMMETRIC KEYS;
--    SET @MinValidVersion = 
--    SET @LastSyncVersion = (SELECT LastSyncVersion FROM);
--    IF @LastSyncVersion
--    INSERT $(EHA_SCHEMA).$(BOOKINGS_SYNONYM)
--      ( Id
--      , ServerName
--      , ProcId
--      , ObjectName
--      , Parameters
--      , Status
--      , ErrorData
--      , CreateUTCDT
--      , CreateUser)
--    SELECT Id
--          , ServerName
--          , ProcId
--          , ObjectName
--          , Parameters
--          , Status
--          , ErrorData
--          , CreateUTCDT
--          , CreateUser 
--    FROM $(EHA_SCHEMA)_$(BOOKINGS_TABLE) AS b
--    CROSS APPLY CHANGETABLE (CHANGES $(EHA_SCHEMA).$(BOOKINGS_SYNONYM), @last_sync_version) AS c;
--    SET @RowCount = @@ROWCOUNT 
--    IF @RowCount > 0
--      BEGIN
--        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
--          ( Id
--          , MAC
--          , Action
--          , Status )
--        SELECT @Id
--              , @MAC
--              , FORMATMESSAGE( 'CHANGETABLE (CHANGES $(EHA_SCHEMA).$(BOOKINGS_SYNONYM), version=%d)', @LastSyncVersion)
--              , 'Complete'
--          FROM cdc.change_tables
--          WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA).$(BOOKINGS_TABLE)');

--    SET @MinValidVersion = 
--    SET @LastSyncVersion = (SELECT LastSyncVersion FROM);
--    IF @LastSyncVersion
--    INSERT $(EHA_SCHEMA).$(BACKUP_ACTIVITY_SYNONYM)
--      ( Id
--      , ServerName
--      , DbName
--      , Node
--      , Level
--      , NodeName
--      , BackupName
--      , BackupNameBucket
--      , UseHash
--      , BackupPath
--      , BackupPhraseVersion
--      , KeyPhraseVersion
--      , Colophon
--      , Edition
--      , MAC
--      , Action
--      , Status
--      , CipherType
--      , ErrorData
--      , CreateUTCDT
--      , CreateUser)
--    SELECT Id
--          , ServerName
--          , DbName
--          , Node.ToString()
--          , Level
--          , NodeName
--          , BackupName
--          , BackupNameBucket
--          , UseHash
--          , BackupPath
--          , BackupPhraseVersion
--          , KeyPhraseVersion
--          , Colophon
--          , Edition
--          , MAC
--          , Action
--          , Status
--          , CipherType
--          , ErrorData
--          , CreateUTCDT
--          , CreateUser 
--    FROM $(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE) AS b
--    CROSS APPLY CHANGETABLE (CHANGES $(EHA_SCHEMA).$(BACKUP_ACTIVITY_SYNONYM), @last_sync_version) AS c;
--    IF @@ROWCOUNT > 0        
--      INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
--        ( Id
--        , MAC
--        , Action
--        , Status )
--      SELECT @Id
--            , @MAC
--            , FORMATMESSAGE( 'cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(BACKUP_ACTIVITY_TABLE) ( %#x, %#x, ''all'')'
--                          , @MinLsn, @MaxLsn, 'all')
--            , 'Complete'
--        FROM cdc.change_tables
--        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA).$(BOOKINGS_TABLE)');

--    INSERT $(EHA_SCHEMA).$(NAMEVALUES_SYNONYM)
--      ( Id
--      , ServerName
--      , NameBucket
--      , ValueBucket
--      , Version
--      , Name
--      , Value
--      , CreateUTCDT
--      , CreateUser)
--    SELECT Id
--          , ServerName
--          , NameBucket
--          , ValueBucket
--          , Version
--          , Name
--          , Value
--          , CreateUTCDT
--          , CreateUser 
--    FROM $(EHA_SCHEMA)_$(NAMEVALUES_TABLE) AS b
--    CROSS APPLY CHANGETABLE (CHANGES $(EHA_SCHEMA).$(NAMEVALUES_SYNONYM), @last_sync_version) AS c;
--    IF @@ROWCOUNT > 0        
--      INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
--        ( Id
--        , MAC
--        , Action
--        , Status )
--      SELECT @Id
--            , @MAC
--            , FORMATMESSAGE( 'cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(NAMEVALUES_TABLE) ( %#x, %#x, ''all'')'
--                          , @MinLsn, @MaxLsn, 'all')
--            , 'Complete'
--        FROM cdc.change_tables
--        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA).$(BOOKINGS_TABLE)');

--        SET @RowCount = @@ROWCOUNT;
--        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
--          ( Id
--          , CaptureInstance
--          , MinLsn
--          , MaxLsn
--          , [RowCount]
--          , MAC
--          , Action
--          , Status )
--        SELECT  @Id
--               , @CaptureInstance
--               , @BeginLsn
--               , @MaxLsn
--               , @RowCount  
--               , @MAC
--               , OBJECT_NAME(@@PROCID)
--               , 'Complete'
--        FROM cdc.change_tables
--        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA)_$(NAMEVALUES_TABLE)');
--      END
--    SET @Minlsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)');
--    SET @LastLsn = 
--        ISNULL( ( SELECT TOP (1) MaxLsn 
--                  FROM $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)
--                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)'
--                  ORDER BY CreateUTCDT DESC ), 0x000000000000000000 );
--    SET @BeginLsn = sys.fn_cdc_increment_lsn(@LastLsn)
--    IF NOT EXISTS (SELECT * 
--                   FROM $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_SYNONYM)
--                   WHERE Id = ( SELECT TOP (1) Id
--                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)
--                                                                    ( @BeginLsn, @BeginLsn, 'all') 
--                                ORDER BY __$start_lsn DESC ) 
--                   AND @LastLsn > = @MinLsn ) -- means something is missing  
--      BEGIN
--        INSERT $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_SYNONYM)
--          ( Id
--          , ServerName
--          , MAC
--          , Action
--          , Status
--          , ErrorData
--          , CreateUTCDT
--          , CreateUser )
--        SELECT Id
--             , ServerName
--             , MAC
--             , Action
--             , Status
--             , ErrorData
--             , CreateUTCDT
--             , CreateUser 
--        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)
--                                                        ( @MinLsn, @MaxLsn, 'all'); 
--        SET @RowCount = @@ROWCOUNT;
--        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
--          ( Id
--          , CaptureInstance
--          , MinLsn
--          , MaxLsn
--          , [RowCount]
--          , MAC
--          , Action
--          , Status )
--        SELECT  @Id
--               , @CaptureInstance
--               , @BeginLsn
--               , @MaxLsn
--               , @RowCount  
--               , @MAC
--               , OBJECT_NAME(@@PROCID)
--               , 'Complete'
--        FROM cdc.change_tables
--        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA)_$(NAMEVALUE_ACTIVITY_TABLE)');
--      END
--    SET @Minlsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)');
--    SET @LastLsn = 
--        ISNULL( ( SELECT TOP (1) MaxLsn 
--                  FROM $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)
--                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(SPOKE_ACTIVITY_TABLE)'
--                  ORDER BY CreateUTCDT DESC ), 0x000000000000000000 );
--    SET @BeginLsn = sys.fn_cdc_increment_lsn(@LastLsn)
--    IF NOT EXISTS (SELECT * 
--                   FROM $(EHA_SCHEMA).$(SPOKE_ACTIVITY_SYNONYM)
--                   WHERE Id = ( SELECT TOP (1) Id
--                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(SPOKE_ACTIVITY_TABLE)
--                                                                    ( @BeginLsn, @BeginLsn, 'all') 
--                                ORDER BY __$start_lsn DESC ) 
--                   AND @LastLsn > = @MinLsn ) -- means something is missing  
--      BEGIN
--        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_SYNONYM)
--          ( Id
--          , ServerName
--          , CaptureInstance
--          , MinLsn
--          , MaxLsn
--          , MAC
--          , [RowCount]
--          , Action
--          , Status
--          , ErrorData
--          , CreateUTCDT
--          , CreateUser)
--        SELECT Id
--             , ServerName
--             , CaptureInstance
--             , MinLsn
--             , MaxLsn
--             , MAC
--             , [RowCount]
--             , Action
--             , Status
--             , ErrorData
--             , CreateUTCDT
--             , CreateUser 
--        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(SPOKE_ACTIVITY_TABLE) 
--                                                     ( @BeginLsn, @MaxLsn, 'all'); 
--        SET @RowCount = @@ROWCOUNT;
--        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
--          ( Id
--          , CaptureInstance
--          , MinLsn
--          , MaxLsn
--          , [RowCount]
--          , MAC
--          , Action
--          , Status )
--        SELECT  @Id
--               , @CaptureInstance
--               , @BeginLsn
--               , @MaxLsn
--               , @RowCount  
--               , @MAC
--               , OBJECT_NAME(@@PROCID)
--               , 'Complete'
--        FROM cdc.change_tables
--        WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA)_$(SPOKE_ACTIVITY_TABLE)');
--      END
--    SET @Minlsn = sys.fn_cdc_get_min_lsn('$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)');
--    SET @LastLsn = 
--        ISNULL( ( SELECT TOP (1) MaxLsn 
--                  FROM $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)
--                  WHERE CaptureInstance = '$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE)'
--                  ORDER BY CreateUTCDT DESC ), 0x000000000000000000 );
--    SET @BeginLsn = sys.fn_cdc_increment_lsn(@LastLsn)
--    IF NOT EXISTS (SELECT * 
--                   FROM $(EHA_SCHEMA).$(REPORT_ACTIVITY_SYNONYM)
--                   WHERE Id = ( SELECT TOP (1) Id
--                                FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE)
--                                                                    ( @BeginLsn, @BeginLsn, 'all') 
--                                ORDER BY __$start_lsn DESC ) 
--                   AND @LastLsn > = @MinLsn ) -- means something is missing  
--      BEGIN
--        INSERT $(EHA_SCHEMA).$(REPORT_ACTIVITY_SYNONYM)
--          ( Id
--          , ServerName
--          , ReportProcedure
--          , Duration_ms
--          , RowsReturned
--          , MAC
--          , Status
--          , ErrorData
--          , CreateUTCDT
--          , CreateUser )
--        SELECT Id
--             , ServerName
--             , ReportProcedure
--             , Duration_ms
--             , RowsReturned
--             , MAC
--             , Status
--             , ErrorData
--             , CreateUTCDT
--             , CreateUser 
--        FROM cdc.fn_cdc_get_all_changes_$(EHA_SCHEMA)_$(REPORT_ACTIVITY_TABLE) 
--                                                   ( @BeginLsn, @MaxLsn, 'all'); 
--        SET @RowCount = @@ROWCOUNT;
--        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
--          ( Id
--          , CaptureInstance
--          , MinLsn
--          , MaxLsn
--          , [RowCount]
--          , MAC
--          , Action
--          , Status )
--        SELECT @Id
--             , capture_instance
--             , @MinLsn
--             , @MaxLsn
--             , @RowCount  
--             , @MAC
--             , OBJECT_NAME(@@PROCID)
--             , 'Complete'
--         FROM cdc.change_tables
--         WHERE source_object_id = OBJECT_ID('$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)');
--      END
--  END TRY
--  BEGIN CATCH
--    IF @Id IS NULL
--      THROW;
--    ELSE
--      BEGIN
--        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
--        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
--        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
--          ( Id
--          , CaptureInstance
--          , MinLsn
--          , MaxLsn
--          , [RowCount]
--          , MAC
--          , Action
--          , Status 
--          , ErrorData )
--        SELECT @Id
--             , ISNULL( @CaptureInstance, CAST(NEWID() AS NVARCHAR(128) ) )
--             , ISNULL( @BeginLsn, 0x )
--             , ISNULL( @MaxLsn, 0x )  
--             , ISNULL( @MAC, 0x )
--             , ISNULL( @RowCount, 0 )
--             , OBJECT_NAME(@@PROCID)
--             , 'Error'
--             , ENCRYPTBYKEY( KEY_GUID('$(ERROR_SYMMETRIC_KEY)')
--                           , ErrorInfo 
--                           , 1
--                           , @Id )
--        FROM (SELECT FORMATMESSAGE( $(MESSAGE_OFFSET)02
--                                  , ERROR_NUMBER()
--                                  , ERROR_SEVERITY()
--                                  , ERROR_STATE()
--                                  , ISNULL(ERROR_PROCEDURE(), 'ad hoc')
--                                  , ERROR_LINE()
--                                  , ERROR_MESSAGE() ) AS ErrorInfo ) AS derived;
--        CLOSE ALL SYMMETRIC KEYS;
--      END
--  END CATCH
--END
--GO
--ADD SIGNATURE TO $(EHA_SCHEMA).PushTrackedChanges
--BY CERTIFICATE $(OBJECT_CERTIFICATE)
--WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO

IF OBJECT_ID ('$(EHA_SCHEMA).RecallBackup') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).RecallBackup
GO
-------------------------------------------------------------------------------
--  bwunder at yahoo dot com
--  Desc: copy the key or key pair backups from hub to the restore filetable
--        eha.Restore FileTable space
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).RecallBackup
  ( @RecallId NVARCHAR(36) )-- if null download but do not restore
$(WITH_OPTIONS)
AS
BEGIN
DECLARE @ErrorData VARBINARY(8000)
      , @Id NVARCHAR(36)
      , @BackupName NVARCHAR(128) 
      , @BackupPath VARBINARY(8000)  
      , @MAC VARBINARY(128)
      , @Parameters VARBINARY (8000) = ENCRYPTBYKEY( Key_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                                   , FORMATMESSAGE( '@RecallId = %s', @RecallId)
                                                   , 1
                                                   , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
      , @RowCount INT
      , @SourceServer NVARCHAR(128)
      , @StartDT DATETIME2 = SYSUTCDATETIME();
SET NOCOUNT ON;
  BEGIN TRY
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
    -- cannot object sign a synonym so definition is captured at install 
    -- used here for hard value compare validation 
    -- this can be spoofed by somoeone with knowledge of the code
    IF NOT EXISTS ( SELECT * 
                    FROM sys.synonyms syn
                    CROSS JOIN sys.servers ser  
                    WHERE syn.name =  '$(BACKUPS_SYNONYM)'
                    AND syn.schema_id = SCHEMA_ID( '$(EHA_SCHEMA)' )
                    AND syn.base_object_name = 
'[$(HUB_LINKED_SERVER_NAME)].[$(HUB_DATABASE)].[$(EHA_SCHEMA)].[$(BACKUPS_TABLE)]'
                    AND ser.Name = '$(HUB_LINKED_SERVER_NAME)'
                    AND ser.data_source = '$(HUB_DATASOURCE)' ) 
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'$(BACKUPS_SYNONYM)','not found');
    INSERT $(EHA_SCHEMA).$(RESTORES_FILETABLE) 
      ( stream_id, file_stream )
    SELECT Id, Export 
    FROM $(EHA_SCHEMA).$(BACKUPS_SYNONYM)
    WHERE Id = @RecallId
    AND VerifySignedByCert( CERT_ID('$(OBJECT_CERTIFICATE)')
                          , Export
                          , Signature ) = 1
    IF @@ROWCOUNT <> 1 
      RAISERROR($(MESSAGE_OFFSET)35,16,1,'remote store','not verified');
    SELECT @SourceServer = ServerName
         , @BackupName = CAST( DECRYPTBYKEY( BackupName
                                         , 1
                                         , CAST( Id AS NVARCHAR(36) ) ) AS NVARCHAR(128) )
         , @BackupPath = BackupPath
    FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_SYNONYM)
    WHERE Id = @RecallId;
    INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
      ( Id
      , ServerName
      , MAC
      , Action
      , Status )
    VALUES 
      ( @Id
      , @SourceServer
      , @MAC
      , OBJECT_NAME(@@PROCID)
      , 'Complete' )
    CLOSE ALL SYMMETRIC KEYS;
  END TRY
  BEGIN CATCH
    IF @Id IS NULL
      THROW;
    ELSE
      BEGIN
        OPEN SYMMETRIC KEY $(ERROR_SYMMETRIC_KEY)
        DECRYPTION BY PASSWORD = '$(ERROR_KEY_ENCRYPTION_PHRASE)';
        INSERT $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) 
          ( Id
          , MAC
          , Action
          , Status 
          , ErrorData )
        SELECT @Id
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
ADD SIGNATURE TO $(EHA_SCHEMA).RecallBackup
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
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
         , ABS( CHECKSUM( HASHBYTES( ''$(HASHBYTES_ALGORITHM)'', CAST( key_guid AS NVARCHAR(36) ) ) ) )
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
         , HASHBYTES( ''$(HASHBYTES_ALGORITHM)'', CAST( key_guid AS NVARCHAR(36) ) )
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
         , ABS( CHECKSUM( HASHBYTES( ''$(HASHBYTES_ALGORITHM)'', CAST( thumbprint AS NVARCHAR(36) ) ) ) )
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
DECLARE @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NVARCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorInfo
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
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NVARCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorInfo
    FROM eha.$(BACKUP_ACTIVITY_TABLE) 
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
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NVARCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorInfo
    FROM eha.$(NAMEVALUE_ACTIVITY_TABLE)
    WHERE Status = 'Error'
    AND ServerName = @ServerName
    UNION ALL
    SELECT  ServerName 
          , '$(SPOKE_ACTIVITY_TABLE)'
          , DB_NAME()
          , Action
	        , Status
          , CreateUTCDT 
          , CreateUser 
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NVARCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorData 
    FROM eha.$(SPOKE_ACTIVITY_TABLE)     
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
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NVARCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorData 
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
          , CAST( DECRYPTBYKEY( ErrorData, 1, CAST( Id AS NVARCHAR(36) ) ) AS NVARCHAR(4000) ) AS ErrorData 
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
      , @Id NVARCHAR(36)
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
                                  , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
    CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
    EXEC $(EHA_SCHEMA).Book  @@PROCID
                          , @Parameters
                          , @Id OUTPUT
                          , @MAC OUTPUT; 
    IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                    WHERE Id = @Id
                    AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
    FROM (SELECT CAST( b.Id AS NVARCHAR(36) ) AS Id
               , COALESCE( ba.NodeName
                         , ra.ReportProcedure
                         , DECRYPTBYKEY(nv.Name ,1,CAST(nv.Id AS NVARCHAR(36) ) )
                         , '' ) AS Name
               , CASE WHEN nva.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)'
                      WHEN ba.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)'
                      WHEN na.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)' 
                      WHEN oa.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)' 
                      WHEN ra.Id IS NOT NULL THEN '$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)' 
                      END AS [Category] 
               , b.ObjectName AS Action
               , b.Status AS BookingStatus
               , COALESCE(ba.Status, nva.Status, ra.Status, oa.Status) AS ActionStatus
               , COALESCE( b.ErrorData, ba.ErrorData, nva.ErrorData, oa.ErrorData, ra.ErrorData) AS ErrorData
               , ISNULL( ba.CipherType, '' ) AS CipherType
               , b.CreateUTCDT AS BookingUTCDT
               , COALESCE(ba.CreateUTCDT, nva.CreateUTCDT, oa.CreateUTCDT, ra.CreateUTCDT) AS LogUTCDT 
               , COALESCE(ba.CreateUser, nva.CreateUser, oa.CreateUser, ra.CreateUser) AS CreateUser 
          FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) b
          LEFT JOIN $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) ba
          ON b.Id = ba.Id
          LEFT JOIN $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) nva
          ON b.Id = nva.Id
          LEFT JOIN $(EHA_SCHEMA).$(NAMEVALUEs_TABLE) nv
          ON nva.Id = nv.Id
          LEFT JOIN $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE) na
          ON b.Id = na.Id 
          LEFT JOIN $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE) oa
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
-- $(SPOKE_ADMIN_ROLE) role from changing the designated EHAdmin db 
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
           WHERE name = 'trg_ddl_$(SPOKE_DATABASE)' )
  DROP TRIGGER trg_ddl_$(SPOKE_DATABASE) ON DATABASE;

GO
CREATE TRIGGER trg_ddl_$(SPOKE_DATABASE)
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
                    WHERE r.role_principal_id = USER_ID('$(SPOKE_ADMIN_ROLE)') )
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
           WHERE name = 'trg_trg_$(SPOKE_DATABASE)' )
  DROP TRIGGER trg_trg_$(SPOKE_DATABASE) ON DATABASE;
GO
CREATE TRIGGER trg_trg_$(SPOKE_DATABASE)
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
                    WHERE r.role_principal_id = USER_ID('$(SPOKE_ADMIN_ROLE)') )
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
-------------------------------------------------------------------------------
-- Service Broker - 
------------------------------------------------------------------------------- 
-- DDL events, data changes and key backup files are sent to hub
-- events are examined for work tasks and written to NOTIFICATION_ACTIVITY at Spoke
-- change data capture ending lsn by Capture Instance is sent through queue
IF OBJECT_ID ('$(EHA_SCHEMA).InitiatorActivation') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).InitiatorActivation
GO
-------------------------------------------------------------------------------
--    bwunder at yahoo dot com
--    Desc: process replys from target queue
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).InitiatorActivation 
WITH EXECUTE AS '$(SPOKE_BROKER)' $(WITH_OPTIONS_FOR_ACTIVATION)
AS
BEGIN
DECLARE @ConversationHandle UNIQUEIDENTIFIER
      , @ConversationGroupId UNIQUEIDENTIFIER
      , @ConversationGroup NVARCHAR(50)
      , @ErrorData VARBINARY(8000)
      , @Id NVARCHAR(36)
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
    WAITFOR ( GET CONVERSATION GROUP @ConversationGroupId 
              FROM $(EHA_SCHEMA).TargetQueue )
        , TIMEOUT 6000; -- a minute 
    IF @ConversationGroupId IS NOT NULL
      BEGIN
        RECEIVE TOP(1)
            @ConversationHandle = [conversation_handle]
          , @ServiceName = [service_name]
          , @MessageTypeName = [message_type_name]
          , @MessageBody = [message_body]
        FROM $(EHA_SCHEMA).InitiatorQueue
        WHERE conversation_group_id = @ConversationGroupId;
        IF @@ROWCOUNT = 1 
          BEGIN  
            -- write notification row for each queue item processed
            EXEC $(EHA_SCHEMA).OpenSession;
 	          SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                          , N''
                                          , 1
                                          , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
            CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
            EXEC $(EHA_SCHEMA).Book @@PROCID
                                  , @Parameters
                                  , @Id OUTPUT
                                  , @MAC OUTPUT; 
            IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                            WHERE Id = @Id
                            AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
            IF @MessageTypeName = 'http://schemas.microsoft.com/SQL/ServiceBroker/EndDialog'
              -- Target is ending dialog normally.
              END CONVERSATION @ConversationHandle;
            ELSE IF @MessageTypeName = 'http://schemas.microsoft.com/SQL/ServiceBroker/Error'
              WITH XMLNAMESPACES ('http://schemas.microsoft.com/SQL/ServiceBroker/Error' AS ssb) 
              SELECT @ErrorData = ENCRYPTBYKEY( KEY_GUID( '$(ERROR_SYMMETRIC_KEY)' )
                                              , FORMATMESSAGE( $(MESSAGE_OFFSET)02
                                                             , err.value( '(//ssb:Error/ssb:Code)[1]'
                                                                         , 'INT' ) 
                                                             , NULL
                                                             , NULL
                                                             , @MessageTypeName
                                                             , NULL
                                                             , err.value( '(//ssb:Error/ssb:Description)[1]'
                                                                       , 'NVARCHAR(4000)' ) )
                                               , 1
                                               , @Id ) 
              FROM (SELECT CAST(@MessageBody AS XML) AS err) AS derived;
            ELSE -- did not succeed, did not fail? Why are we here?
              BEGIN 
                RAISERROR( 'Unexpected message type [%s] from service [%s] in [$(EHA_SCHEMA).InitiatorQueue].'
                         , 16
                         , 1
                         , @MessageTypeName
                         , @ServiceName);
                
              END
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
                 , @ErrorData ;
              CLOSE ALL SYMMETRIC KEYS;
          END -- there is a dialog item to process
      END -- conversation group exists
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
ADD SIGNATURE TO $(EHA_SCHEMA).InitiatorActivation 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
IF OBJECT_ID ('$(EHA_SCHEMA).TargetActivation') IS NOT NULL
   DROP PROCEDURE $(EHA_SCHEMA).TargetActivation
GO
-------------------------------------------------------------------------------
--    Desc: handles event notification, data change and backup offload messages
-------------------------------------------------------------------------------
CREATE PROCEDURE $(EHA_SCHEMA).TargetActivation 
WITH EXECUTE AS '$(SPOKE_BROKER)' $(WITH_OPTIONS_FOR_ACTIVATION)
AS
BEGIN
DECLARE @BackupId NVARCHAR(36)
      , @ConversationHandle UNIQUEIDENTIFIER
      , @ConversationGroupId UNIQUEIDENTIFIER
      , @ConversationGroup NVARCHAR(50)
      , @ErrorData VARBINARY(8000)
      , @EventType NVARCHAR(128)
      , @Id NVARCHAR(36)
      , @MAC VARBINARY(128)
      , @MessageBody VARBINARY(MAX)
      , @MessageTypeName NVARCHAR(128)
      , @Parameters VARBINARY(8000)
      , @ReturnCode INT
      , @ServiceName NVARCHAR(128)
      , @Timeout INT = $(TIMER_TIMEOUT)
      , @tvp NAMEVALUETYPE
      , @Version INT ; -- AddNameValue output parameter
SET NOCOUNT ON;
  BEGIN TRY
      WAITFOR ( GET CONVERSATION GROUP @ConversationGroupId 
                FROM $(EHA_SCHEMA).TargetQueue )
          , TIMEOUT 6000; -- a minute - the session keys are open for this
      IF @ConversationGroupId IS NOT NULL
        BEGIN
          RECEIVE TOP(1)
              @ConversationHandle = [conversation_handle]
            , @ServiceName = [service_name]
            , @MessageTypeName = [message_type_name]
            , @MessageBody = [message_body]
          FROM $(EHA_SCHEMA).TargetQueue
          WHERE conversation_group_id = @ConversationGroupId;
          IF @@ROWCOUNT = 1 
            BEGIN  
              -- book and write notification row for each queue item processed
              EXEC $(EHA_SCHEMA).OpenSession;
 	            SET @Parameters = ENCRYPTBYKEY( KEY_GUID('$(AUDIT_SYMMETRIC_KEY)')
                                            , FORMATMESSAGE( 'service_name ''%s'' message_type_name ''%s'''
                                                           , @ServiceName
                                                           , @MessageTypeName )
                                            , 1
                                            , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) );
              CLOSE SYMMETRIC KEY [$(AUDIT_SYMMETRIC_KEY)];
              EXEC $(EHA_SCHEMA).Book @@PROCID
                                    , @Parameters
                                    , @Id OUTPUT
                                    , @MAC OUTPUT; 
              IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
                              WHERE Id = @Id
                              AND KeyGuid = CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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

              -- all this proc should do is write the event notifications the spoke    
              --IF @MessageTypeName = 'http://schemas.microsoft.com/SQL/Notifications/EventNotification'
              --SET @EventType = CAST( @MessageBody AS XML ).value('(/EVENT_INSTANCE/EventType)[1]','NVARCHAR(128)');
              IF @MessageTypeName = '//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/Backup' 
                BEGIN
                  --SET @BackupId = CAST( @MessageBody AS NVARCHAR(36) );
                  EXEC $(EHA_SCHEMA).OffloadBackup @BackupId = @MessageBody;
                END
              ELSE IF @MessageTypeName = '//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/DataChanges'
              -- if many changes, uncomment the timer to send changes to hub in sets 
                BEGIN
                  -- timer is started on local queue
                  IF NOT EXISTS ( SELECT * FROM $(EHA_SCHEMA).TargetQueue
                                  WHERE message_type_name = 'http://schemas.microsoft.com/SQL/ServiceBroker/DialogTimer' )
                    BEGIN CONVERSATION TIMER ( @ConversationHandle ) TIMEOUT = 120; 
                END
              ELSE IF @MessageTypeName = 'http://schemas.microsoft.com/SQL/ServiceBroker/DialogTimer'
                EXEC $(EHA_SCHEMA).PushChanges;
              
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
ADD SIGNATURE TO $(EHA_SCHEMA).TargetActivation 
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO
-- conversation
CREATE MESSAGE TYPE [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/Backup] VALIDATION = WELL_FORMED_XML;
CREATE MESSAGE TYPE [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/DataChanges] VALIDATION = EMPTY;
CREATE MESSAGE TYPE [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/Reply] VALIDATION = WELL_FORMED_XML;
GO
CREATE CONTRACT [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/SendtoHub]
  ( [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/Backup] SENT BY INITIATOR
  , [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/DataChanges] SENT BY INITIATOR
  , [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/Reply] SENT BY TARGET )  
GO
IF NOT EXISTS ( SELECT * FROM sys.service_queues 
                WHERE name = 'InitiatorQueue'
                AND schema_id = SCHEMA_ID( '$(EHA_SCHEMA)' ) ) 
  CREATE QUEUE $(EHA_SCHEMA).InitiatorQueue 
  WITH RETENTION = ON
     , ACTIVATION ( STATUS = ON
                  , PROCEDURE_NAME = $(EHA_SCHEMA).InitiatorActivation
                  , MAX_QUEUE_READERS = 1
                  , EXECUTE AS '$(SPOKE_BROKER)' ) ;
GO
IF NOT EXISTS ( SELECT * FROM sys.services 
                WHERE name = '$(EHA_SCHEMA)InitiatorService' )
  BEGIN
    CREATE SERVICE $(EHA_SCHEMA)InitiatorService AUTHORIZATION [$(SPOKE_ADMIN)]
    ON QUEUE $(EHA_SCHEMA).InitiatorQueue 
      ( [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/SendtoHub] );

    ALTER SERVICE $(EHA_SCHEMA)TargetService
    ON QUEUE $(EHA_SCHEMA).TargetQueue 
    ( ADD CONTRACT [//$(SPOKE_DATABASE)/$(EHA_SCHEMA)/SendtoHub] );
  END
GO
--IF OBJECT_ID('$(EHA_SCHEMA).CheckQueueSizes','P') IS NOT NULL
--    DROP PROCEDURE $(EHA_SCHEMA).CheckQueueSizes
--GO
-----------------------------------------------------------------------
---- count of a messages in queues according to sys.partitions
-----------------------------------------------------------------------
--CREATE PROCEDURE $(EHA_SCHEMA).GetQueueSizes 
--$(WITH OPTIONS)
--AS
--BEGIN
--  SELECT [InitiatorQueue] AS [Initiator Queue Msg Count]
--        , [sysxmitqueue] AS [Transmission Queue Msg Count]
--        , [TargetQueue] AS [Target Queue Msg Count]
--  FROM (
--        SELECT q.name AS name, p.rows
--        FROM sys.objects AS o
--        JOIN sys.partitions AS p f
--        ON p.object_id = o.object_id
--        JOIN sys.objects AS q 
--        ON o.parent_object_id = q.object_id
--        WHERE o.name = 'InitiatorQueue'
--        AND SCHEMA_NAME(q.schema_id) = '$(EHA_SCHEMA)'
--        AND p.index_id = 1
--      UNION ALL 
--        SELECT o.name AS name, p.rows
--        FROM sys.objects AS o
--        JOIN sys.partitions AS p 
--        ON p.object_id = o.object_id
--        WHERE o.name = 'sysxmitqueue'
--      UNION ALL
--        SELECT q.name AS name, p.rows
--        FROM sys.objects AS o
--        JOIN sys.partitions AS p 
--        ON p.object_id = o.object_id
--        JOIN sys.objects AS q 
--        ON o.parent_object_id = q.object_id
--        WHERE q.name = 'TargetQueue'
--        AND SCHEMA_NAME(q.schema_id) = '$(EHA_SCHEMA)'
--        AND p.index_id = 1 
--                           ) AS SourceData
--  PIVOT (SUM(rows) FOR name IN ( [InitiatorQueue]
--                               , [sysxmitqueue]
--                               , [TargetQueue] ) ) AS PivotTable;     
--END;
--GO
--ADD SIGNATURE TO $(EHA_SCHEMA).GetQueueSizes
--BY CERTIFICATE $(OBJECT_CERTIFICATE)
--WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
--GO
---- DDL events from above should be in the queue - and any other changes that happened
--EXEC $(EHA_SCHEMA).GetQueueSizes;
GO
ALTER QUEUE $(EHA_SCHEMA).TargetQueue 
WITH ACTIVATION ( STATUS = ON 
                , PROCEDURE_NAME = $(EHA_SCHEMA).TargetActivation
                , MAX_QUEUE_READERS = 1
                , EXECUTE AS '$(SPOKE_BROKER)' ) ;
GO
------------------------------------------------------------------------------------------------------
-- verify OBJECT_COUNT and DELTA
------------------------------------------------------------------------------------------------------
-- if  values provided are incorrect (objects are added/removed) 
-- used as part of run-time schema validation/sanity check
-- nothing will work if counts change & these values are not updated before installing
SELECT ISNULL(obj.type, sig.type) AS ObjectType
     , ISNULL(obj.ObjectCount, 0) AS ObjectCount
     , IIF(ISNULL(obj.type, sig.type) = 'OBJECT_COUNT'
          , '$(OBJECT_COUNT)'
          , '') AS [setvar OBJECT_COUNT]
     , ISNULL(sig.SignedCount, 0) AS SignedCount 
     , ISNULL(obj.ObjectCount, 0) - ISNULL(sig.SignedCount, 0) AS Delta
     , IIF(ISNULL(obj.type, sig.type) = 'OBJECT_COUNT'
          , '$(DELTA)'
          , '') AS [setvar DELTA]
FROM (SELECT IIF(GROUPING(type_desc) = 1, 'OBJECT_COUNT', type_desc) AS type
           , COUNT(*) AS [ObjectCount]
      FROM sys.objects
      WHERE SCHEMA_NAME(schema_id) = '$(EHA_SCHEMA)'
      AND parent_object_id = 0
      OR type = 'TR' 
      GROUP BY type_desc 
      WITH ROLLUP) as obj
FULL OUTER JOIN 
     (SELECT IIF(grouping(type) = 1, 'OBJECT_COUNT', s.type) AS type
           , COUNT(*) AS [SignedCount]
      FROM sys.certificates c
      CROSS APPLY sys.fn_check_object_signatures ( 'CERTIFICATE', c.thumbprint ) s
      WHERE c.name = 'ObjectCertificate'--'$(OBJECT_CERTIFICATE)'
      AND c.pvt_key_encryption_type = 'PW'
      AND OBJECT_SCHEMA_NAME (s.entity_id) = '$(EHA_SCHEMA)'
      AND s.is_signature_valid = 1	
      GROUP BY s.type 
      WITH ROLLUP) AS sig
ON obj.type = sig.type;
GO
------------------------------------------------------------------------------------------------------
-- first booking
------------------------------------------------------------------------------------------------------
-- a SESSION_SYMMETRIC_KEY must be open before any white-listed procedure is run
-- and every white-listed procedure ends with CLOSE ALL SYMMETRIC KEYS
-- the key is always a temp object encrypted by the SESSION_SYMMETRIC_KEY   
------------------------------------------------------------------------------------------------------
EXEC $(EHA_SCHEMA).OpenSession; 
INSERT INTO $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
  ( Id
  , ProcId
  , ObjectName
  , Parameters
  , KeyGuid
  , Status )
VALUES ( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
       , 0   
       , 'InstallSpoke.sql'
       , ENCRYPTBYKEY( KEY_GUID( '$(AUDIT_SYMMETRIC_KEY)')
                     , N'WITH_OPTIONS "$(WITH_OPTIONS)"
WITH_OPTIONS_FOR_ACTIVATION "$(WITH_OPTIONS_FOR_ACTIVATION)"
EXPORT_PATH "$(EXPORT_PATH)"
SESSION_SYMMETRIC_KEY "$(SESSION_SYMMETRIC_KEY)"
SESSION_KEY_SOURCE "$(SESSION_KEY_SOURCE)"
SESSION_KEY_IDENTITY "$(SESSION_KEY_IDENTITY)"
TDE_CERTIFICATE "$(TDE_CERTIFICATE)"
TDE_CERTIFICATE_ALGORITHM "$(TDE_CERTIFICATE_ALGORITHM)"
AUDIT_CERTIFICATE "$(AUDIT_CERTIFICATE)"
AUDIT_SYMMETRIC_KEY "$(AUDIT_SYMMETRIC_KEY)"
AUDIT_KEY_ENCRYPTION_ALGORITHM "$(AUDIT_KEY_ENCRYPTION_ALGORITHM)"
AUDIT_TO "$(AUDIT_TO)"
AUTHENTICITY_CERTIFICATE "$(AUTHENTICITY_CERTIFICATE)"
ERROR_SYMMETRIC_KEY "$(ERROR_SYMMETRIC_KEY)"
ERROR_KEY_ENCRYPTION_ALGORITHM "$(ERROR_KEY_ENCRYPTION_ALGORITHM)"
EVENT_CERTIFICATE "$(EVENT_CERTIFICATE)"
FILE_CERTIFICATE "$(FILE_CERTIFICATE)"
FILE_SYMMETRIC_KEY "$(FILE_SYMMETRIC_KEY)"
FILE_KEY_ENCRYPTION_ALGORITHM "$(FILE_KEY_ENCRYPTION_ALGORITHM)"
NAME_CERTIFICATE "$(NAME_CERTIFICATE)"
NAME_SYMMETRIC_KEY "$(NAME_SYMMETRIC_KEY)"
NAME_KEY_ENCRYPTION_ALGORITHM "$(NAME_KEY_ENCRYPTION_ALGORITHM)"
OBJECT_CERTIFICATE "$(OBJECT_CERTIFICATE)"
VALUE_CERTIFICATE "$(VALUE_CERTIFICATE)"
VALUE_SYMMETRIC_KEY "$(VALUE_SYMMETRIC_KEY)"
VALUE_KEY_ENCRYPTION_ALGORITHM "$(VALUE_KEY_ENCRYPTION_ALGORITHM)"
HASHBYTES_ALGORITHM "$(HASHBYTES_ALGORITHM)"
MESSAGE_OFFSET "$(MESSAGE_OFFSET)"
MIN_PHRASE_LENGTH "$(MIN_PHRASE_LENGTH)"
OBJECT_COUNT "$(OBJECT_COUNT)"
DELTA "$(DELTA)"
MAX_TRACE_COUNT "$(MAX_TRACE_COUNT)"
USE_HASH_FOR_FILENAME "$(USE_HASH_FOR_FILENAME)"
EVENT_NOTIFICATION "$(EVENT_NOTIFICATION)"
TIMER_TIMEOUT "$(TIMER_TIMEOUT)"
HUB_DATASOURCE "$(HUB_DATASOURCE)"
HUB_SERVER_NAME "$(HUB_SERVER_NAME)"
HUB_LINKED_SERVER_NAME "$(HUB_LINKED_SERVER_NAME)"
BOOKINGS_SYNONYM "$(BOOKINGS_SYNONYM)"
BACKUPS_SYNONYM "$(BACKUPS_SYNONYM)"
BACKUP_ACTIVITY_SYNONYM "$(BACKUP_ACTIVITY_SYNONYM)"
HUB_ACTIVITY_SYNONYM "$(HUB_ACTIVITY_SYNONYM)"
NAMEVALUES_SYNONYM "$(NAMEVALUES_SYNONYM)"
NAMEVALUE_ACTIVITY_SYNONYM "$(NAMEVALUE_ACTIVITY_SYNONYM)"
NOTIFICATION_ACTIVITY_SYNONYM "$(NOTIFICATION_ACTIVITY_SYNONYM)"
SPOKE_ACTIVITY_SYNONYM "$(SPOKE_ACTIVITY_SYNONYM)"
REPORT_ACTIVITY_SYNONYM "$(REPORT_ACTIVITY_SYNONYM)"
MASTER_KEY_BACKUP_EXT "$(MASTER_KEY_BACKUP_EXT)"
PRIVATE_KEY_BACKUP_EXT "$(PRIVATE_KEY_BACKUP_EXT)"
PUBLIC_KEY_BACKUP_EXT "$(PUBLIC_KEY_BACKUP_EXT)"
SPOKE_ADMIN "$(SPOKE_ADMIN)"
SPOKE_BROKER "$(SPOKE_BROKER)"
SPOKE_DATABASE v$(SPOKE_DATABASE)"
HUB_DATABASE "$(HUB_DATABASE)"
EHA_SCHEMA "$(EHA_SCHEMA)"
HUB_ADMIN_ROLE "$(HUB_ADMIN_ROLE)"
SPOKE_ADMIN_ROLE "$(SPOKE_ADMIN_ROLE)"
BOOKINGS_TABLE "$(BOOKINGS_TABLE)"
BACKUPS_TABLE "$(BACKUPS_TABLE)"
BACKUP_ACTIVITY_TABLE "$(BACKUP_ACTIVITY_TABLE)"
HUB_ACTIVITY_TABLE "$(HUB_ACTIVITY_TABLE)"
NAMEVALUES_TABLE "$(NAMEVALUES_TABLE)"
NAMEVALUE_ACTIVITY_TABLE "$(NAMEVALUE_ACTIVITY_TABLE)"
NOTIFICATION_ACTIVITY_TABLE "$(NOTIFICATION_ACTIVITY_TABLE)"
SPOKE_ACTIVITY_TABLE "$(SPOKE_ACTIVITY_TABLE)"
REPORT_ACTIVITY_TABLE "$(REPORT_ACTIVITY_TABLE)"
FILESTREAM_FILEGROUP "$(FILESTREAM_FILEGROUP)"
FILESTREAM_FILE "$(FILESTREAM_FILE)"
FILETABLE_DIRECTORY "$(FILETABLE_DIRECTORY)"'
                               , 1  
                               , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) ) )
       , CAST( KEY_GUID('$(SESSION_SYMMETRIC_KEY)') AS NVARCHAR(36) )
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
WHERE Id = KEY_GUID('$(SESSION_SYMMETRIC_KEY)'); 
CLOSE ALL SYMMETRIC KEYS;
GO
-- generate and the salt seed for all hash columns and save in NAMEVALUE_TABLE
EXEC $(EHA_SCHEMA).OpenSession;
EXEC $(EHA_SCHEMA).MakeSalt '$(SPOKE_DATABASE)', '$(EHA_SCHEMA)', '$(BACKUP_ACTIVITY_TABLE)', 'BackupNameBucket';
GO
EXEC $(EHA_SCHEMA).OpenSession;
EXEC $(EHA_SCHEMA).MakeSalt '$(SPOKE_DATABASE)', '$(EHA_SCHEMA)', '$(BACKUP_ACTIVITY_TABLE)', 'Colophon';
GO
EXEC $(EHA_SCHEMA).OpenSession;
EXEC $(EHA_SCHEMA).MakeSalt '$(SPOKE_DATABASE)', '$(EHA_SCHEMA)', '$(NAMEVALUES_TABLE)', 'NameBucket';
GO
EXEC $(EHA_SCHEMA).OpenSession;
EXEC $(EHA_SCHEMA).MakeSalt '$(SPOKE_DATABASE)', '$(EHA_SCHEMA)', '$(NAMEVALUES_TABLE)', 'ValueBucket';
GO
------------------------------------------------------------------------------------------------------
-- local backups of cryptographic objects created by script, push changes to hub, offload backups
------------------------------------------------------------------------------------------------------
-- SQL Trace "assignment obfuscation" is ineffective for call stored procedures and sp_executesql 
-- SP:Starting of the crypto-objects backups will reveal the secrets 
-- blogs.msdn.com/b/sqlsecurity/archive/2009/06/10/filtering-obfuscating-sensitive-text-in-sql-server.aspx
-- a temp session symmetric key is used to encrypt before passing. This relies upon crypto-DDL 
-- obfuscation. The temp key goes away when user closes the SQL Server connection.   
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
EXEC $(EHA_SCHEMA).BackupDatabaseMasterKey @DbName = N'$(SPOKE_DATABASE)'
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
                                   , @DbName = N'$(SPOKE_DATABASE)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = DEFAULT
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(VALUE_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @CertificateName = N'$(VALUE_CERTIFICATE)'
                                   , @DbName = N'$(SPOKE_DATABASE)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = DEFAULT
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(FILE_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @CertificateName = N'$(FILE_CERTIFICATE)'
                                   , @DbName = N'$(SPOKE_DATABASE)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = DEFAULT
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(AUTHENTICITY_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @Certificatename = N'$(AUTHENTICITY_CERTIFICATE)'
                                   , @DbName = N'$(SPOKE_DATABASE)'
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
                                   , @DbName = N'$(SPOKE_DATABASE)'
                                   , @BackupPhrase = @BackupPhrase
                                   , @KeyPhrase = @KeyPhrase
                                   , @UseHash = $(USE_HASH_FOR_FILENAME)
                                   , @ForceNew = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
SET @BackupPhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                        ,  CAST( '$(EVENT_CERTIFICATE_BACKUP_PHRASE)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).BackupCertificate @Certificatename = N'$(EVENT_CERTIFICATE)'
                                   , @DbName = N'$(SPOKE_DATABASE)'
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
                                   , @DbName = N'$(SPOKE_DATABASE)'
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
EXEC $(EHA_SCHEMA).AddPortableSymmetricKey @KeyName = '$(ERROR_SYMMETRIC_KEY)'
                                          , @KeyIdentity = @KeyIdentity
                                          , @KeySource = @KeySource;
-- redundant because SQL Server encrypts any cached linked server passwords  - but that one cannot be recalled 
EXEC $(EHA_SCHEMA).OpenSession;
SET @PrivatePhrase = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                         ,  CAST( '$(PRIVATE_ENCRYPTION_PHRASE)' AS NVARCHAR(128) ) ) );
SET @Value = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                 ,  CAST( '$(SPOKE_ADMIN_PASSWORD)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).AddPrivateValue @Name = 'SPOKE_ADMIN_PASSWORD'
                                  , @Value = @Value
                                  , @EncryptionPhrase = @PrivatePhrase
                                  , @AuditPrivateData = DEFAULT;
EXEC $(EHA_SCHEMA).OpenSession;
-- already have @PrivatePhrase 
SET @Value = (SELECT ENCRYPTBYKEY( KEY_GUID('$(SESSION_SYMMETRIC_KEY)')
                                 ,  CAST( '$(SPOKE_BROKER_PASSWORD)' AS NVARCHAR(128) ) ) );
EXEC $(EHA_SCHEMA).AddPrivateValue @Name = 'SPOKE_BROKER_PASSWORD'
                                  , @Value = @Value
                                  , @EncryptionPhrase = @PrivatePhrase
                                  , @AuditPrivateData = DEFAULT;

EXEC $(EHA_SCHEMA).OpenSession;
EXEC $(EHA_SCHEMA).PushChanges;
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

