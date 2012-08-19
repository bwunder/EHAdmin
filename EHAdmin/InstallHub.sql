:on error exit
-------------------------------------------------------------------------------
-- Encryption Hierarchy Administration Hub  
-- central storage of the already secured spoke schema(s)
-------------------------------------------------------------------------------
-- Pre-requisites 
--  1. SQL Server SQL Server 2012, SQLExpress 2012* or SQLAzure 
--  2. Contained database accessible from all spokes via linked server (ODBC)
--     note that a linked server cannot access a (localdb) or user instance
-- Notes:
--  1. No local native T-SQL cryptographic methods or objects used   
--  2. SQL Authentication is used - linked server encrypts stored password  
--  3. To configure ODBC DSN - run|odbcad32.exe 
-- blogs.msdn.com/b/sqlcat/archive/2011/03/08/linked-servers-to-sql-azure.aspx
--  4. Use this script in SQLClue or SSMS/SSDT using SQLCMD mode. 
--  5. Replace template SQLCMD variables with your values
--  6. DO NOT save this script once your values have been entered... EVER 
--  7. User database is created if specified database does not exist by name
--     as a partially contained database if not SQL Azure
--
--  8. uninstall hub located just below the setvars and is commented 
------------------------------------------------------------------------------
-- principals
:setvar HUB_ADMIN                          "HubAdmin"              -- "<[HUB_ADMIN],SYSNAME,HubAdmin>"                       
:setvar HUB_ADMIN_PASSWORD                 "si*%tPW#4RfHgd"        -- "<[HUB_ADMIN_PASSWORD],PASSPHRASE,si*%tFE#4RfHgd>"     
:setvar SPOKE_ADMIN                        "SpokeAdmin"            -- "<[SPOKE_ADMIN],SYSNAME,SpokeAdmin>"                   
:setvar SPOKE_ADMIN_PASSWORD               "sj*%tFE#4RfHgf"        -- "<[SPOKE_ADMIN_PASSWORD],PASSPHRASE,sj*%tFE#4RfHgf>"   
:setvar SPOKE_BROKER                       "SpokeBroker"           -- "<[SPOKE_BROKER],SYSNAME,SpokeBroker>"                 
:setvar SPOKE_BROKER_PASSWORD              "sk*%tFE#4RfHge"        -- "<[SPOKE_BROKER_PASSWORD],PASSPHRASE,sk*%tFE#4RfHge>"  
-- use is created for testing spoke ODBC DSNs during config - has no role membership or access 
-- can be given to localsystem administrator for configuration of  ODBC DSN and change at any time with no impact to hub 
:setvar HUB_ODBC_AGENT                     "HubAgent"              -- "<[HUB_ODBC_AGENT],SYSNAME,HubAgent>"                  
:setvar HUB_ODBC_AGENT_PASSWORD            "VerifyDSN"             -- "<[HUB_ODBC_AGENT_PASSWORD],PASSPHRASE,VerifyDSN>"     
--databases
:setvar HUB_DATABASE                       "ehHub"                 -- "<[HUB_DATABASE],SYSNAME,ehHub>"                       
:setvar SPOKE_DATABASE                     "ehdb"                  -- "<[SPOKE_DATABASE],SYSNAME,ehdb>"                      
-- schema
:setvar EHA_SCHEMA                         "eha"                   -- "<[EHA_SCHEMA],SYSNAME,eha>"                           
-- roles
:setvar HUB_ADMIN_ROLE                     "HubAdministrators"     
:setvar SPOKE_ADMIN_ROLE                   "SpokedAdministrators"  
:setvar SPOKE_BROKER_ROLE                  "SpokeBrokers"          
-- tables
:setvar BOOKINGS_TABLE                     "Bookings"              
:setvar BACKUPS_TABLE                      "Backups"               
:setvar BACKUP_ACTIVITY_TABLE              "BackupActivity"        
:setvar HUB_ACTIVITY_TABLE                 "HubActivity"           
:setvar NAMEVALUES_TABLE                   "NameValues"            
:setvar NAMEVALUE_ACTIVITY_TABLE           "NameValueActivity"     
:setvar NOTIFICATION_ACTIVITY_TABLE        "NotificationActivity"  
:setvar SPOKE_ACTIVITY_TABLE               "SpokeActivity"         
:setvar REPORT_ACTIVITY_TABLE              "ReportActivity"        
GO
---- uninstall
--USE $(HUB_DATABASE); 
--ALTER DATABASE $(HUB_DATABASE) SET SINGLE_USER WITH ROLLBACK IMMEDIATE; 
--USE master;
--DROP DATABASE $(HUB_DATABASE);  
--EXEC sp_configure 'contained database authentication', 0;
--RECONFIGURE;
--RAISERROR('RECONFIGURE complete...',0,0);
--DROP LOGIN $(SPOKE_ADMIN);
--DROP LOGIN $(SPOKE_BROKER);

---- current contents of hub
--USE $(HUB_DATABASE);
--SELECT '$(EHA_SCHEMA).$(BOOKINGS_TABLE)' AS [Table]
--     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
----SELECT '$(EHA_SCHEMA).$(BOOKINGS_TABLE)' AS [Table], ServerName
----     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
----GROUP BY ServerName;
--SELECT '$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)' AS [Table]
--     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE);
--SELECT '$(EHA_SCHEMA).$(NAMEVALUES_TABLE)' AS [Table]
--     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(NAMEVALUES_TABLE);
--SELECT '$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)' AS [Table]
--     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE);
--SELECT '$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)' AS [Table]
--     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE);
--SELECT '$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)' AS [Table]
--     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE);
--SELECT '$(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)' AS [Table]
--     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE);
--SELECT '$(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE)' AS [Table]
--     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE);

-- If SQL Azure the database must already exist
IF SERVERPROPERTY('Edition') <> 'SQL Azure'
  BEGIN
    IF DB_ID('$(HUB_DATABASE)') IS NOT NULL
      BEGIN
        ALTER DATABASE $(HUB_DATABASE) 
        SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
        USE master;
        DROP DATABASE $(HUB_DATABASE);
      END
    IF ( SELECT value_in_use FROM sys.configurations 
         WHERE name = 'contained database authentication' ) <> 1
      BEGIN
        EXEC sp_configure 'contained database authentication', 1;
        RECONFIGURE;
        RAISERROR('RECONFIGURE complete...',0,0);
      END
    CREATE DATABASE $(HUB_DATABASE) CONTAINMENT = PARTIAL;
    DECLARE @SQL NVARCHAR(256) = 
        ( SELECT FORMATMESSAGE('ALTER AUTHORIZATION ON DATABASE::$(HUB_DATABASE) TO [%s]'
                              , name ) 
          FROM sys.server_principals WHERE sid = 0x01 );
    EXEC sp_executesql @SQL; 
    RAISERROR(@SQL, 0, 0);
  END
GO

USE $(HUB_DATABASE);

IF NOT EXISTS (SELECT * FROM sys.schemas 
                WHERE name = N'$(EHA_SCHEMA)')
  EXEC sys.sp_executesql N'CREATE SCHEMA [$(EHA_SCHEMA)]';

-- users
-- the user running this script also has administrative authority!
IF SERVERPROPERTY('Edition') <> 'SQL Azure'
AND EXISTS ( SELECT * FROM sys.databases 
             WHERE name = DB_NAME() and containment = 1 ) 
  BEGIN
    IF USER_ID ('$(HUB_ADMIN)') IS NULL
      CREATE USER $(HUB_ADMIN) WITH PASSWORD = '$(HUB_ADMIN_PASSWORD)';  

    IF USER_ID ('$(HUB_ODBC_AGENT)') IS NULL
      CREATE USER $(HUB_ODBC_AGENT) WITH PASSWORD = '$(HUB_ODBC_AGENT_PASSWORD)';  

    IF USER_ID ('$(SPOKE_ADMIN)') IS NULL
      CREATE USER $(SPOKE_ADMIN) WITH PASSWORD = '$(SPOKE_ADMIN_PASSWORD)';  

    IF USER_ID ('$(SPOKE_BROKER)') IS NULL
      CREATE USER $(SPOKE_BROKER) WITH PASSWORD = '$(SPOKE_BROKER_PASSWORD)';  
  END
ELSE
  BEGIN
    IF SUSER_SID ( '$(HUB_ADMIN)' ) IS NULL
      CREATE LOGIN $(HUB_ADMIN) WITH PASSWORD = '$(HUB_ADMIN_PASSWORD)';  
    IF USER_ID ('$(HUB_ADMIN)') IS NULL
      CREATE USER $(HUB_ADMIN) FROM LOGIN $(HUB_ADMIN);  

    IF SUSER_SID ( '$(HUB_ODBC_AGENT)' ) IS NULL
      CREATE LOGIN $(HUB_ODBC_AGENT) WITH PASSWORD = '$(HUB_ODBC_AGENT_PASSWORD)';  
    IF USER_ID ('$(HUB_ODBC_AGENT)') IS NULL
      CREATE USER $(HUB_ODBC_AGENT) FROM LOGIN $(HUB_ODBC_AGENT);  

    IF SUSER_SID ( '$(SPOKE_ADMIN)' ) IS NULL
      CREATE LOGIN $(SPOKE_ADMIN) WITH PASSWORD = '$(SPOKE_ADMIN_PASSWORD)';  
    IF USER_ID ('$(SPOKE_ADMIN)') IS NULL
      CREATE USER $(SPOKE_ADMIN) FROM LOGIN $(SPOKE_ADMIN);  

    IF SUSER_SID ( '$(SPOKE_BROKER)' ) IS NULL
      CREATE LOGIN $(SPOKE_BROKER) WITH PASSWORD = '$(SPOKE_BROKER_PASSWORD)';  
    IF USER_ID ('$(SPOKE_BROKER)') IS NULL
      CREATE USER $(SPOKE_BROKER) FROM LOGIN $(SPOKE_BROKER);  
  END

IF NOT EXISTS ( SELECT * FROM sys.database_principals 
                WHERE name = N'$(HUB_ADMIN_ROLE)' 
                AND type = 'R')
  CREATE ROLE [$(HUB_ADMIN_ROLE)];

GRANT CONTROL ON DATABASE::$(HUB_DATABASE) TO $(HUB_ADMIN_ROLE);

ALTER ROLE [$(HUB_ADMIN_ROLE)]
ADD MEMBER $(HUB_ADMIN);
    
IF NOT EXISTS ( SELECT * 
                FROM sys.database_principals 
                WHERE name = ORIGINAL_LOGIN() )
AND SERVERPROPERTY('Edition') <> 'SQL Azure' 
  BEGIN
    DECLARE @CreateUserDDL NVARCHAR(512);
    SET @CreateUserDDL = 'CREATE USER [' + ORIGINAL_LOGIN() + '] FROM LOGIN [' + ORIGINAL_LOGIN() + '];'
                       + 'ALTER ROLE $(HUB_ADMIN_ROLE) ADD MEMBER [' + ORIGINAL_LOGIN() + '];';
    EXEC sp_executesql @CreateUserDDL;
  END 

IF NOT EXISTS ( SELECT * FROM sys.database_principals 
                WHERE name = N'$(SPOKE_BROKER_ROLE)' 
                AND type = 'R')
  CREATE ROLE [$(SPOKE_BROKER_ROLE)]

GRANT SELECT, INSERT ON SCHEMA::$(EHA_SCHEMA) TO $(SPOKE_BROKER_ROLE);

ALTER ROLE [$(SPOKE_BROKER_ROLE)]
ADD MEMBER $(SPOKE_BROKER);

IF NOT EXISTS ( SELECT * FROM sys.database_principals 
                WHERE name = N'$(SPOKE_ADMIN_ROLE)' 
                AND type = 'R')
  CREATE ROLE [$(SPOKE_ADMIN_ROLE)]

GRANT SELECT ON SCHEMA::$(EHA_SCHEMA) TO $(SPOKE_ADMIN_ROLE);

ALTER ROLE [$(SPOKE_ADMIN_ROLE)]
ADD MEMBER $(SPOKE_ADMIN);

IF OBJECT_ID('$(EHA_SCHEMA).$(BOOKINGS_TABLE)') IS NULL
  BEGIN
	  CREATE TABLE $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
	    ( Id UNIQUEIDENTIFIER NOT NULL 
      , ServerName NVARCHAR(128) NOT NULL
	    , ProcId INT NULL
	    , ObjectName NVARCHAR (128) NULL
      , Parameters VARBINARY (8000) NOT NULL
      , Status VARCHAR (30) NOT NULL
      , ErrorData VARBINARY(8000) SPARSE NULL
      , CreateUTCDT DATETIME NOT NULL
	    , CreateUser NVARCHAR(128) NOT NULL
	    , CONSTRAINT pkc_$(BOOKINGS_TABLE)__Id__ServerName
	      PRIMARY KEY CLUSTERED (Id, ServerName) );
    CREATE NONCLUSTERED INDEX ixn_$(BOOKINGS_TABLE)__CreateUTCDT__ServerName
    ON $(EHA_SCHEMA).$(BOOKINGS_TABLE) (CreateUTCDT, ServerName);
  END

IF OBJECT_ID('$(EHA_SCHEMA).$(BACKUPS_TABLE)') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(BACKUPS_TABLE) 
    ( Id UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL 
    , ExportFile VARBINARY(8000) NOT NULL
	  , ErrorData VARBINARY(8000) SPARSE NULL
	  , CreateUTCDT DATETIME NOT NULL
	  , CreateUser NVARCHAR(128) NOT NULL
	  , CONSTRAINT pkc_$(BACKUPS_TABLE)__Id__ServerName
		  PRIMARY KEY (Id, ServerName)
    , CONSTRAINT fk_$(BACKUPS_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
      FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );

IF OBJECT_ID('$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)') IS NULL
	CREATE TABLE $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
    ( Id UNIQUEIDENTIFIER NOT NULL 
    , ServerName NVARCHAR(128) NOT NULL 
    , DbName NVARCHAR(128) NOT NULL
    , Node NVARCHAR(256) NULL 
    , Level INT 
	  , NodeName NVARCHAR(128) NOT NULL
    , BackupName VARBINARY(8000) NOT NULL 
    , BackupNameBucket INT NOT NULL 
    , UseHash BIT NOT NULL          
    , BackupPath VARBINARY(8000) NOT NULL
    , BackupPhraseVersion SMALLINT NOT NULL
    , KeyPhraseVersion SMALLINT NULL
    , Colophon INT NOT NULL 
    , Edition SMALLINT NOT NULL        
    , MAC VARBINARY(128) NOT NULL
    , Action NVARCHAR(128) NOT NULL
    , Status VARCHAR(30) NOT NULL
    , CipherType CHAR(2) NOT NULL
    , ErrorData VARBINARY(8000) SPARSE NULL
		, CreateUTCDT DATETIME NOT NULL
		, CreateUser NVARCHAR(128) NOT NULL
		, CONSTRAINT pkc_$(BACKUP_ACTIVITY_TABLE)__Id__ServerName
		  PRIMARY KEY ( Id, ServerName )
	  , CONSTRAINT fk_$(BACKUP_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
	    FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );

IF OBJECT_ID('$(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE)') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE)
    ( Id UNIQUEIDENTIFIER NOT NULL
    , HubName NVARCHAR(128) NOT NULL
      CONSTRAINT dft_$(HUB_ACTIVITY_TABLE)__ServerName
      DEFAULT (@@SERVERNAME)
    , BookingId UNIQUEIDENTIFIER NULL
    , ServerName NVARCHAR(128) NULL 
    , Action NVARCHAR(128)
    , Status VARCHAR(30)
    , ErrorInfo XML SPARSE NULL
    , CreateUTCDT DATETIME
		  CONSTRAINT dft_$(HUB_ACTIVITY_TABLE)__CreateUTCDT
		  DEFAULT (SYSUTCDATETIME())
		, CreateUser NVARCHAR(128) NOT NULL
		  CONSTRAINT dft_$(HUB_ACTIVITY_TABLE)__CreateUser
		  DEFAULT (ORIGINAL_LOGIN())  
    , CONSTRAINT pkc_$(HUB_ACTIVITY_TABLE)__Id__HubName
      PRIMARY KEY ( Id, HubName ) ); 

IF NOT EXISTS (SELECT * FROM sys.indexes 
               WHERE name = 'ixn_$(HUB_ACTIVITY_TABLE)__BookingId__ServerName' )
  CREATE INDEX ixn_$(HUB_ACTIVITY_TABLE)__BookingId__ServerName
  ON $(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE) ( BookingId, ServerName ) ;   

IF OBJECT_ID('$(EHA_SCHEMA).$(NAMEVALUES_TABLE)') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(NAMEVALUES_TABLE) 
	  ( Id UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL
	  , NameBucket INT NOT NULL 
    , ValueBucket INT NOT NULL
	  , Version SMALLINT NOT NULL 
	  , Name VARBINARY (8000) NOT NULL  
	  , Value VARBINARY (8000) NOT NULL 
   	, CreateUTCDT DATETIME NOT NULL
	  , CreateUser NVARCHAR(128) NOT NULL
	  , CONSTRAINT pkc_$(NAMEVALUES_TABLE)__Id__ServerName
	    PRIMARY KEY (Id, ServerName)
	  , CONSTRAINT fk_$(NAMEVALUES_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
	    FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );

IF OBJECT_ID('$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)') IS NULL
	CREATE TABLE $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
		( Id UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL
    , MAC VARBINARY(128) NOT NULL
		, Action NVARCHAR (128) NOT NULL
		, Status VARCHAR (30) NOT NULL
		, ErrorData VARBINARY(8000) SPARSE NULL 
		, CreateUTCDT DATETIME NOT NULL
		, CreateUser NVARCHAR(128)
		, CONSTRAINT pkc_$(NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName
		  PRIMARY KEY (Id, ServerName)
		, CONSTRAINT fk_$(NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
		  FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );

IF OBJECT_ID('$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)
    ( ConversationHandle UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL 
    , ConversationGroupId UNIQUEIDENTIFIER NOT NULL
    , MessageTypeName NVARCHAR(256) NOT NULL
    , Message VARBINARY(MAX) NOT NULL
    , Hash VARBINARY(8000) NOT NULL
    , Action NVARCHAR(128) NOT NULL
    , Status VARCHAR(30) NOT NULL
    , ErrorData VARBINARY(8000) SPARSE NULL
    , CreateUTCDT DATETIME
	  , CreateUser NVARCHAR(128) NOT NULL
    , CONSTRAINT pkc_$(NOTIFICATION_ACTIVITY_TABLE)__ConversationHandle__ServerName
      PRIMARY KEY (ConversationHandle, ServerName ) );   

IF OBJECT_ID('$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
    ( Id UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL 
    , ReportProcedure NVARCHAR(128) NOT NULL
    , Duration_ms INT NULL 
    , RowsReturned INT NULL 
    , MAC VARBINARY(128) NOT NULL
    , Action AS (ReportProcedure)
	  , Status VARCHAR (30) NOT NULL
	  , ErrorData VARBINARY(8000) SPARSE NULL
	  , CreateUTCDT DATETIME NOT NULL
	  , CreateUser NVARCHAR(128) NOT NULL
	  , CONSTRAINT pkc_$(REPORT_ACTIVITY_TABLE)__Id__ServerName
		  PRIMARY KEY (Id, ServerName)
    , CONSTRAINT fk_$(REPORT_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
      FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );

IF OBJECT_ID('$(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)
    ( Id UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL 
    , MinLsn BINARY(10) NULL 
    , MaxLsn BINARY(10) NULL 
    , [RowCount] INT NULL
    , MAC VARBINARY(128) NOT NULL
    , Action NVARCHAR(128)
    , Status VARCHAR(30)
    , ErrorData VARBINARY(8000) SPARSE NULL
    , CreateUTCDT DATETIME
	  , CreateUser NVARCHAR(128) NOT NULL
    , CONSTRAINT pkc_$(SPOKE_ACTIVITY_TABLE)__Id__ServerName
      PRIMARY KEY ( Id, ServerName ) 
    , CONSTRAINT fk_$(SPOKE_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
      FOREIGN KEY ( Id, ServerName ) 
      REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE) ( Id, ServerName ) );   
GO
INSERT $(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE)
    ( Id
    , BookingId
    , ServerName 
    , Action
    , Status )
VALUES ( NEWID()
       , NULL
       , NULL
       , 'InstallHub.sql'
       , 'Complete' );