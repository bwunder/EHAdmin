:on error exit
select * from sys.configurations
-------------------------------------------------------------------------------
-- Encryption Hierarchy Administration Hub  
-- secure offsite storage of encryption hierarchy backups for n SQL Servers 
-------------------------------------------------------------------------------
-- Pre-requisites 
--  1. any SQL Server that is accessible via linked server to ODBC DSN
--     tested with hub hosted on SQL 2012, SQLExpress 2012 or SQLAzure
-- Notes:
--  1. Use this script in SSMS/SSDT using SQLCMD mode only. 
--  2. Replace template tokens with your values
--  3. NEVER save this script once your values have been entered 
--  4. User database is created if specified database does not exist by name
--  5. SQLCDM variables must match values used in InstallSpoke.sql 
--     could be better to call this script from InstallSpoke.sql?
--  6. ODBC Administrator - Start|Run|odbcad32.exe
--     note that linked servers cannot instantiate localdb connections
--  7. drop database to uninstall hub 
-------------------------------------------------------------------------------

:setvar LINK_EHDB                              "ehdbHub"               
:setvar LINK_SCHEMA                            "eha"                   
:setvar LINK_EHADMIN_ROLE                      "EHAdminRole"           
:setvar LINK_BOOKINGS_TABLE                    "Bookings"              
:setvar LINK_BACKUP_ACTIVITY_TABLE             "BackupActivity"        
:setvar LINK_CONTAINERS_TABLE                  "Containers"            
:setvar LINK_CONTAINER_ACTIVITY_TABLE          "ContainerActivity"     
:setvar LINK_NAMEVALUES_TABLE                  "NameValues"            
:setvar LINK_NAMEVALUE_ACTIVITY_TABLE          "NameValueActivity"     
:setvar LINK_NOTIFICATION_ACTIVITY_TABLE       "NotificationActivity"  
:setvar LINK_OFFSITE_ACTIVITY_TABLE            "OffsiteActivity"       
:setvar LINK_REPORT_ACTIVITY_TABLE             "ReportActivity"        
:setvar LINK_USER                              "bwunder"                -- "<[LINK_USER],SYSNAME,bwunder>"                                                
:setvar LINK_PASSWORD                          "si*%tFE#4RfHgf"         -- "<[LINK_PASSWORD],SYSNAME,si*%tFE#4RfHgf>"                                     
GO
-- dump current contents of hub
--USE $(LINK_EHDB);
--SELECT '$(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE)' AS [Table]
--SELECT * FROM $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE);
--SELECT '$(LINK_SCHEMA).$(LINK_BACKUP_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(LINK_SCHEMA).$(LINK_BACKUP_ACTIVITY_TABLE);
--SELECT '$(LINK_SCHEMA).$(LINK_CONTAINERS_TABLE)' AS [Table]
--SELECT * FROM $(LINK_SCHEMA).$(LINK_CONTAINERS_TABLE);
--SELECT '$(LINK_SCHEMA).$(LINK_CONTAINER_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(LINK_SCHEMA).$(LINK_CONTAINER_ACTIVITY_TABLE);
--SELECT '$(LINK_SCHEMA).$(LINK_NAMEVALUES_TABLE)' AS [Table]
--SELECT * FROM $(LINK_SCHEMA).$(LINK_NAMEVALUES_TABLE);
--SELECT '$(LINK_SCHEMA).$(LINK_NAMEVALUE_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(LINK_SCHEMA).$(LINK_NAMEVALUE_ACTIVITY_TABLE);
--SELECT '$(LINK_SCHEMA).$(LINK_NOTIFICATION_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(LINK_SCHEMA).$(LINK_NOTIFICATION_ACTIVITY_TABLE);
--SELECT '$(LINK_SCHEMA).$(LINK_OFFSITE_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(LINK_SCHEMA).$(LINK_OFFSITE_ACTIVITY_TABLE);
--SELECT '$(LINK_SCHEMA).$(LINK_REPORT_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(LINK_SCHEMA).$(LINK_REPORT_ACTIVITY_TABLE);
GO

IF SERVERPROPERTY('Edition') <> 'SQL Azure'
  BEGIN
    EXEC sp_configure 'contained database authentication', 1;
    RECONFIGURE;
    EXEC sp_configure 'contained database authentication';
    IF DB_ID('$(LINK_EHDB)') IS NOT NULL
      BEGIN
        ALTER DATABASE $(LINK_EHDB) 
        SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
        USE master;
        DROP DATABASE $(LINK_EHDB);
      END
  END 
GO
IF SERVERPROPERTY('Edition') <> 'SQL Azure'
  CREATE DATABASE $(LINK_EHDB);
GO
IF SERVERPROPERTY('Edition') <> 'SQL Azure'
  BEGIN
    USE $(LINK_EHDB);
    ALTER DATABASE $(LINK_EHDB) SET CONTAINMENT = PARTIAL;
    IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = N'$(LINK_EHADMIN_ROLE)' AND type = 'R')
      CREATE ROLE [$(LINK_EHADMIN_ROLE)]
    IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = N'$(LINK_SCHEMA)')
      EXEC sys.sp_executesql N'CREATE SCHEMA [$(LINK_SCHEMA)]';
    GRANT INSERT, SELECT ON SCHEMA::$(LINK_SCHEMA) TO $(LINK_EHADMIN_ROLE);
    IF USER_ID ('$(LINK_USER)') IS NULL
      CREATE USER $(LINK_USER) WITH PASSWORD = '$(LINK_PASSWORD)';  
    ALTER ROLE [$(LINK_EHADMIN_ROLE)]
    ADD MEMBER $(LINK_USER);
 END
GO

IF OBJECT_ID('$(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE)') IS NULL
  BEGIN
	CREATE TABLE $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE) 
	  ( Id UNIQUEIDENTIFIER NOT NULL 
      , ServerName NVARCHAR(128) NOT NULL
	  , ProcId INT NULL
	  , ObjectName NVARCHAR (128) NULL
      , Parameters VARBINARY (8000) NOT NULL
      , Status VARCHAR (30) NOT NULL
        CONSTRAINT ck_$(LINK_BOOKINGS_TABLE)__Status 
        CHECK (Status IN ( 'audit'
                         , 'authority'
                         , 'caller'
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
                         , 'sign'))
      , ErrorData VARBINARY(8000) SPARSE NULL
      , CreateUTCDT DATETIME NOT NULL
	  , CreateUser NVARCHAR(128) NOT NULL
	  , CONSTRAINT pkc_$(LINK_BOOKINGS_TABLE)__Id__ServerName
	    PRIMARY KEY CLUSTERED (Id, ServerName) );
     CREATE NONCLUSTERED INDEX ixn_$(LINK_BOOKINGS_TABLE)__CreateUTCDT
     ON $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE) (CreateUTCDT);
  END
GO
IF OBJECT_ID('$(LINK_SCHEMA).$(LINK_BACKUP_ACTIVITY_TABLE)') IS NULL
  BEGIN
	CREATE TABLE $(LINK_SCHEMA).$(LINK_BACKUP_ACTIVITY_TABLE) 
      ( Id UNIQUEIDENTIFIER NOT NULL 
      , ServerName NVARCHAR(128) NOT NULL 
      , DbName NVARCHAR(128) NOT NULL
      , Node NVARCHAR(256) NULL 
      , Level INT 
	  , NodeName NVARCHAR (128) NOT NULL
      , BackupName VARBINARY(8000) NOT NULL -- CalculateCipherLen('ValueKey',896,1)=964-- NVARCHAR(448)
      , BackupNameBucket INT NOT NULL 
      , UseHash BIT NOT NULL          
      , BackupPath VARBINARY(8000) NOT NULL -- CalculateCipherLen('ValueKey',2048,1)=2116-- NVARCHAR(1024)
      , BackupPhraseVersion SMALLINT NOT NULL
      , KeyPhraseVersion SMALLINT NULL
      , Colophon INT NOT NULL  -- checksum of the hash of key guids and cert thumbprints
      , Edition SMALLINT NOT NULL  -- the number of backups made for the current Colophon       
      , MAC VARBINARY (128) NOT NULL
      , Action VARCHAR (30) NOT NULL
      , Status VARCHAR (30) NOT NULL
        CONSTRAINT ck_$(LINK_BACKUP_ACTIVITY_TABLE)__Status 
        CHECK (Status IN ( 'Complete'
                         , 'Error'
                         , 'Instead'
                         , 'Offsite' ) ) 
      , CipherType CHAR (2) NOT NULL
        CONSTRAINT ck_$(LINK_BACKUP_ACTIVITY_TABLE)__CipherType 
        CHECK (CipherType IN ( 'A1'   -- AES 128 
                             , 'A2'   -- AES 192
                             , 'A3'   -- AES 256 (Denali DPAPI)
                             , 'AK'   -- asymmetric key
                             , 'D3'   -- Triple DES (Yukon DPAPI)
                             , 'DT'   -- Triple DES 3KEY
                             , 'NA'   -- EKM or no private key in database
                             , 'MK'   -- database master key
                             , 'PW'   -- passphrase
                             , 'SK'   -- symmetric key
                             , 'SM'   -- service master key
                             , 'SP'   -- service master key AND passphrase
                             , '' ) ) -- undetermined
        , ErrorData VARBINARY(8000) SPARSE NULL
		, CreateUTCDT DATETIME NOT NULL
		, CreateUser NVARCHAR(128) NOT NULL
		, CONSTRAINT pkc_$(LINK_BACKUP_ACTIVITY_TABLE)__Id__ServerName
		  PRIMARY KEY ( Id, ServerName )
	    , CONSTRAINT fk_$(LINK_BACKUP_ACTIVITY_TABLE)__Id__ServerName__TO__$(LINK_BOOKINGS_TABLE)__Id__ServerName
	      FOREIGN KEY ( Id, ServerName ) REFERENCES $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE)( Id, ServerName ) );
  END
GO
IF OBJECT_ID('$(LINK_SCHEMA).$(LINK_CONTAINERS_TABLE)', 'U') IS NULL
  BEGIN
    CREATE TABLE $(LINK_SCHEMA).$(LINK_CONTAINERS_TABLE)
      ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR(128) NOT NULL
      , Tag NVARCHAR(128) NOT NULL                             
      , FileImage IMAGE NOT NULL --VARBINARY(MAX) NOT NULL 
      , Signature VARBINARY(8000) NOT NULL
      , CONSTRAINT pkc_$(LINK_CONTAINERS_TABLE)_Id__ServerName
        PRIMARY KEY (Id, ServerName) 
      , CONSTRAINT fk_$(LINK_CONTAINERS_TABLE)__Id__ServerName__TO__$(LINK_BOOKINGS_TABLE)__Id__ServerName
		FOREIGN KEY ( Id, ServerName ) REFERENCES $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE)(Id, ServerName) );
  END    
GO
IF OBJECT_ID('$(LINK_SCHEMA).$(LINK_CONTAINER_ACTIVITY_TABLE)', 'U') IS NULL
  BEGIN
    CREATE TABLE $(LINK_SCHEMA).$(LINK_CONTAINER_ACTIVITY_TABLE)
      ( Id UNIQUEIDENTIFIER NOT NULL 
      , ServerName NVARCHAR(128) NOT NULL
      , FileName VARBINARY(8000)  
      , FilePath VARBINARY(8000) 
      , SizeInBytes BIGINT NOT NULL -- enough to infer a local file? 
      , MAC VARBINARY (128) NOT NULL
      , Action VARCHAR (30) NOT NULL
        CONSTRAINT ck_$(LINK_CONTAINER_ACTIVITY_TABLE)__Action 
        CHECK (Action IN ( 'BackupContainer'  -- Archive scope is complete schema 
                         , 'RecallContainer'  -- recall from archive also at item granularity
                         , 'RestoreContainer' ) )
	  , Status VARCHAR (30) NOT NULL
        CONSTRAINT ck_$(LINK_CONTAINER_ACTIVITY_TABLE)__Status 
        CHECK (Status IN ( 'Complete'
                         , 'Error' ) )
      , ErrorData VARBINARY(8000) SPARSE NULL
	  , CreateUTCDT DATETIME NOT NULL
	  , CreateUser NVARCHAR(128) NOT NULL
      , CONSTRAINT pkc_$(LINK_CONTAINER_ACTIVITY_TABLE)_Id__ServerName
        PRIMARY KEY (Id, ServerName) 
      , CONSTRAINT fk_$(LINK_CONTAINER_ACTIVITY_TABLE)__Id__ServerName__TO__$(LINK_BOOKINGS_TABLE)__Id__ServerName
		FOREIGN KEY ( Id, ServerName) REFERENCES $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE)( Id, ServerName ) );
  END
GO
IF OBJECT_ID('$(LINK_SCHEMA).$(LINK_NAMEVALUES_TABLE)') IS NULL
  BEGIN
    CREATE TABLE $(LINK_SCHEMA).$(LINK_NAMEVALUES_TABLE) 
	( Id UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL
	, NameBucket INT NOT NULL 
    , ValueBucket INT NOT NULL
	, Version SMALLINT NOT NULL 
	, Name VARBINARY (8000) NOT NULL  
	, Value VARBINARY (8000) NOT NULL --CalculateCipherLen 
	, CreateUTCDT DATETIME NOT NULL
	, CreateUser NVARCHAR(128) NOT NULL
	, CONSTRAINT pkc_$(LINK_NAMEVALUES_TABLE)__Id__ServerName
	  PRIMARY KEY (Id, ServerName)
	, CONSTRAINT fk_$(LINK_NAMEVALUES_TABLE)__Id__ServerName__TO__$(LINK_BOOKINGS_TABLE)__Id__ServerName
	  FOREIGN KEY ( Id, ServerName ) REFERENCES $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE)( Id, ServerName ) );
  END
GO 
IF OBJECT_ID('$(LINK_SCHEMA).$(LINK_NAMEVALUE_ACTIVITY_TABLE)') IS NULL
  BEGIN
	  CREATE TABLE $(LINK_SCHEMA).$(LINK_NAMEVALUE_ACTIVITY_TABLE) 
		  ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR(128) NOT NULL
      , MAC VARBINARY(128) NOT NULL
		  , Action VARCHAR (128) NOT NULL
		  , Status VARCHAR (30) NOT NULL
            CONSTRAINT ck_$(LINK_NAMEVALUE_ACTIVITY_TABLE)__Status 
            CHECK (Status IN ( 'Complete'
                             , 'Error'
                             , 'Instead'
                             , 'Invalid'
                             , 'Valid' ) )
		  , ErrorData VARBINARY(8000) SPARSE NULL 
		  , CreateUTCDT DATETIME NOT NULL
		  , CreateUser NVARCHAR(128)
		  , CONSTRAINT pkc_$(LINK_NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName
		    PRIMARY KEY (Id, ServerName)
		  , CONSTRAINT fk_$(LINK_NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName__TO__$(LINK_BOOKINGS_TABLE)__Id__ServerName
		    FOREIGN KEY ( Id, ServerName ) REFERENCES $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE)( Id, ServerName ) );
  END
GO
IF OBJECT_ID('$(LINK_SCHEMA).$(LINK_NOTIFICATION_ACTIVITY_TABLE)') IS NULL
  BEGIN
    CREATE TABLE $(LINK_SCHEMA).$(LINK_NOTIFICATION_ACTIVITY_TABLE)
      ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR(128) NOT NULL 
      , ConversationHandle UNIQUEIDENTIFIER NOT NULL
      , ConversationGroupId UNIQUEIDENTIFIER NOT NULL
      , Message IMAGE NOT NULL
      , Signature VARBINARY(8000) NOT NULL
      , MAC VARBINARY(128) NOT NULL
      , Action VARCHAR(30)
      , Status VARCHAR(30)
        CONSTRAINT ck_$(LINK_NOTIFICATION_ACTIVITY_TABLE)__Status 
        CHECK ( Status IN ( 'Complete'
                          , 'Error' ) )
      , ErrorData VARBINARY(8000) SPARSE NULL
      , CreateUTCDT DATETIME
	    , CreateUser NVARCHAR(128) NOT NULL
      , CONSTRAINT pkc_$(LINK_NOTIFICATION_ACTIVITY_TABLE)__Id__ServerName
        PRIMARY KEY (Id, ServerName ) 
      , CONSTRAINT fk_$(LINK_NOTIFICATION_ACTIVITY_TABLE)__Id__ServerName__TO__$(LINK_BOOKINGS_TABLE)__Id__ServerName
        FOREIGN KEY ( Id, ServerName ) 
        REFERENCES $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE)( Id, ServerName ) );   
  END 
GO
IF OBJECT_ID('$(LINK_SCHEMA).$(LINK_OFFSITE_ACTIVITY_TABLE)') IS NULL
  BEGIN
    CREATE TABLE $(LINK_SCHEMA).$(LINK_OFFSITE_ACTIVITY_TABLE)
      ( Id UNIQUEIDENTIFIER NOT NULL
      , CaptureInstance NVARCHAR(128) NOT NULL
        CONSTRAINT ck_$(LINK_OFFSITE_ACTIVITY_TABLE)__CaptureInstance 
        CHECK (CaptureInstance IN ( '$(LINK_SCHEMA)_$(LINK_BOOKINGS_TABLE)'
                                  , '$(LINK_SCHEMA)_$(LINK_BACKUP_ACTIVITY_TABLE)' 
                                  , '$(LINK_SCHEMA)_$(LINK_CONTAINERS_TABLE)' 
                                  , '$(LINK_SCHEMA)_$(LINK_CONTAINER_ACTIVITY_TABLE)' 
                                  , '$(LINK_SCHEMA)_$(LINK_NAMEVALUES_TABLE)' 
                                  , '$(LINK_SCHEMA)_$(LINK_NAMEVALUE_ACTIVITY_TABLE)' 
                                  , '$(LINK_SCHEMA)_$(LINK_NOTIFICATION_ACTIVITY_TABLE)' 
                                  , '$(LINK_SCHEMA)_$(LINK_OFFSITE_ACTIVITY_TABLE)' 
                                  , '$(LINK_SCHEMA)_$(LINK_REPORT_ACTIVITY_TABLE)' 
                                  , 'unknown') )
      , ServerName NVARCHAR(128) NOT NULL 
      , MinLsn BINARY(10) NOT NULL
      , MaxLsn BINARY(10) NOT NULL
      , [RowCount] INT NULL
      , MAC VARBINARY(128) NOT NULL
      , Action VARCHAR(30)
        CONSTRAINT ck_$(LINK_OFFSITE_ACTIVITY_TABLE)__Action 
        CHECK ( Action IN ( 'SendOffsiteCDC'
                          , 'SendOffSiteTC' 
                          , 'RecallContainer' ) )
      , Status VARCHAR(30)
        CONSTRAINT ck_$(LINK_OFFSITE_ACTIVITY_TABLE)__Status 
        CHECK ( Status IN ( 'Complete'
                          , 'Error' ) )
      , ErrorData VARBINARY(8000) SPARSE NULL
      , CreateUTCDT DATETIME
	    , CreateUser NVARCHAR(128) NOT NULL
      , CONSTRAINT pkc_$(LINK_OFFSITE_ACTIVITY_TABLE)__Id__CaptureInstance_ServerName
        PRIMARY KEY (Id, CaptureInstance, ServerName ) 
      , CONSTRAINT fk_$(LINK_OFFSITE_ACTIVITY_TABLE)__Id__ServerName__TO__$(LINK_BOOKINGS_TABLE)__Id__ServerName
        FOREIGN KEY ( Id, ServerName ) 
        REFERENCES $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE)( Id, ServerName ) );   
  END 
GO
IF OBJECT_ID('$(LINK_SCHEMA).$(LINK_REPORT_ACTIVITY_TABLE)') IS NULL
  BEGIN
    CREATE TABLE $(LINK_SCHEMA).$(LINK_REPORT_ACTIVITY_TABLE) 
      ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR(128) NOT NULL 
      , ReportProcedure NVARCHAR(128) NOT NULL
      , Duration_ms INT NULL 
      , RowsReturned INT NULL 
      , MAC VARBINARY(128) NOT NULL
	    , Status VARCHAR (30) NOT NULL
        CONSTRAINT ck_$(LINK_REPORT_ACTIVITY_TABLE)__Status 
        CHECK (Status IN ( 'Complete'
                          , 'Error' ) )
	    , ErrorData VARBINARY(8000) SPARSE NULL
	    , CreateUTCDT DATETIME NOT NULL
	    , CreateUser NVARCHAR(128) NOT NULL
	    , CONSTRAINT pkc_$(LINK_REPORT_ACTIVITY_TABLE)__Id__ServerName
		    PRIMARY KEY (Id, ServerName)
      , CONSTRAINT fk_$(LINK_REPORT_ACTIVITY_TABLE)__Id__ServerName__TO__$(LINK_BOOKINGS_TABLE)__Id__ServerName
        FOREIGN KEY ( Id, ServerName ) REFERENCES $(LINK_SCHEMA).$(LINK_BOOKINGS_TABLE)( Id, ServerName ) );
  END
GO

