:on error exit
-------------------------------------------------------------------------------
-- Encryption Hierarchy Administration Hub  
-- secure offsite storage of encryption hierarchy backups for n SQL Servers 
-------------------------------------------------------------------------------
-- Pre-requisites 
--  1. any SQL Server that is accessible via linked server to ODBC DSN
--     tested with hub hosted on SQL 2012, SQLExpress 2012 or SQLAzure
-- Notes:
--  1. ONLY use this script in SQLClue or SSMS/SSDT using SQLCMD mode. 
--  2. ALWAYS replace template SQLCMD variables with your values
--  3. NEVER save this script once your values have been entered 
--  4. User database is created if specified database does not exist by name
--     contained database if not SQL Azure
--  5. SQLCDM variables must match values used in InstallSpoke.sql 
--  6. ODBC Administrator - Start|Run|odbcad32.exe
--     note that linked servers cannot instantiate localdb connections
--  7. to uninstall hub
--USE ehdbHub; 
--ALTER DATABASE ehdbHub SET SINGLE_USER WITH ROLLBACK IMMEDIATE; 
--USE master;
--DROP DATABASE ehdbHub;  
-------------------------------------------------------------------------------
-- must match names supplied for InstallSpoke.sql or nothing will work
:setvar LINK_EHDB                             "ehdbHub"                -- "<[LINK_EHDB],SYSNAME,ehdbHub>"
:setvar LINK_USER                             "bwunder"                -- "<[LINK_USER],SYSNAME,bwunder>"                                                
:setvar LINK_PASSWORD                         "si*%tFE#4RfHgf"         -- "<[LINK_PASSWORD],SYSNAME,si*%tFE#4RfHgf>"                                     
-- probably no reason to change these
:setvar EHA_SCHEMA                            "eha"                   
:setvar EHADMIN_ROLE                          "EHAdminRole"           
:setvar BOOKINGS_TABLE                        "Bookings"              
:setvar BACKUP_ACTIVITY_TABLE                 "BackupActivity"        
:setvar CONTAINERS_TABLE                      "Containers"            
:setvar CONTAINER_ACTIVITY_TABLE              "ContainerActivity"     
:setvar NAMEVALUES_TABLE                      "NameValues"            
:setvar NAMEVALUE_ACTIVITY_TABLE              "NameValueActivity"     
:setvar NOTIFICATION_ACTIVITY_TABLE           "NotificationActivity"  
:setvar OFFSITE_ACTIVITY_TABLE                "OffsiteActivity"       
:setvar REPORT_ACTIVITY_TABLE                 "ReportActivity"        
GO
-- dump current contents of hub
--USE $(LINK_EHDB);
--SELECT '$(EHA_SCHEMA).$(BOOKINGS_TABLE)' AS [Table]
--SELECT * FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE);
--SELECT '$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE);
--SELECT '$(EHA_SCHEMA).$(CONTAINERS_TABLE)' AS [Table]
--SELECT * FROM $(EHA_SCHEMA).$(CONTAINERS_TABLE);
--SELECT '$(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE);
--SELECT '$(EHA_SCHEMA).$(NAMEVALUES_TABLE)' AS [Table]
--SELECT * FROM $(EHA_SCHEMA).$(NAMEVALUES_TABLE);
--SELECT '$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE);
--SELECT '$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE);
--SELECT '$(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE);
--SELECT '$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)' AS [Table]
--SELECT * FROM $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE);
GO
-- If SQL Azure the database must be already created and user added
IF SERVERPROPERTY('Edition') <> 'SQL Azure'
  BEGIN
    IF DB_ID('$(LINK_EHDB)') IS NOT NULL
      BEGIN
        ALTER DATABASE $(LINK_EHDB) 
        SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
        USE master;
        DROP DATABASE $(LINK_EHDB);
      END
    EXEC sp_configure 'contained database authentication', 1;
    RECONFIGURE;
    CREATE DATABASE $(LINK_EHDB) CONTAINMENT = PARTIAL;
  END
GO
IF SERVERPROPERTY('Edition') <> 'SQL Azure'
  BEGIN
    USE $(LINK_EHDB);
    IF NOT EXISTS ( SELECT * FROM sys.database_principals 
                    WHERE name = N'$(EHADMIN_ROLE)' 
                    AND type = 'R')
      CREATE ROLE [$(EHADMIN_ROLE)]
    IF NOT EXISTS (SELECT * FROM sys.schemas 
                   WHERE name = N'$(EHA_SCHEMA)')
      EXEC sys.sp_executesql N'CREATE SCHEMA [$(EHA_SCHEMA)]';
    GRANT INSERT, SELECT ON SCHEMA::$(EHA_SCHEMA) TO $(EHADMIN_ROLE);
    IF USER_ID ('$(LINK_USER)') IS NULL
      CREATE USER $(LINK_USER) WITH PASSWORD = '$(LINK_PASSWORD)';  
    ALTER ROLE [$(EHADMIN_ROLE)]
    ADD MEMBER $(LINK_USER);
  END
GO

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
GO
IF OBJECT_ID('$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)') IS NULL
	CREATE TABLE $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
    ( Id UNIQUEIDENTIFIER NOT NULL 
    , ServerName NVARCHAR(128) NOT NULL 
    , DbName NVARCHAR(128) NOT NULL
    , Node NVARCHAR(256) NULL 
    , Level INT 
	  , NodeName NVARCHAR (128) NOT NULL
    , BackupName VARBINARY(8000) NOT NULL 
    , BackupNameBucket INT NOT NULL 
    , UseHash BIT NOT NULL          
    , BackupPath VARBINARY(8000) NOT NULL
    , BackupPhraseVersion SMALLINT NOT NULL
    , KeyPhraseVersion SMALLINT NULL
    , Colophon INT NOT NULL 
    , Edition SMALLINT NOT NULL        
    , MAC VARBINARY (128) NOT NULL
    , Action VARCHAR (30) NOT NULL
    , Status VARCHAR (30) NOT NULL
    , CipherType CHAR (2) NOT NULL
    , ErrorData VARBINARY(8000) SPARSE NULL
		, CreateUTCDT DATETIME NOT NULL
		, CreateUser NVARCHAR(128) NOT NULL
		, CONSTRAINT pkc_$(BACKUP_ACTIVITY_TABLE)__Id__ServerName
		  PRIMARY KEY ( Id, ServerName )
	  , CONSTRAINT fk_$(BACKUP_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
	    FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );
GO
IF OBJECT_ID('$(EHA_SCHEMA).$(CONTAINERS_TABLE)', 'U') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(CONTAINERS_TABLE)
    ( Id UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL
    , Tag NVARCHAR(128) NOT NULL                             
    , FileImage VARBINARY(MAX) NOT NULL 
    , Signature VARBINARY(8000) NOT NULL
    , CONSTRAINT pkc_$(CONTAINERS_TABLE)_Id__ServerName
      PRIMARY KEY (Id, ServerName) 
    , CONSTRAINT fk_$(CONTAINERS_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
	    FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)(Id, ServerName) );
GO
IF OBJECT_ID('$(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE)', 'U') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(CONTAINER_ACTIVITY_TABLE)
    ( Id UNIQUEIDENTIFIER NOT NULL 
    , ServerName NVARCHAR(128) NOT NULL
    , FileName VARBINARY(8000)  
    , FilePath VARBINARY(8000) 
    , SizeInBytes BIGINT NOT NULL
    , MAC VARBINARY (128) NOT NULL
    , Action VARCHAR (30) NOT NULL
	  , Status VARCHAR (30) NOT NULL
    , ErrorData VARBINARY(8000) SPARSE NULL
	  , CreateUTCDT DATETIME NOT NULL
	  , CreateUser NVARCHAR(128) NOT NULL
    , CONSTRAINT pkc_$(CONTAINER_ACTIVITY_TABLE)_Id__ServerName
      PRIMARY KEY (Id, ServerName) 
    , CONSTRAINT fk_$(CONTAINER_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
		  FOREIGN KEY ( Id, ServerName) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );
GO
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
GO 
IF OBJECT_ID('$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)') IS NULL
	CREATE TABLE $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
		( Id UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL
    , MAC VARBINARY(128) NOT NULL
		, Action VARCHAR (128) NOT NULL
		, Status VARCHAR (30) NOT NULL
		, ErrorData VARBINARY(8000) SPARSE NULL 
		, CreateUTCDT DATETIME NOT NULL
		, CreateUser NVARCHAR(128)
		, CONSTRAINT pkc_$(NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName
		  PRIMARY KEY (Id, ServerName)
		, CONSTRAINT fk_$(NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
		  FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );
GO
IF OBJECT_ID('$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)
    ( Id UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL 
    , ConversationHandle UNIQUEIDENTIFIER NOT NULL
    , ConversationGroupId UNIQUEIDENTIFIER NOT NULL
    , Message IMAGE NOT NULL
    , Signature VARBINARY(8000) NOT NULL
    , MAC VARBINARY(128) NOT NULL
    , Action VARCHAR(30)
    , Status VARCHAR(30)
    , ErrorData VARBINARY(8000) SPARSE NULL
    , CreateUTCDT DATETIME
	  , CreateUser NVARCHAR(128) NOT NULL
    , CONSTRAINT pkc_$(NOTIFICATION_ACTIVITY_TABLE)__Id__ServerName
      PRIMARY KEY (Id, ServerName ) 
    , CONSTRAINT fk_$(NOTIFICATION_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
      FOREIGN KEY ( Id, ServerName ) 
      REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );   
GO
IF OBJECT_ID('$(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(OFFSITE_ACTIVITY_TABLE)
    ( Id UNIQUEIDENTIFIER NOT NULL
    , CaptureInstance NVARCHAR(128) NOT NULL
    , ServerName NVARCHAR(128) NOT NULL 
    , MinLsn BINARY(10) NOT NULL
    , MaxLsn BINARY(10) NOT NULL
    , [RowCount] INT NULL
    , MAC VARBINARY(128) NOT NULL
    , Action VARCHAR(30)
    , Status VARCHAR(30)
    , ErrorData VARBINARY(8000) SPARSE NULL
    , CreateUTCDT DATETIME
	  , CreateUser NVARCHAR(128) NOT NULL
    , CONSTRAINT pkc_$(OFFSITE_ACTIVITY_TABLE)__Id__CaptureInstance_ServerName
      PRIMARY KEY (Id, CaptureInstance, ServerName ) 
    , CONSTRAINT fk_$(OFFSITE_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
      FOREIGN KEY ( Id, ServerName ) 
      REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );   
GO
IF OBJECT_ID('$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)') IS NULL
  CREATE TABLE $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
    ( Id UNIQUEIDENTIFIER NOT NULL
    , ServerName NVARCHAR(128) NOT NULL 
    , ReportProcedure NVARCHAR(128) NOT NULL
    , Duration_ms INT NULL 
    , RowsReturned INT NULL 
    , MAC VARBINARY(128) NOT NULL
	  , Status VARCHAR (30) NOT NULL
	  , ErrorData VARBINARY(8000) SPARSE NULL
	  , CreateUTCDT DATETIME NOT NULL
	  , CreateUser NVARCHAR(128) NOT NULL
	  , CONSTRAINT pkc_$(REPORT_ACTIVITY_TABLE)__Id__ServerName
		  PRIMARY KEY (Id, ServerName)
    , CONSTRAINT fk_$(REPORT_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
      FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );
GO

