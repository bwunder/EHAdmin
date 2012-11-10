
SET NOCOUNT ON;
:setvar HUB_ADMIN_PASSWORD                     "si*%tPW#4RfHgd"                
:r C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\Variables.sql  
GO
-------------------------------------------------------------------------------
-- Encryption Hierarchy Administration Hub  
-- central storage of the already secured spoke schema(s)
-------------------------------------------------------------------------------
-- Pre-requisites 
--  1. SQLAzure 
-- Notes:
--  1. No local native T-SQL cryptographic methods or objects used at hub   
--  2. SQL Authentication via linked server (sql encrypts link stored password)  
--  3. To configure ODBC DSN - run|odbcad32.exe 
-- blogs.msdn.com/b/sqlcat/archive/2011/03/08/linked-servers-to-sql-azure.aspx
--  4. Use this script in SQLClue or SSMS/SSDT using SQLCMD mode.
--     tested using SQLClient only not OLE-DB protocol 
--  5. Replace template tokens in .tql files with your values and save as .sql
--     files in same folder before running this script. Once the hub is created
--     the files in the setup directory can be marked read-only for use by all
--     spokes subsequently connected to hub 
--  6. to protect secrets NEVER save THIS script once your secrets are entered 
--  7. User database is created if specified database does not exist by name
--     as a partially contained database if not SQL Azure
------------------------------------------------------------------------------
SET NOCOUNT ON;
GO
!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -dmaster -Q"CREATE LOGIN $(HUB_ADMIN) WITH PASSWORD = '$(HUB_ADMIN_PASSWORD)'"  
!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -d($HUB_DATABASE) -Q"CREATE USER $(HUB_ADMIN) FROM LOGIN $(HUB_ADMIN)"
!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -dmaster -Q'CREATE LOGIN $(HUB_ODBC_AGENT) WITH PASSWORD = '$(HUB_ODBC_AGENT_PASSWORD)'"  
!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -d($HUB_DATABASE) -Q"CREATE USER $(HUB_ODBC_AGENT) FROM LOGIN $(HUB_ODBC_AGENT)"  
!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -dmaster -Q"CREATE LOGIN $(SPOKE_ADMIN) WITH PASSWORD = '$(SPOKE_ADMIN_PASSWORD)'"  
!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -d($HUB_DATABASE) -Q"CREATE USER $(SPOKE_ADMIN) FROM LOGIN $(SPOKE_ADMIN)"  
!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -dmaster -Q"CREATE LOGIN $(SPOKE_BROKER) WITH PASSWORD = '$(SPOKE_BROKER_PASSWORD)'"  
!!sqlcmd -S$(HUB_SERVER_NAME) -U$(HUB_ADMIN)@$(HUB_SERVER_NAME) -P$(HUB_ADMIN_PASSWORD) -d($HUB_DATABASE) -Q"CREATE USER $(SPOKE_BROKER) FROM LOGIN $(SPOKE_BROKER);"
GO
-------------------------------------------------------------------------------
-- users
-------------------------------------------------------------------------------
BEGIN TRY
  IF USER_ID ('$(HUB_ADMIN)') IS NULL
    EXEC sp_executesql N'CREATE LOGIN $(HUB_ADMIN) WITH PASSWORD = ''$(HUB_ADMIN_PASSWORD)''';  
    EXEC sp_executesql N'CREATE USER $(HUB_ADMIN) FROM LOGIN $(HUB_ADMIN)';  

  IF SUSER_SID ( '$(HUB_ODBC_AGENT)' ) IS NULL
    EXEC sp_executesql N'CREATE LOGIN $(HUB_ODBC_AGENT) WITH PASSWORD = ''$(HUB_ODBC_AGENT_PASSWORD)''';  
  IF USER_ID ('$(HUB_ODBC_AGENT)') IS NULL
    EXEC sp_executesql N'CREATE USER $(HUB_ODBC_AGENT) FROM LOGIN $(HUB_ODBC_AGENT)';  

  IF SUSER_SID ( '$(SPOKE_ADMIN)' ) IS NULL
    EXEC sp_executesql N'CREATE LOGIN $(SPOKE_ADMIN) WITH PASSWORD = ''$(SPOKE_ADMIN_PASSWORD)''';  
  IF USER_ID ('$(SPOKE_ADMIN)') IS NULL
    EXEC sp_executesql N'CREATE USER $(SPOKE_ADMIN) FROM LOGIN $(SPOKE_ADMIN)';  

  IF SUSER_SID ( '$(SPOKE_BROKER)' ) IS NULL
    EXEC sp_executesql N'CREATE LOGIN $(SPOKE_BROKER) WITH PASSWORD = ''$(SPOKE_BROKER_PASSWORD)'';';  
  IF USER_ID ('$(SPOKE_BROKER)') IS NULL
    EXEC sp_executesql N'CREATE USER $(SPOKE_BROKER) FROM LOGIN $(SPOKE_BROKER);';  
END TRY
BEGIN CATCH
  THROW;
END CATCH
GO
BEGIN TRY
  -- schema
  IF NOT EXISTS (SELECT * FROM sys.schemas 
                  WHERE name = N'$(EHA_SCHEMA)')
    EXEC sys.sp_executesql N'CREATE SCHEMA [$(EHA_SCHEMA)]';
  -------------------------------------------------------------------------------
  -- roles
  -------------------------------------------------------------------------------
  DECLARE @MembersDDL NVARCHAR(4000);    
  IF NOT EXISTS ( SELECT * FROM sys.database_principals 
                  WHERE name = N'$(HUB_ADMIN_ROLE)' 
                  AND type = 'R')
    BEGIN
      CREATE ROLE [$(HUB_ADMIN_ROLE)];
      GRANT CONTROL ON DATABASE::$(HUB_DATABASE) TO $(HUB_ADMIN_ROLE);
      SET @MembersDDL = CASE WHEN PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128) ), 4) < 11
                             OR SERVERPROPERTY('EngineEdition') = 5 
                             THEN 'EXEC sp_addrolemember ''$(HUB_ADMIN_ROLE)'', ''$(HUB_ADMIN)'';'
                             ELSE 'ALTER ROLE [$(HUB_ADMIN_ROLE)] ADD MEMBER $(HUB_ADMIN);'
                             END 
                      --+ 'CREATE USER [' + ORIGINAL_LOGIN() + '] FROM LOGIN [' + ORIGINAL_LOGIN() + '];'
                      --+ CASE WHEN PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128) ), 4) < 11
                      --       THEN 'EXEC sp_addrolemember ''$(HUB_ADMIN_ROLE)'', ''' + ORIGINAL_LOGIN() + ''';'
                      --       ELSE 'ALTER ROLE $(HUB_ADMIN_ROLE) ADD MEMBER [' + ORIGINAL_LOGIN() + '];'
                      --       END;
      EXEC sp_executesql @MembersDDL;
    END 
  GRANT SELECT, INSERT ON SCHEMA::$(EHA_SCHEMA) TO $(SPOKE_BROKER);
  IF NOT EXISTS ( SELECT * FROM sys.database_principals 
                  WHERE name = N'$(SPOKE_ADMIN_ROLE)' 
                  AND type = 'R')
    BEGIN
      CREATE ROLE [$(SPOKE_ADMIN_ROLE)]
      GRANT SELECT ON SCHEMA::$(EHA_SCHEMA) TO $(SPOKE_ADMIN_ROLE);
      SET @MembersDDL = CASE WHEN PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128) ), 4) < 11
                             OR SERVERPROPERTY('EngineEdition') = 5 
                             THEN 'EXEC sp_addrolemember ''$(SPOKE_ADMIN_ROLE)'', ''$(SPOKE_ADMIN)'';'
                             ELSE 'ALTER ROLE [$(SPOKE_ADMIN_ROLE)] ADD MEMBER $(SPOKE_ADMIN);'
                             END 
      EXEC sp_executesql @MembersDDL;
    END    
  -------------------------------------------------------------------------------
  -- tables
  -------------------------------------------------------------------------------
  IF OBJECT_ID('$(EHA_SCHEMA).$(BOOKINGS_TABLE)') IS NULL
    BEGIN
	    CREATE TABLE $(EHA_SCHEMA).$(BOOKINGS_TABLE) 
	      ( Id UNIQUEIDENTIFIER NOT NULL 
        , ServerName NVARCHAR (128) NOT NULL
	      , ProcId INT NULL
	      , ObjectName NVARCHAR (128) NULL
        , Parameters VARBINARY (8000) NOT NULL
        , KeyGuid NVARCHAR (36) NOT NULL
        , Status NVARCHAR (36) NOT NULL
        , ErrorData VARBINARY (8000) SPARSE NULL
        , CreateUTCDT DATETIME NOT NULL
	      , CreateUser NVARCHAR (128) NOT NULL
	      , CONSTRAINT pkc_$(BOOKINGS_TABLE)__Id__ServerName
	        PRIMARY KEY CLUSTERED (Id, ServerName) );
      CREATE NONCLUSTERED INDEX ixn_$(BOOKINGS_TABLE)__CreateUTCDT__ServerName
      ON $(EHA_SCHEMA).$(BOOKINGS_TABLE) (CreateUTCDT, ServerName);
    END

  IF OBJECT_ID('$(EHA_SCHEMA).$(BACKUPS_TABLE)') IS NULL
    CREATE TABLE $(EHA_SCHEMA).$(BACKUPS_TABLE) 
      ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR (128) NOT NULL 
      , Export VARBINARY (8000) NOT NULL
	    , CreateUTCDT DATETIME NOT NULL
	    , CreateUser NVARCHAR (128) NOT NULL
	    , CONSTRAINT pkc_$(BACKUPS_TABLE)__Id__ServerName
		    PRIMARY KEY (Id, ServerName)
      , CONSTRAINT fk_$(BACKUPS_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
        FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );

  IF OBJECT_ID('$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)') IS NULL
	  CREATE TABLE $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE) 
      ( Id UNIQUEIDENTIFIER NOT NULL 
      , ServerName NVARCHAR (128) NOT NULL 
      , DbName NVARCHAR (128) NOT NULL
      , Node NVARCHAR (256) NULL 
      , Level INT 
	    , NodeName NVARCHAR (128) NOT NULL
      , BackupName VARBINARY (8000) NOT NULL 
      , BackupNameBucket INT NOT NULL 
      , UseHash BIT NOT NULL          
      , BackupPath VARBINARY (8000) NOT NULL
      , BackupPhraseVersion SMALLINT NOT NULL
      , KeyPhraseVersion SMALLINT NULL
      , Colophon INT NOT NULL 
      , Edition SMALLINT NOT NULL        
      , MAC VARBINARY (128) NOT NULL
      , Action NVARCHAR (128) NOT NULL
      , Status NVARCHAR (36) NOT NULL
      , CipherType CHAR (2) NOT NULL
      , ErrorData VARBINARY (8000) SPARSE NULL
		  , CreateUTCDT DATETIME NOT NULL
		  , CreateUser NVARCHAR (128) NOT NULL
		  , CONSTRAINT pkc_$(BACKUP_ACTIVITY_TABLE)__Id__ServerName
		    PRIMARY KEY ( Id, ServerName )
	    , CONSTRAINT fk_$(BACKUP_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
	      FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );

  IF OBJECT_ID('$(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE)') IS NULL
    CREATE TABLE $(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE)
      ( Id UNIQUEIDENTIFIER NOT NULL
      , HubName NVARCHAR (128) NOT NULL
        CONSTRAINT dft_$(HUB_ACTIVITY_TABLE)__ServerName
        DEFAULT (@@SERVERNAME)
      , BookingId UNIQUEIDENTIFIER NULL
      , ServerName NVARCHAR (128) NULL 
      , Action NVARCHAR (128)
      , Status VARCHAR (30)
      , ErrorInfo XML SPARSE NULL
      , CreateUTCDT DATETIME
		    CONSTRAINT dft_$(HUB_ACTIVITY_TABLE)__CreateUTCDT
		    DEFAULT (SYSUTCDATETIME())
		  , CreateUser NVARCHAR (128) NOT NULL
		    CONSTRAINT dft_$(HUB_ACTIVITY_TABLE)__CreateUser
		    DEFAULT (ORIGINAL_LOGIN())  
      , CONSTRAINT pkc_$(HUB_ACTIVITY_TABLE)__Id__HubName
        PRIMARY KEY ( Id, HubName ) ); 

  IF NOT EXISTS (SELECT * FROM sys.indexes 
                 WHERE name = 'ixn_$(HUB_ACTIVITY_TABLE)__BookingId__ServerName' )
    CREATE INDEX ixn_$(HUB_ACTIVITY_TABLE)__BookingId__ServerName
    ON $(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE) ( BookingId, ServerName );   

  IF OBJECT_ID('$(EHA_SCHEMA).$(NAMEVALUES_TABLE)') IS NULL
    CREATE TABLE $(EHA_SCHEMA).$(NAMEVALUES_TABLE) 
	    ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR (128) NOT NULL
	    , NameBucket INT NOT NULL 
      , ValueBucket INT NOT NULL
	    , Version SMALLINT NOT NULL 
	    , Name VARBINARY (8000) NOT NULL  
	    , Value VARBINARY (8000) NOT NULL 
   	  , CreateUTCDT DATETIME NOT NULL
	    , CreateUser NVARCHAR (128) NOT NULL
	    , CONSTRAINT pkc_$(NAMEVALUES_TABLE)__Id__ServerName
	      PRIMARY KEY (Id, ServerName)
	    , CONSTRAINT fk_$(NAMEVALUES_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
	      FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );

  IF OBJECT_ID('$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)') IS NULL
	  CREATE TABLE $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE) 
		  ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR (128) NOT NULL
      , MAC VARBINARY (128) NOT NULL
		  , Action NVARCHAR (128) NOT NULL
		  , Status NVARCHAR (36) NOT NULL
		  , ErrorData VARBINARY (8000) SPARSE NULL 
		  , CreateUTCDT DATETIME NOT NULL
		  , CreateUser NVARCHAR (128)
		  , CONSTRAINT pkc_$(NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName
		    PRIMARY KEY (Id, ServerName)
		  , CONSTRAINT fk_$(NAMEVALUE_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
		    FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );

  IF OBJECT_ID('$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)') IS NULL
    CREATE TABLE $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)
      ( ID UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR (128) NOT NULL 
      , ConversationHandle UNIQUEIDENTIFIER NOT NULL
      , ConversationGroupId UNIQUEIDENTIFIER NOT NULL
      , ConversationSequenceNumber BIGINT NOT NULL
      , MessageTypeName NVARCHAR (256) NOT NULL
      , MessageBody VARBINARY(MAX) NOT NULL
      , HashIndex VARBINARY (8000) NOT NULL
      , Action NVARCHAR (128) NOT NULL
      , Status NVARCHAR (36) NOT NULL
      , ErrorData VARBINARY (8000) SPARSE NULL
      , CreateUTCDT DATETIME NOT NULL
	    , CreateUser NVARCHAR (128) NOT NULL
      , CONSTRAINT pkc_$(NOTIFICATION_ACTIVITY_TABLE)__ConversationHandle__ServerName
        PRIMARY KEY ( ConversationHandle, ServerName ) );   

  IF OBJECT_ID('$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)') IS NULL
    CREATE TABLE $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE) 
      ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR (128) NOT NULL 
      , Duration_ms INT NULL 
      , RowsReturned INT NULL 
      , MAC VARBINARY (128) NOT NULL
      , Action NVARCHAR (128) NOT NULL
	    , Status NVARCHAR (36) NOT NULL
	    , ErrorData VARBINARY (8000) SPARSE NULL
	    , CreateUTCDT DATETIME NOT NULL
	    , CreateUser NVARCHAR (128) NOT NULL
	    , CONSTRAINT pkc_$(REPORT_ACTIVITY_TABLE)__Id__ServerName
		    PRIMARY KEY (Id, ServerName)
      , CONSTRAINT fk_$(REPORT_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
        FOREIGN KEY ( Id, ServerName ) REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE)( Id, ServerName ) );

  IF OBJECT_ID('$(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)') IS NULL
    CREATE TABLE $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)
      ( Id UNIQUEIDENTIFIER NOT NULL
      , ServerName NVARCHAR (128) NOT NULL 
      , MAC VARBINARY (128) NOT NULL
      , Action NVARCHAR (128)
      , Status NVARCHAR (36)
      , ErrorData VARBINARY (8000) SPARSE NULL
      , CreateUTCDT DATETIME NOT NULL
	    , CreateUser NVARCHAR (128) NOT NULL
      , CONSTRAINT pkc_$(SPOKE_ACTIVITY_TABLE)__Id__ServerName
        PRIMARY KEY ( Id, ServerName ) 
      , CONSTRAINT fk_$(SPOKE_ACTIVITY_TABLE)__Id__ServerName__TO__$(BOOKINGS_TABLE)__Id__ServerName
        FOREIGN KEY ( Id, ServerName ) 
        REFERENCES $(EHA_SCHEMA).$(BOOKINGS_TABLE) ( Id, ServerName ) );   
--initialize the hub activity table
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
END TRY
BEGIN CATCH
  THROW;
END CATCH
GO