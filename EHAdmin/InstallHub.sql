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
-- used only for SQL Azure - This should be THE SQL Azure administrator login 
:setvar SQLAZURE_INSTANCE_NAME             "vucjhke38b.database.windows.net"
:setvar SQLAZURE_SYSADMIN                  "bwunder"                                         
:setvar SQLAZURE_SYSADMIN_PASSWORD         "not4Birds"                                                                       
-- principals 
:setvar HUB_ADMIN                          "HubAdmin"              -- "<[HUB_ADMIN],SYSNAME,HubAdmin>"                       
:setvar HUB_ADMIN_PASSWORD                 "si*%tPW#4RfHgd"        -- "<[HUB_ADMIN_PASSWORD],PASSPHRASE,si*%tFE#4RfHgd>"     
:setvar SPOKE_ADMIN                        "SpokeAdmin"            -- "<[SPOKE_ADMIN],SYSNAME,SpokeAdmin>"                   
:setvar SPOKE_ADMIN_PASSWORD               "sj*%tFE#4RfHgf"        -- "<[SPOKE_ADMIN_PASSWORD],PASSPHRASE,sj*%tFE#4RfHgf>"   
:setvar SPOKE_BROKER                       "SpokeBroker"           -- "<[SPOKE_BROKER],SYSNAME,SpokeBroker>"                 
:setvar SPOKE_BROKER_PASSWORD              "sk*%tFE#4RfHge"        -- "<[SPOKE_BROKER_PASSWORD],PASSPHRASE,sk*%tFE#4RfHge>"  

-- user is available for testing spoke ODBC DSNs during config - has no role membership or access 
-- can be given out for testing of ODBC DSN and then changed/disabled/dropped at any time
-- it  
:setvar HUB_ODBC_AGENT                     "HubAgent"              -- "<[HUB_ODBC_AGENT],SYSNAME,HubAgent>"                  
:setvar HUB_ODBC_AGENT_PASSWORD            "VerifyDSN"             -- "<[HUB_ODBC_AGENT_PASSWORD],PASSPHRASE,VerifyDSN>"     
--
:setvar MESSAGE_OFFSET                     "21474836"              -- "<[MESSAGE_OFFSET],INT,21474836>"                      
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
-------------------------------------------------------------------------------
-- uninstall  -- NOT FOR SQL AZURE!
-------------------------------------------------------------------------------
--BEGIN TRY
--  USE master;
--  IF DB_ID('$(HUB_DATABASE)') IS NOT NULL
--    EXEC sp_executesql 
--        N'USE $(HUB_DATABASE);
--          ALTER DATABASE $(HUB_DATABASE) SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
--          USE master; 
--          DROP DATABASE $(HUB_DATABASE)';     
--  IF ( SELECT value_in_use FROM sys.configurations 
--        WHERE name = 'contained database authentication' ) = 1
--    BEGIN
--      EXEC sp_configure 'contained database authentication', 0;
--      RECONFIGURE;
--      RAISERROR('RECONFIGURE complete.',0,0);
--    END
--  IF SUSER_SID( '$(SPOKE_ADMIN)' ) IS NOT NULL
--    DROP LOGIN $(SPOKE_ADMIN);
--  IF SUSER_SID( '$(SPOKE_BROKER)' ) IS NOT NULL
--    DROP LOGIN $(SPOKE_BROKER);
--  IF SUSER_SID( '$(HUB_ADMIN)' ) IS NOT NULL
--    DROP LOGIN $(HUB_ADMIN);
--  IF SUSER_SID( '$(HUB_ODBC_AGENT)' ) IS NOT NULL
--    DROP LOGIN $(HUB_ODBC_AGENT)
--END TRY
--BEGIN CATCH
--  THROW;
--END CATCH  
--GO
-------------------------------------------------------------------------------
-- uninstall  -- SQL AZURE
-------------------------------------------------------------------------------
--IF USER_ID('$(SPOKE_ADMIN)') IS NOT NULL
--  DROP USER $(SPOKE_ADMIN);
--IF USER_ID('$(SPOKE_BROKER)') IS NOT NULL
--  DROP USER $(SPOKE_BROKER);
--IF USER_ID('$(HUB_ADMIN)') IS NOT NULL
--  DROP USER $(HUB_ADMIN);
--IF USER_ID('$(HUB_ODBC_AGENT)') IS NOT NULL
--  DROP USER $(HUB_ODBC_AGENT);
--GO
--:on error ignore
--GO
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -dmaster -Q"DROP LOGIN $(HUB_ADMIN)"  
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -dmaster -Q"DROP LOGIN $(HUB_ODBC_AGENT)"  
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -dmaster -Q"DROP LOGIN $(SPOKE_ADMIN)"  
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -dmaster -Q"DROP LOGIN $(SPOKE_BROKER)"  
--GO
--:on error exit
--GO
--BEGIN TRY
--  IF USER_ID('$(HUB_ADMIN_ROLE)') IS NOT NULL
--    DROP ROLE $(HUB_ADMIN_ROLE);
--  IF USER_ID('$(SPOKE_ADMIN_ROLE)') IS NOT NULL
--    DROP ROLE $(SPOKE_ADMIN_ROLE);
--  IF USER_ID('$(SPOKE_BROKER_ROLE)') IS NOT NULL
--    DROP ROLE $(SPOKE_BROKER_ROLE);
--  IF OBJECT_ID('$(EHA_SCHEMA).HubActivity') IS NOT NULL
--    DROP TABLE $(EHA_SCHEMA).HubActivity;
--  IF OBJECT_ID('$(EHA_SCHEMA).NotificationActivity') IS NOT NULL
--    DROP TABLE $(EHA_SCHEMA).NotificationActivity; 
--  IF OBJECT_ID('$(EHA_SCHEMA).ReportActivity') IS NOT NULL
--    DROP TABLE $(EHA_SCHEMA).ReportActivity;
--  IF OBJECT_ID('$(EHA_SCHEMA).SpokeActivity') IS NOT NULL
--    DROP TABLE $(EHA_SCHEMA).SpokeActivity; 
--  IF OBJECT_ID('$(EHA_SCHEMA).NameValues') IS NOT NULL
--    DROP TABLE $(EHA_SCHEMA).NameValues;
--  IF OBJECT_ID('$(EHA_SCHEMA).NameValueActivity') IS NOT NULL
--    DROP TABLE $(EHA_SCHEMA).NameValueActivity;
--  IF OBJECT_ID('$(EHA_SCHEMA).Backups') IS NOT NULL
--    DROP TABLE $(EHA_SCHEMA).Backups;
--  IF OBJECT_ID('$(EHA_SCHEMA).BackupActivity') IS NOT NULL
--    DROP TABLE $(EHA_SCHEMA).BackupActivity;
--  IF OBJECT_ID('$(EHA_SCHEMA).Bookings') IS NOT NULL
--    DROP TABLE $(EHA_SCHEMA).Bookings;
--  IF SCHEMA_ID('$(EHA_SCHEMA)') IS NOT NULL
--    DROP SCHEMA $(EHA_SCHEMA);
--END TRY
--BEGIN CATCH
--  THROW;
--END CATCH  
--GO
-------------------------------------------------------------------------------
---- current contents of hub by spoke
-------------------------------------------------------------------------------
USE $(HUB_DATABASE);
SELECT '$(EHA_SCHEMA).$(BOOKINGS_TABLE)' AS [Table]
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
--SELECT '$(EHA_SCHEMA).$(BOOKINGS_TABLE)' AS [Table], ServerName
--     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
--GROUP BY ServerName;
SELECT '$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)' AS [Table]
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE);
SELECT '$(EHA_SCHEMA).$(NAMEVALUES_TABLE)' AS [Table]
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(NAMEVALUES_TABLE);
SELECT '$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)' AS [Table]
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE);
SELECT '$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)' AS [Table]
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE);
SELECT '$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)' AS [Table]
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE);
SELECT '$(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)' AS [Table]
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE);
SELECT '$(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE)' AS [Table]
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE);

-- If SQL Azure we expect to already be in the database to use
GO
BEGIN TRY
  IF SERVERPROPERTY('EngineEdition') <> 5 -- SQL Azure
    BEGIN
      IF SERVERPROPERTY('IsLocalDB') = 1
        RAISERROR('Hub cannot be created on LocalDB. LocalDB cannot be opened by a linked server.', 16, 1); 
      IF EXISTS ( SELECT * FROM sys.configurations 
                  WHERE name = 'contained database authentication' )
        BEGIN
          EXEC sp_configure 'contained database authentication', 1;
          EXEC sp_executesql N'RECONFIGURE;';
          RAISERROR('RECONFIGURE complete...',0,0);
        END
      DECLARE @script NVARCHAR(256) = 
          CASE WHEN PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128) ), 4) < 11
               THEN N'CREATE DATABASE $(HUB_DATABASE);
                      USE $(HUB_DATABASE);
                      EXEC sp_changedbowner ''' + SUSER_SNAME(0x1) + ''''
               ELSE N'CREATE DATABASE $(HUB_DATABASE) CONTAINMENT = PARTIAL;
                      ALTER AUTHORIZATION ON DATABASE::$(HUB_DATABASE) TO ' + SUSER_SNAME(0x1)
               END          
      EXEC sp_executesql @script
    END
END TRY
BEGIN CATCH
  THROW;
END CATCH
GO
USE $(HUB_DATABASE);
---- in SQL Azure - OK to comment everything from here up to the setvars
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -dmaster -Q"CREATE LOGIN $(HUB_ADMIN) WITH PASSWORD = '$(HUB_ADMIN_PASSWORD)'"  
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -d($HUB_DATABASE) -Q"CREATE USER $(HUB_ADMIN) FROM LOGIN $(HUB_ADMIN)"
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -dmaster -Q'CREATE LOGIN $(HUB_ODBC_AGENT) WITH PASSWORD = '$(HUB_ODBC_AGENT_PASSWORD)'"  
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -d($HUB_DATABASE) -Q"CREATE USER $(HUB_ODBC_AGENT) FROM LOGIN $(HUB_ODBC_AGENT)"  
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -dmaster -Q"CREATE LOGIN $(SPOKE_ADMIN) WITH PASSWORD = '$(SPOKE_ADMIN_PASSWORD)'"  
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -d($HUB_DATABASE) -Q"CREATE USER $(SPOKE_ADMIN) FROM LOGIN $(SPOKE_ADMIN)"  
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -dmaster -Q"CREATE LOGIN $(SPOKE_BROKER) WITH PASSWORD = '$(SPOKE_BROKER_PASSWORD)'"  
--!!sqlcmd -S$(SQLAZURE_INSTANCE_NAME) -U$(SQLAZURE_SYSADMIN)@$(SQLAZURE_INSTANCE_NAME) -P$(SQLAZURE_SYSADMIN_PASSWORD) -d($HUB_DATABASE) -Q"CREATE USER $(SPOKE_BROKER) FROM LOGIN $(SPOKE_BROKER);"
GO
IF DB_NAME() <> '$(HUB_DATABASE)' 
  RAISERROR ('Whoaa! This is NOT the $(HUB_DATABASE) database!', 16, 1); 
GO
-------------------------------------------------------------------------------
-- users
-------------------------------------------------------------------------------
-- the user running this script also has administrative authority!
BEGIN TRY
  IF SERVERPROPERTY('EngineEdition') <> 5 
    BEGIN
      IF ( SELECT value_in_use FROM sys.configurations 
           WHERE name = 'contained database authentication' ) = 1
        BEGIN
          IF USER_ID ('$(HUB_ADMIN)') IS NULL
            EXEC sp_executesql N'CREATE USER $(HUB_ADMIN) WITH PASSWORD = ''$(HUB_ADMIN_PASSWORD)''';  

          IF USER_ID ('$(HUB_ODBC_AGENT)') IS NULL
            EXEC sp_executesql N'CREATE USER $(HUB_ODBC_AGENT) WITH PASSWORD = ''$(HUB_ODBC_AGENT_PASSWORD)''';  

          IF USER_ID ('$(SPOKE_ADMIN)') IS NULL
            EXEC sp_executesql N'CREATE USER $(SPOKE_ADMIN) WITH PASSWORD = ''$(SPOKE_ADMIN_PASSWORD)''';  

          IF USER_ID ('$(SPOKE_BROKER)') IS NULL
            EXEC sp_executesql N'CREATE USER $(SPOKE_BROKER) WITH PASSWORD = ''$(SPOKE_BROKER_PASSWORD)''';  
        END
      ELSE
        BEGIN
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
        END
    END
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
  IF NOT EXISTS ( SELECT * FROM sys.database_principals 
                  WHERE name = N'$(SPOKE_BROKER_ROLE)' 
                  AND type = 'R')
    BEGIN
      CREATE ROLE [$(SPOKE_BROKER_ROLE)];
      GRANT SELECT, INSERT ON SCHEMA::$(EHA_SCHEMA) TO $(SPOKE_BROKER_ROLE);
      SET @MembersDDL = CASE WHEN PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128) ), 4) < 11
                             OR SERVERPROPERTY('EngineEdition') = 5 
                             THEN 'EXEC sp_addrolemember ''$(SPOKE_BROKER_ROLE)'', ''$(SPOKE_BROKER)'';'
                             ELSE 'ALTER ROLE [$(SPOKE_BROKER_ROLE)] ADD MEMBER $(SPOKE_BROKER);'
                             END 
      EXEC sp_executesql @MembersDDL;
    END
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
    ON $(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE) ( BookingId, ServerName ) ;   

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