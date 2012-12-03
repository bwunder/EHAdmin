-- CTRL+SHFT+M to replace tokens
:on error exit                                                                 
--#:setvar HUB_SERVER_NAME                  "."                                   
-- in live environments use "WITH EXECUTE AS CALLER, ENCRYPTION" 
--#:setvar WITH_OPTIONS               "WITH EXECUTE AS CALLER, ENCRYPTION"        
--hub data store
:setvar HUB_DATASOURCE                   "Hub"                                 
:setvar HUB_LINKED_SERVER_NAME           "Hub"                                 

--#:setvar HUB_DATABASE                     "ehHub"                               

--spoke data store
--#:setvar SPOKE_DATABASE                   "ehdb"                                
--- export file extensions (file will not have extension if (.) is omitted)                                             
:setvar MASTER_KEY_BACKUP_EXT            ".keybak"                             
:setvar PRIVATE_KEY_BACKUP_EXT           ".prvbak"                             
:setvar PUBLIC_KEY_BACKUP_EXT            ".cerbak"                             
-- this value times 100 is used as the floor for 100 messages from sys.messages 
:setvar MESSAGE_OFFSET                   "21474836"                            
:setvar MIN_PHRASE_LENGTH                "21"                                  
-- for run-time schema validation - values are hard coded into Book & 
-- OpenSession stored procedures the SpokeVerifyDelta.sql
:setvar OBJECT_COUNT                     "58"                                  
:setvar DELTA                            "10"                                  
-- number active traces allowed (if default trace enabled set to 1)
:setvar MAX_TRACE_COUNT                  "1"                                   
--  0 to use generated filename literal or 1 to use hash of that value 
-- (namebucket column) for the file name in file system 
:setvar USE_HASH_FOR_FILENAME            "1"                                   
-- prefix for event notifications
:setvar EVENT_NOTIFICATION               "DDLChanges"                          
-- time to wait between data change pushes to hub (for broker dialog timer)
:setvar TIMER_TIMEOUT                    "120"                                 
-- audit to "SECURITY" log more secure but restricted access
:setvar SQLAUDIT_TO                      "APPLICATION"                         

-- user is schema owner at hub with read access at spokes, for SQLAzure this must be the admin user  
--#:setvar HUB_ADMIN                        "HubAdmin"               -- "<[HUB_ADMIN],SYSNAME,HubAdmin>"                                
---- unprivledged hub user for connection testing when creating ODBC DSN with ODBCAD32.exe
--#:setvar HUB_ODBC_AGENT                   "HubAgent"               -- "<[HUB_ODBC_AGENT],SYSNAME,HubAgent>"                           
---- user is schema owner at spoke with read access at hub
--#:setvar SPOKE_ADMIN                      "SpokeAdmin"             -- "<[SPOKE_ADMIN],SYSNAME,SpokeAdmin>"                            
---- activation EXECUTE AS user - schema owner at spoke with read and insert permissions at hub
--#:setvar SPOKE_BROKER                     "SpokeBroker"            -- "<[SPOKE_BROKER],SYSNAME,SpokeBroker>"                          

-- roles
--:setvar HUB_ADMIN_ROLE                   "HubAdministrators"      -- "<[HUB_ADMIN_ROLE],SYSNAME,HubAdministrators>"                  
--:setvar SPOKE_ADMIN_ROLE                 "SpokeAdministrators"    -- "<[SPOKE_ADMIN_ROLE],SYSNAME,SpokeAdministrators>"              
:setvar SESSION_SYMMETRIC_KEY            "#SessionSymmetricKey"   -- "<[SESSION_SYMMETRIC_KEY],SYSNAME,#SessionSymmetricKey>"        
:setvar SESSION_KEY_SOURCE               "SessionKeySource"       -- "<[SESSION_KEY_SOURCE],NVARCHAR,SessionKeySource>"              
:setvar SESSION_KEY_IDENTITY             "SessionKeyIdentity"     -- "<[SESSION_KEY_IDENTITY],NVARCHAR,SessionKeyIdentity>"          
:setvar SESSION_KEY_ENCRYPTION_PHRASE    "NOT checked 4 hardness" -- "<[SESSION_KEY_ENCRYPTION_PHRASE],PASSPHRASE,NOT checked 4 hardness>"
-- master database encryption hierarchy (hierarchy for SPOKE_DATEBASE TDE certificate)  
--:setvar TDE_CERTIFICATE                  "TDECertificate"         -- "<[TDE_CERTIFICATE] - for EHDB TDE,SYSNAME,TDECertificate>"     
:setvar TDE_CERTIFICATE_ALGORITHM        "AES_256"                -- "<[TDE_CERTIFICATE_ALGORITHM],SYSNAME,AES_256>"                 
-- EHDB database encryption hierarchy
-- authenticity cert protects man-in-the-middle and primary storage vectors, e.g. TVPs, passed values 
-- for inter-procedure authentication - value persisted as MAC column of affected activity log for non-repudiation  
:setvar AUTHENTICITY_CERTIFICATE         "AuthenticityCertificate"-- "<[AUTHENTICITY_CERTIFICATE],SYSNAME,AuthenticityCertificate>   
--  
:setvar EVENT_CERTIFICATE                "EventCertificate"       -- "<[EVENT_CERTIFICATE],SYSNAME,EventCertificate>                 
-- BACKUP_ACTIVITY.Names BACKUP_ACTIVITY.Path cell encryption
--:setvar FILE_CERTIFICATE                 "FileCertificate"        -- "<[FILE_CERTIFICATE],SYSNAME,FileCertificate>                   
:setvar FILE_SYMMETRIC_KEY               "FileKey"                -- "<[FILE_SYMMETRIC_KEY],SYSNAME,FileKey>"                        
:setvar FILE_KEY_ENCRYPTION_ALGORITHM    "AES_256"                -- "<[FILE_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"             
-- NameValues.Names cell encryption
:setvar NAME_CERTIFICATE                 "NameCertificate"        -- "<[OBJECT_CERTIFICATE],SYSNAME,NameCertificate>                 
:setvar NAME_SYMMETRIC_KEY               "NameKey"                -- "<[NAME_SYMMETRIC_KEY],SYSNAME,ValueKey>"                       
:setvar NAME_KEY_ENCRYPTION_ALGORITHM    "AES_256"                -- "<[NAME_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"             
-- SCHEMA_NAME schema signing 
:setvar OBJECT_CERTIFICATE               "ObjectCertificate"      -- "<[OBJECT_CERTIFICATE],SYSNAME,ObjectCertificate>               
-- spoke NameValues.Value cell encryption
:setvar VALUE_CERTIFICATE                "ValueCertificate"       -- "<[VALUE_CERTIFICATE],SYSNAME,ValueCertificate>"                
:setvar VALUE_SYMMETRIC_KEY              "ValueKey"               -- "<[VALUE_SYMMETRIC_KEY],SYSNAME,ValueKey>"                      
:setvar VALUE_KEY_ENCRYPTION_ALGORITHM   "AES_256"                -- "<[VALUE_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"            

:setvar HASHBYTES_ALGORITHM              "SHA2_512"               -- "<[HASHBYTES_ALGORITHM],SYSNAME,SHA2_512>"                      
-- schema
--:setvar EHA_SCHEMA                       "eha"                    -- "<[EHA_SCHEMA],SYSNAME,eha>"                                    
-- tables
:setvar BOOKINGS_TABLE                   "Bookings"               -- "<[BOOKINGS_TABLE],SYSNAME,Bookings>"                           
:setvar BACKUPS_TABLE                    "Backups"                -- "<[BACKUPS_TABLE],SYSNAME,Backups>"                             
:setvar BACKUP_ACTIVITY_TABLE            "BackupActivity"         -- "<[BACKUP_ACTIVITY_TABLE],SYSNAME,BackupActivity>"              
-- this one created on hub only - all spokes see the synonym  
:setvar HUB_ACTIVITY_TABLE               "HubActivity"            -- "<[HUB_ACTIVITY_TABLE],SYSNAME,HubActivity>"                    
:setvar NAMEVALUES_TABLE                 "NameValues"             -- "<[NAMEVALUES_TABLE],SYSNAME,NameValues>"                       
:setvar NAMEVALUE_ACTIVITY_TABLE         "NameValueActivity"      -- "<[NAMEVALUE_ACTIVITY_TABLE],SYSNAME,NameValueActivity>"        
:setvar NOTIFICATION_ACTIVITY_TABLE      "NotificationActivity"   -- "<[NOTIFICATION_ACTIVITY_TABLE],SYSNAME,NotificationActivity>"  
:setvar SPOKE_ACTIVITY_TABLE             "SpokeActivity"          -- "<[SPOKE_ACTIVITY_TABLE],SYSNAME,SpokeActivity>"                
:setvar REPORT_ACTIVITY_TABLE            "ReportActivity"         -- "<[REPORT_ACTIVITY_TABLE],SYSNAME,ReportActivity>"              
-- filetable  
:setvar FILESTREAM_FILEGROUP             "FilestreamFileGroup"    -- "<[FILESTREAM_FILEGROUP],SYSNAME,FilestreamFileGroup>"          
:setvar FILESTREAM_FILE                  "FilestreamFile"         -- "<[FILESTREAM_FILE],SYSNAME,FilestreamFile>"                    
:setvar FILETABLE_DIRECTORY              "FiletableDirectory"     -- "<[FILETABLE_DIRECTORY],SYSNAME,FiletableDirectory>"            
:setvar RESTORES_FILETABLE               "Restores"               -- "<[RESTORES_FILETABLE],SYSNAME,Restores>"                       
-- synonyms
:setvar BOOKINGS_SYNONYM                 "zBookings"              -- "<[BOOKINGS_SYNONYM],SYSNAME,zBookings>"                        
:setvar BACKUPS_SYNONYM                  "zBackups"               -- "<[BACKUPS_SYNONYM],SYSNAME,zBackups>"                          
:setvar BACKUP_ACTIVITY_SYNONYM          "zBackupActivity"        -- "<[BACKUP_ACTIVITY_SYNONYM],SYSNAME,zBackupActivity>"           
:setvar HUB_ACTIVITY_SYNONYM             "zHubActivity"           -- "<[HUB_ACTIVITY_SYNONYM],SYSNAME,zHubActivity>"                 
:setvar NAMEVALUES_SYNONYM               "zNameValues"            -- "<[NAMEVALUES_SYNONYM],SYSNAME,zNameValues>"                    
:setvar NAMEVALUE_ACTIVITY_SYNONYM       "zNameValueActivity"     -- "<[NAMEVALUE_ACTIVITY_SYNONYM],SYSNAME,zNameValueActivity>"     
:setvar NOTIFICATION_ACTIVITY_SYNONYM    "zNotificationActivity"  -- "<[NOTIFICATION_ACTIVITY_SYNONYM],SYSNAME,zNotificationActivity>"
:setvar SPOKE_ACTIVITY_SYNONYM           "zSpokeActivity"         -- "<[SPOKE_ACTIVITY_SYNONYM],SYSNAME,zSpokeActivity>"             
:setvar REPORT_ACTIVITY_SYNONYM          "zReportActivity"        -- "<[REPORT_ACTIVITY_SYNONYM],SYSNAME,zReportActivity>"           
-- possible division of responsibility artifact 
-- audit cert phrase assignment - isolate for division of responsibility 
:setvar AUDIT_CERTIFICATE                "AuditCertificate"       -- "<[AUDIT_CERTIFICATE],SYSNAME,AuditCertificate>"                
:setvar AUDIT_SYMMETRIC_KEY              "AuditKey"               -- "<[AUDIT_SYMMETRIC_KEY],SYSNAME,AuditKey>"                      
:setvar AUDIT_KEY_ENCRYPTION_ALGORITHM   "AES_256"                -- "<[AUDIT_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"            
-- shared symmetric key - with ERROR_KEY_ENCRYPTION_PHRASE is portable
:setvar ERROR_SYMMETRIC_KEY              "ErrorKey"               -- "<[ERROR_SYMMETRIC_KEY],SYSNAME,ErrorKey>"                                     
:setvar ERROR_KEY_ENCRYPTION_ALGORITHM   "AES_256"                -- "<[ERROR_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"                           
:setvar ERROR_KEY_SOURCE                 "i$Db8d b vf989sb d&ubsG"-- "<[ERROR_KEY_SOURCE_PHRASE],PASSPHRASE*,i$Db8d b vf989sb d&ubsG>"              
:setvar ERROR_KEY_IDENTITY               "t {bleS*&(d84vr4 67vfes"-- "<[ERROR_KEY_IDENTITY],PASSPHRASE*,t {bleS*&(d84vr4 67vfes>"                   
GO
