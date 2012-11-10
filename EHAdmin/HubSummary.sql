SET NOCOUNT ON;
:r C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\Variables.sql             
GO 
:Connect $(HUB_SERVER_NAME)                                                    
GO
-----------------------------------------------------------------------------
-- current rowcounts at hub by spoke
-------------------------------------------------------------------------------
USE $(HUB_DATABASE);
SELECT '$(EHA_SCHEMA).$(BOOKINGS_TABLE)' AS [Table], ServerName
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(BOOKINGS_TABLE)
GROUP BY ServerName;
SELECT '$(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)' AS [Table], ServerName
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(BACKUP_ACTIVITY_TABLE)
GROUP BY ServerName;
SELECT '$(EHA_SCHEMA).$(NAMEVALUES_TABLE)' AS [Table], ServerName
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(NAMEVALUES_TABLE)
GROUP BY ServerName;
SELECT '$(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)' AS [Table], ServerName
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(NAMEVALUE_ACTIVITY_TABLE)
GROUP BY ServerName;
SELECT '$(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)' AS [Table], ServerName
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(NOTIFICATION_ACTIVITY_TABLE)
GROUP BY ServerName;
SELECT '$(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)' AS [Table], ServerName
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(REPORT_ACTIVITY_TABLE)
GROUP BY ServerName;
SELECT '$(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)' AS [Table], ServerName
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(SPOKE_ACTIVITY_TABLE)
GROUP BY ServerName;
SELECT '$(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE)' AS [Table], ServerName
     , COUNT(*) AS [rows] FROM $(EHA_SCHEMA).$(HUB_ACTIVITY_TABLE)
GROUP BY ServerName;
GO
