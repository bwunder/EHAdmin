SET NOCOUNT ON;
:r C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\Variables.sql -- <path to Variables.sql,NVARCHAR,C:\Users\bwunder\Documents\GitHub\EHAdmin\EHAdmin\>Variables.sql             
GO 
:Connect . --<SQL Server Name,SYSNAME,.>                                                                            
GO
USE $(SPOKE_DATABASE)
------------------------------------------------------------------------------------------------------
-- verify OBJECT_COUNT and DELTA variables
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
