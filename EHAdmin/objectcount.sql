
:setvar OBJECT_COUNT                           "60"                    
:setvar TABLE_COUNT                            "8"                     
GO
SELECT COUNT(*)--CASE WHEN COUNT(*) = $(OBJECT_COUNT) - $(TABLE_COUNT) THEN 1 ELSE 0 END
          FROM sys.certificates c
          OUTER APPLY sys.fn_check_object_signatures ('certificate', c.thumbprint) s
          WHERE c.name = 'ObjectCertificate'--$(OBJECT_CERTIFICATE)'
          AND c.pvt_key_encryption_type = 'PW'
          AND OBJECT_SCHEMA_NAME (entity_id) = 'eha'--$(EHA_SCHEMA)'
          AND EXISTS (SELECT *              
                      FROM sys.database_role_members
                      WHERE role_principal_id = USER_ID( 'EHAdminRole' )--$(EHADMIN_ROLE)' )
                      AND SYSTEM_USER = ORIGINAL_LOGIN()
                      AND USER_NAME(member_principal_id) = ORIGINAL_LOGIN() )
          AND is_signed = 1 
          AND is_signature_valid = 1
          HAVING COUNT(*) = $(OBJECT_COUNT) - $(TABLE_COUNT)