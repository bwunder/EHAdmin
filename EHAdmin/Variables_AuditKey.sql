-- audit cert phrase assignment - isolate for division of responsibility 
-- private phrase is hard coded into encrypted Book stored procedure only
:setvar AUDITOR_PRIVATE_PHRASE                 "Auditors Little Secret" -- "<[AUDITOR_PRIVATE_PHRASE],PASSPHRASE*,Auditors Little Secret>"       
-- encryption phrase is stored as privae value in NameValues using above private value
:setvar AUDIT_CERTIFICATE_ENCRYPTION_PHRASE    "Au&6Gf% 3Fe14CQAN@wcf?" -- "<[AUDIT_CERTIFICATE_ENCRYPTION_PHRASE],PASSPHRASE*,Au&6Gf% 3Fe14CQAN@wcf?>"  

:setvar AUDIT_CERTIFICATE                      "AuditCertificate"       -- "<[AUDIT_CERTIFICATE],SYSNAME,AuditCertificate>"                
:setvar AUDIT_SYMMETRIC_KEY                    "AuditKey"               -- "<[AUDIT_SYMMETRIC_KEY],SYSNAME,AuditKey>"                      
:setvar AUDIT_KEY_ENCRYPTION_ALGORITHM         "AES_256"                -- "<[AUDIT_KEY_ENCRYPTION_ALGORITHM],SYSNAME,AES_256>"            
