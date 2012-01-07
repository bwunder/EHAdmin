-- install/reinstall the stored procedures, functions and triggers removing ENCRYPTION from the $(WITH_OPTIONS) sqlcmd var
-- copy the OBJECT_CERTIFICATE and OBJECT_CERTIFICATE_ENCRYPTION_PHRASE values from the installer script to this script
-- script the proc from SSMS to the clipboard and paste it between the OBJECT_CERTIFICATE sqlcmd parms and the ADD SIGNATURE
-- if the script is taken from the install script instead of off the instance, other sqlcmd parms referenced must also be copied here
:setvar OBJECT_CERTIFICATE                     "ObjectCertificate"      -- "<[OBJECT_CERTIFICATE],SYSNAME,ObjectCertificate>                              
:setvar OBJECT_CERTIFICATE_ENCRYPTION_PHRASE   "Lu&6Gf%3Fe9 ROIT@wc?f"  -- "<[OBJECT_CERTIFICATE_ENCRYPTION_PHRASE],PASSPHRASE*,Lu&6Gf%3Fe9 ROIT@wc?f>"   
GO


GO
ADD SIGNATURE TO eha.SendOffsiteCDC
BY CERTIFICATE $(OBJECT_CERTIFICATE)
WITH PASSWORD = '$(OBJECT_CERTIFICATE_ENCRYPTION_PHRASE)';
GO

