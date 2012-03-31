:on error exit
SET NOCOUNT ON;
-- change the SAMPLE_SIZE here, run script 3x at 100,500,1000,5000,10000
:setvar SAMPLE_SIZE          100                                           

:setvar MAX_SAMPLE_SIZE      10000                                         
:setvar PASS_PHRASE         "2htFO6%3 vJ6yfut@J 587voy&4hj"                
:setvar SYMKEY_PHRASE       "3LKUYASoIwio(*& %SUG EWmvkljd"                
:setvar CERT_PHRASE         "4W?D flkfrh3p9h d f dfsg&^Rsverew"            
:setvar ASYMKEY_PHRASE      "5dU6 vJ6y fut@ voy& 4hjm"                     

:setvar CLEANUP             0                                              
GO
use tempdb
GO
IF $(CLEANUP) = 1
  BEGIN
    IF TYPE_ID('CIPHER') IS NOT NULL
      DROP TYPE CIPHER;
    IF OBJECT_ID('dbo.TestTimes') IS NOT NULL
      DROP TABLE dbo.TestTimes;
    IF OBJECT_ID('#sample') IS NOT NULL
      DROP TABLE #sample;
    IF OBJECT_ID('#sample2') IS NOT NULL
      DROP TABLE #sample2;
    IF OBJECT_ID('#sample3') IS NOT NULL
      DROP TABLE #sample3;
    IF OBJECT_ID('#sample4') IS NOT NULL
      DROP TABLE #sample4;
    IF CERT_ID('cert') IS NOT NULL
	  DROP CERTIFICATE cert
	IF ASYMKEY_ID('asymkeyRSA_1024') IS NOT NULL
	  DROP ASYMMETRIC KEY asymkeyRSA_1024  
	IF ASYMKEY_ID('asymkeyRSA_2048') IS NOT NULL
	  DROP ASYMMETRIC KEY asymkeyRSA_2048  
    IF key_ID('#symkeyDES') IS NOT NULL
      RAISERROR('Cleanup Complete. Disconnecting from the SQL Server to drop temp Symmetric Keys',20,1) WITH LOG 
  END
GO
IF TYPE_ID('CIPHER') IS NULL
  CREATE TYPE CIPHER AS TABLE
	  ( RowId INT PRIMARY KEY
      , ciphertext VARBINARY(8000) ); 

GO
IF OBJECT_ID('dbo.TestTimes') IS NULL
  CREATE TABLE dbo.TestTimes 
    ( Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY
	, Method NVARCHAR(64) NOT NULL
	  CHECK ( Method IN ( 'CRYPT_GEN_RANDOM'
	                    , 'ASYMMETRIC KEY'
					    , 'CERTIFICATE'
					    , 'SYMMETRIC KEY'
					    , 'Hash HASHBYTES'
					    , 'Hash PWDCOMPARE' ) )
	, Configurithm NVARCHAR(50) NOT NULL
	, Condition NVARCHAR(14) NOT NULL
	  CHECK ( Condition IN 
	             ( 'none'           -- no specified salt or authenticator
				 , '@RowId'         -- add RowId as symkey @authenticator
				 , '@RowGUID'       -- use RowGUID as symkey @authenticator 
				 , '@random'        -- add a 'random' value as @authenticator
                 , 'row-by-row'     -- add rows 1 at a time 
				 , '+Identity'      -- also create RowId at insert
				 , '+GUID'          -- also create Sequential RowGUID at insert
				 , '&RowId'         -- use RowId as salt 
				 , '&RowGUID'       -- use RowGUID as salt
				 , '&random'        -- add a random value as salt
				 , '&encrypted' ) ) -- use a static, securely stored value as salt
	  DEFAULT ('none') 		   
	, SampleSize BIGINT NOT NULL
    , TextBytes BIGINT NOT NULL 
    , CycleStartDT DATETIME NOT NULL
	, AddDT DATETIME NOT NULL
	, Encode_Duration AS ( DATEDIFF( ms, CycleStartDT, AddDT ) ) 
	, Encode_Time_Cost AS ( DATEDIFF( ms, CycleStartDT, AddDT ) * 1.0 / SampleSize ) 
    , CipherBytes BIGINT NOT NULL 
	, Encode_Storage_Cost AS ( CipherBytes / SampleSize ) 
	, UseDT DATETIME NOT NULL DEFAULT ( CURRENT_TIMESTAMP ) 
	, Use_Duration AS ( DATEDIFF( ms, AddDT, UseDT ) )
	, Decode_Time_Cost AS ( DATEDIFF( ms, AddDT, UseDT ) * 1.0 / SampleSize ) );  
GO
IF OBJECT_ID('#sample') IS NULL
  CREATE TABLE #sample ( RowId INT IDENTITY(1,1) CHECK ( RowId <= $(MAX_SAMPLE_SIZE) ) PRIMARY KEY
                       , ClearText NVARCHAR(58)  -- max for ASYM RSA_1024
                         DEFAULT ( CONVERT ( NVARCHAR(58), CRYPT_GEN_RANDOM(58), 2 ) ) 
                       , RecCreatedDT DATETIME NOT NULL);
GO
IF OBJECT_ID('#sample2') IS NULL
  CREATE TABLE #sample2 ( RowGUID UNIQUEIDENTIFIER ROWGUIDCOL PRIMARY KEY  
                          DEFAULT ( NEWSEQUENTIALID() ) 
                        , RowId INT UNIQUE
                        , ClearText NVARCHAR(58)
                          DEFAULT ( CONVERT ( NVARCHAR(58), CRYPT_GEN_RANDOM(58), 2 ) ) );
GO
IF OBJECT_ID('#sample3') IS NULL
  CREATE TABLE #sample3 ( Id INT IDENTITY(1,1) PRIMARY KEY
                        , RowId INT UNIQUE
                        , ClearText NVARCHAR(58)
                          DEFAULT ( CONVERT ( NVARCHAR(58), CRYPT_GEN_RANDOM(58), 2 ) ) );
GO
IF OBJECT_ID('#sample4') IS NULL
  CREATE TABLE #sample4 ( RowId INT PRIMARY KEY
                        , ClearText NVARCHAR(58)
                          DEFAULT ( CONVERT ( NVARCHAR(58), CRYPT_GEN_RANDOM(58), 2 ) ) );
GO
IF KEY_GUID('#symkeyDES') IS NULL
  CREATE SYMMETRIC KEY #symkeyDES
  WITH ALGORITHM = DES     
     , KEY_SOURCE = 'SYMKEY SOURCE'
     , IDENTITY_VALUE = 'symkeyDES'
  ENCRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
GO
IF KEY_GUID('#symkeyTRIPLE_DES') IS NULL
  CREATE SYMMETRIC KEY #symkeyTRIPLE_DES
  WITH ALGORITHM = TRIPLE_DES     
     , KEY_SOURCE = 'SYMKEY SOURCE'
     , IDENTITY_VALUE = 'symkeyTRIPLE_DES'
  ENCRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
GO
IF KEY_GUID('#symkeyTRIPLE_DES_3KEY') IS NULL
  CREATE SYMMETRIC KEY #symkeyTRIPLE_DES_3KEY
  WITH ALGORITHM = TRIPLE_DES_3KEY     
     , KEY_SOURCE = 'SYMKEY SOURCE'
     , IDENTITY_VALUE = 'symkeyTRIPLE_DES_3KEY'
  ENCRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
GO
IF KEY_GUID('#symkeyRC2') IS NULL
  CREATE SYMMETRIC KEY #symkeyRC2
  WITH ALGORITHM = RC2     
     , KEY_SOURCE = 'SYMKEY SOURCE'
     , IDENTITY_VALUE = 'symkeyRC2'
  ENCRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
GO
--IF KEY_GUID('#symkeyRC4') IS NULL
--  CREATE SYMMETRIC KEY #symkeyRC4
--  WITH ALGORITHM = RC4
--     , KEY_SOURCE = 'SYMKEY SOURCE'
--     , IDENTITY_VALUE = 'symkeyRC4'
--  ENCRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
GO
--IF KEY_GUID('#symkeyRC4_128') IS NULL
--  CREATE SYMMETRIC KEY #symkeyRC4_128
--  WITH ALGORITHM = RC4_128     
--     , KEY_SOURCE = 'SYMKEY SOURCE'
--     , IDENTITY_VALUE = 'symkeyRC4_128'
--  ENCRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
GO
IF KEY_GUID('#symkeyDESX') IS NULL
  CREATE SYMMETRIC KEY #symkeyDESX
  WITH ALGORITHM = DESX     
      , KEY_SOURCE = 'SYMKEY SOURCE'
      , IDENTITY_VALUE = 'symkeyDESX'
  ENCRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
GO
IF KEY_GUID('#symkeyAES_128') IS NULL
  CREATE SYMMETRIC KEY #symkeyAES_128
  WITH ALGORITHM = AES_128     
     , KEY_SOURCE = 'SYMKEY SOURCE'
     , IDENTITY_VALUE = 'symkeyAES_128'
  ENCRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
GO
IF KEY_GUID('#symkeyAES_192') IS NULL
  CREATE SYMMETRIC KEY #symkeyAES_192
  WITH ALGORITHM = AES_192
     , KEY_SOURCE = 'SYMKEY SOURCE'
     , IDENTITY_VALUE = 'symkeyAES_192'
  ENCRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
GO
IF KEY_GUID('#symkeyAES_256') IS NULL
  CREATE SYMMETRIC KEY #symkeyAES_256
  WITH ALGORITHM = AES_256     
     , KEY_SOURCE = 'SYMKEY SOURCE'
     , IDENTITY_VALUE = 'symkeyAES_256'
  ENCRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
GO
-- a certificate can encrypt up to 256 Bytes - nvarchar(128)
IF CERT_ID('cert') IS NULL
  CREATE CERTIFICATE cert
  ENCRYPTION BY PASSWORD = N'$(CERT_PHRASE)'
  WITH SUBJECT = 'CERTIFICATE SUBJECT';
GO
--a RSA_512 algorithm can encrypt up to 53 bytes - NVARCHAR(26)
--IF ASYMKEY_ID('asymkeyRSA_512') IS NULL
--  CREATE ASYMMETRIC KEY asymkeyRSA_512
--  WITH ALGORITHM = RSA_512  
--  ENCRYPTION BY PASSWORD = '$(ASYMKEY_PHRASE)';
GO
-- a 1024 bit key can encrypt up to 117 bytes - NVARCHAR(58)
IF ASYMKEY_ID('asymkeyRSA_1024') IS NULL
  CREATE ASYMMETRIC KEY asymkeyRSA_1024
  WITH ALGORITHM = RSA_1024 
  ENCRYPTION BY PASSWORD = '$(ASYMKEY_PHRASE)';
GO
-- a 2048 bit key can encrypt up to 245 bytes - NVARCHAR(122)
IF ASYMKEY_ID('asymkeyRSA_2048') IS NULL
  CREATE ASYMMETRIC KEY asymkeyRSA_2048
  WITH ALGORITHM = RSA_2048
  ENCRYPTION BY PASSWORD = '$(ASYMKEY_PHRASE)';
GO
DECLARE @CycleStartDT DATETIME
	  , @AddDT DATETIME
	  , @pwd CIPHER
      , @hashMD2 CIPHER
--      , @hashMD4 CIPHER
      , @hashMD5 CIPHER
      , @hashSHA CIPHER
      , @hashSHA1 CIPHER
      , @hashSHA2_256 CIPHER
      , @hashSHA2_512 CIPHER
      , @symkeyDES CIPHER
      , @symkeyTRIPLE_DES CIPHER
      , @symkeyTRIPLE_DES_3KEY CIPHER
      , @symkeyRC2 CIPHER
--      , @symkeyRC4 CIPHER
--      , @symkeyRC4_128 CIPHER
      , @symkeyDESX CIPHER
      , @symkeyAES_128 CIPHER
      , @symkeyAES_192 CIPHER
      , @symkeyAES_256 CIPHER

      , @cert CIPHER

--      , @asymkeyRSA_512 CIPHER
      , @asymkeyRSA_1024 CIPHER
      , @asymkeyRSA_2048 CIPHER;

  BEGIN TRY
  
	-- generate test data once per session
    IF ( SELECT COUNT(*) FROM #sample ) <  $(MAX_SAMPLE_SIZE)  
      BEGIN
	    BEGIN TRY
  	    SET @CycleStartDT = CURRENT_TIMESTAMP;
		  -- fill until it hits the RowId check constraint
          WHILE 1=1
            INSERT #sample ( RecCreatedDT )
	        VALUES (CURRENT_TIMESTAMP);
	    END TRY
	    BEGIN CATCH
          IF ERROR_NUMBER() = 547 -- check constraint
			BEGIN
			  SET @AddDT = CURRENT_TIMESTAMP;
			  INSERT dbo.TestTimes 
			    ( Method
  	            , Configurithm  
			    , Condition
				, SampleSize
                , TextBytes
				, CycleStartDT
				, AddDT
				, CipherBytes )
			  SELECT 'CRYPT_GEN_RANDOM'
			       , 'row-by-row'
				   , '+Identity'
				   , COUNT(*)
				   , 0
				   , @CycleStartDT
				   , @AddDT
				   , SUM(DATALENGTH(cleartext)) 
			  from #sample;
			END
		  ELSE
		    THROW;	 
	    END CATCH
      END

    -- include a GUID in a second otherwise equally random sample
    -- this will provide a cost basis for GUID-vs-IDENTITY
    IF ( SELECT COUNT(*) FROM #sample2 ) <  $(MAX_SAMPLE_SIZE)  
      BEGIN
  	    SET @CycleStartDT = CURRENT_TIMESTAMP;
        INSERT #sample2 ( RowId )
	    SELECT RowId FROM #sample;
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
		( Method
  		, Configurithm  
		, Condition
		, SampleSize
		, TextBytes
		, CycleStartDT
		, AddDT
		, CipherBytes )
		SELECT 'CRYPT_GEN_RANDOM'
			, 'set'
			, '+GUID'
			, COUNT(*)
			, 0
			, @CycleStartDT
			, @AddDT
			, SUM(DATALENGTH(cleartext)) 
		FROM #sample2;
      END

    -- no identity or GUID to create otherwise equally random sample
    -- this will provide a cost basis for GUID-vs-IDENTITY
    IF ( SELECT COUNT(*) FROM #sample3 ) <  $(MAX_SAMPLE_SIZE)  
      BEGIN
  	    SET @CycleStartDT = CURRENT_TIMESTAMP;
        INSERT #sample3 ( RowId )
	    SELECT RowId FROM #sample;
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
		( Method
  		, Configurithm  
		, Condition
		, SampleSize
		, TextBytes
		, CycleStartDT
		, AddDT
		, CipherBytes )
		SELECT 'CRYPT_GEN_RANDOM'
			, 'set'
			, '+Identity'
			, COUNT(*)
			, 0
			, @CycleStartDT
			, @AddDT
			, SUM(DATALENGTH(cleartext)) 
		FROM #sample3;
      END

    IF ( SELECT COUNT(*) FROM #sample4 ) <  $(MAX_SAMPLE_SIZE)  
      BEGIN
  	    SET @CycleStartDT = CURRENT_TIMESTAMP;
        INSERT #sample4 ( RowId )
	    SELECT RowId FROM #sample;
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
		( Method
  		, Configurithm  
		, Condition
		, SampleSize
		, TextBytes
		, CycleStartDT
		, AddDT
		, CipherBytes )
		SELECT 'CRYPT_GEN_RANDOM'
			, 'set'
			, 'none'
			, COUNT(*)
			, 0
			, @CycleStartDT
			, @AddDT
			, SUM(DATALENGTH(cleartext)) 
		FROM #sample4;
      END

	SET ROWCOUNT $(SAMPLE_SIZE);

	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @pwd (RowId, ciphertext)
	SELECT RowId, PWDENCRYPT ( cleartext ) 
	FROM #sample; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  	  ( Method
  	  , Configurithm
	  , Condition  
	  , SampleSize
	  , TextBytes
	  , CycleStartDT
	  , AddDT
	  , CipherBytes )
	SELECT 'Hash PWDCOMPARE'
		 , 'legacy'
		 , 'none'
		 , COUNT(*)
		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) ) 
   	FROM #sample AS a
	JOIN @pwd AS d
	ON a.RowId = d.RowId
	WHERE PWDCOMPARE ( a.cleartext, d.ciphertext ) = 1;

    -- MD2 and MD4 are broken, but SQL Server will still accept
	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @hashMD2 (RowId, ciphertext)
	SELECT RowId,  HASHBYTES ( 'MD2', cleartext ) FROM #sample; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  	  ( Method
  	  , Configurithm  
	  , Condition  
	  , SampleSize
	  , TextBytes
	  , CycleStartDT
	  , AddDT
	  , CipherBytes )
	SELECT 'Hash HASHBYTES'
		 , 'MD2'
		 , 'none'
		 , COUNT(*)
		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @hashMD2 AS d
	ON a.RowId = d.RowId
	WHERE HASHBYTES ( 'MD2', a.cleartext ) = d.ciphertext;  

    -- MD4 rejected by SQL Server 

	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @hashMD5 (RowId, ciphertext)
	SELECT RowId,  HASHBYTES ( 'MD5', cleartext ) FROM #sample; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  	  ( Method
  	  , Configurithm  
	  , Condition  
	  , SampleSize
	  , TextBytes
	  , CycleStartDT
	  , AddDT
	  , CipherBytes )
	SELECT 'Hash HASHBYTES'
		 , 'MD5'
		 , 'none'
		 , COUNT(*)
		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @hashMD5 AS d
	ON a.RowId = d.RowId
	WHERE HASHBYTES ( 'MD5', a.cleartext ) = d.ciphertext;  

	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @hashSHA (RowId, ciphertext)
	SELECT RowId,  HASHBYTES ( 'SHA', cleartext ) FROM #sample; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  	  ( Method
  	  , Configurithm  
	  , Condition  
	  , SampleSize
	  , TextBytes
	  , CycleStartDT
	  , AddDT
	  , CipherBytes )
	SELECT 'Hash HASHBYTES'
		 , 'SHA'
		 , 'none'
		 , COUNT(*)
		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @hashSHA AS d
	ON a.RowId = d.RowId
	WHERE HASHBYTES ( 'SHA', a.cleartext ) = d.ciphertext;  

	-- row-by-row test data once per testtimes table
    IF NOT EXISTS( SELECT * 
	               FROM dbo.TestTimes 
	               WHERE Method = 'Hash HASHBYTES'
  	               AND Configurithm = 'SHA1'
	               AND Condition = 'row-by-row')  
      BEGIN
        DELETE @hashSHA1;

        DECLARE @RowId INT;
        DECLARE rbr_cursor CURSOR 
		FOR SELECT RowId 
            FROM #sample
            ORDER BY RowId;
  
		SET @CycleStartDT = CURRENT_TIMESTAMP;

        OPEN rbr_cursor;
  
        FETCH NEXT FROM rbr_cursor 
        INTO @RowId;
  
        WHILE @@FETCH_STATUS = 0
          BEGIN
		    INSERT @hashSHA1 (RowId, ciphertext)
		    SELECT RowId,  HASHBYTES ( 'SHA1', cleartext ) 
			FROM #sample
			WHERE RowId = @RowId ; 

            FETCH NEXT FROM rbr_cursor 
            INTO @RowId;
          END 
        CLOSE rbr_cursor;
        DEALLOCATE rbr_cursor;
  		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  		  ( Method
  		  , Configurithm  
		  , Condition  
		  , SampleSize
		  , TextBytes
		  , CycleStartDT
		  , AddDT
		  , CipherBytes )
		SELECT 'Hash HASHBYTES'
			 , 'SHA1'
			 , 'row-by-row'
			 , COUNT(*)
			 , SUM( DATALENGTH(a.cleartext) )
			 , @CycleStartDT
			 , @AddDT
			 , SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample AS a
		JOIN @hashSHA1 AS d
		ON a.RowId = d.RowId
		WHERE HASHBYTES ( 'SHA1', a.cleartext ) = d.ciphertext;  
      END 

    DELETE @hashSHA1;
	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @hashSHA1 (RowId, ciphertext)
	SELECT RowId,  HASHBYTES ( 'SHA1', cleartext ) FROM #sample; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  	  ( Method
  	  , Configurithm  
	  , Condition  
	  , SampleSize
	  , TextBytes
	  , CycleStartDT
	  , AddDT
	  , CipherBytes )
	SELECT 'Hash HASHBYTES'
		 , 'SHA1'
		 , 'none'
		 , COUNT(*)
		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @hashSHA1 AS d
	ON a.RowId = d.RowId
	WHERE HASHBYTES ( 'SHA1', a.cleartext ) = d.ciphertext;  

    DELETE @hashSHA1;
	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @hashSHA1 (RowId, ciphertext)
	SELECT RowId,  HASHBYTES ( 'SHA1', cleartext + cast(RowId AS NVARCHAR(11) ) ) 
	FROM #sample; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  	  ( Method
  	  , Configurithm  
	  , Condition  
	  , SampleSize
	  , TextBytes
	  , CycleStartDT
	  , AddDT
	  , CipherBytes )
	SELECT 'Hash HASHBYTES'
		 , 'SHA1'
		 , '&RowId'
		 , COUNT(*)
		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @hashSHA1 AS d
	ON a.RowId = d.RowId
	WHERE HASHBYTES ( 'SHA1', a.cleartext + cast(a.RowId AS NVARCHAR(11) ) ) = d.ciphertext;  

    DELETE @hashSHA1;
	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @hashSHA1 (RowId, ciphertext)
	SELECT RowId,  HASHBYTES ( 'SHA1', cleartext + cast(RowGuid AS NCHAR(36) ) ) 
	FROM #sample2
	ORDER BY RowId; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  	  ( Method
  	  , Configurithm  
	  , Condition  
	  , SampleSize
	  , TextBytes
	  , CycleStartDT
	  , AddDT
	  , CipherBytes )
	SELECT 'Hash HASHBYTES'
		 , 'SHA1'
		 , '&RowGUID'
		 , COUNT(*)
		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample2 AS a
	JOIN @hashSHA1 AS d
	ON a.RowId = d.RowId
	WHERE HASHBYTES ( 'SHA1', a.cleartext + cast(a.RowGUID AS NCHAR(36) ) ) = d.ciphertext;  

	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @hashSHA2_256 (RowId, ciphertext)
	SELECT RowId,  HASHBYTES ( 'SHA2_256', cleartext ) FROM #sample; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  	  ( Method
  	  , Configurithm  
	  , Condition  
	  , SampleSize
	  , TextBytes
	  , CycleStartDT
	  , AddDT
	  , CipherBytes )
	SELECT 'Hash HASHBYTES'
		 , 'SHA2_256'
		 , 'none'
		 , COUNT(*)
		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @hashSHA2_256 AS d
	ON a.RowId = d.RowId
	WHERE HASHBYTES ( 'SHA2_256', a.cleartext ) = d.ciphertext;  

	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @hashSHA2_512 (RowId, ciphertext)
	SELECT RowId,  HASHBYTES ( 'SHA2_512', cleartext ) FROM #sample; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  	  ( Method
  	  , Configurithm  
	  , Condition  
	  , SampleSize
	  , TextBytes
	  , CycleStartDT
	  , AddDT
	  , CipherBytes )
	SELECT 'Hash HASHBYTES'
		 , 'SHA2_512'
		 , 'none'
		 , COUNT(*)
		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @hashSHA2_512 AS d
	ON a.RowId = d.RowId
	WHERE HASHBYTES ( 'SHA2_512', a.cleartext ) = d.ciphertext;  
    
    -- keep it open for 3 cycles
	OPEN SYMMETRIC KEY #symkeyDES
	DECRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';

		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyDES (RowId, ciphertext)
		SELECT a.RowId
			 , ENCRYPTBYKEY ( key_GUID('#symkeyDES'), a.cleartext ) 
		FROM #sample AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  		  ( Method
  		  , Configurithm  
   	      , Condition  
		  , SampleSize
		  , TextBytes
		  , CycleStartDT
		  , AddDT
		  , CipherBytes )
		SELECT 'Symmetric Key'
			 , 'DES'
			 , 'none'
			 , COUNT(*)
   		     , SUM( DATALENGTH(a.cleartext) )
			 , @CycleStartDT
			 , @AddDT
			 , SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample AS a
		JOIN @symkeyDES AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext ) AS NVARCHAR(4000) ) = a.cleartext;  

		DELETE @symkeyDES;

		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyDES (RowId, ciphertext)
		SELECT a.RowId
			 , ENCRYPTBYKEY ( key_GUID('#symkeyDES'), a.cleartext, 1, CAST( RowId AS NVARCHAR(58) ) ) 
		FROM #sample AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  		  ( Method
  		  , Configurithm  
   	      , Condition  
		  , SampleSize
		  , TextBytes
		  , CycleStartDT
		  , AddDT
		  , CipherBytes )
		SELECT 'Symmetric Key'
			 , 'DES'
			 , '@RowId'
			 , COUNT(*)
   		     , SUM( DATALENGTH(a.cleartext) )
			 , @CycleStartDT
			 , @AddDT
			 , SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample AS a
		JOIN @symkeyDES AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
								  , 1
								  , CAST( d.RowId AS NVARCHAR(58) ) ) AS NVARCHAR(58) ) = a.cleartext

		DELETE @symkeyDES;
	  
		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyDES (RowId, ciphertext)
		SELECT RowId
			,  ENCRYPTBYKEY ( key_GUID('#symkeyDES'), a.cleartext, 1, CAST( RowGUID AS NCHAR(36) ) ) 
		FROM #sample2 AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  		  ( Method
  		  , Configurithm  
   	      , Condition  
		  , SampleSize
		  , TextBytes
		  , CycleStartDT
		  , AddDT
		  , CipherBytes )
		SELECT 'Symmetric Key'
			 , 'DES'
			 , '@RowGUID'
			 , COUNT(*)
   		     , SUM( DATALENGTH(a.cleartext) )
			 , @CycleStartDT
			 , @AddDT
			 , SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample2 AS a
		JOIN @symkeyDES AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
								  , 1
								  , CAST( a.RowGUID AS NCHAR(36) ) ) 
					AS NVARCHAR(58) ) = a.cleartext
	CLOSE SYMMETRIC KEY #symkeyDES;
	
	OPEN SYMMETRIC KEY #symkeyTRIPLE_DES
	DECRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';

	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @symkeyTRIPLE_DES (RowId, ciphertext)
	SELECT a.RowId
			, ENCRYPTBYKEY ( key_GUID('#symkeyTRIPLE_DES'), a.cleartext, 1, CAST( RowId AS NVARCHAR(58) ) ) 
	FROM #sample AS a; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  		( Method
  		, Configurithm  
   	    , Condition  
		, SampleSize
		, TextBytes
		, CycleStartDT
		, AddDT
		, CipherBytes )
	SELECT 'Symmetric Key'
			, 'TRIPLE_DES'
			, '@RowId'
			, COUNT(*)
   		    , SUM( DATALENGTH(a.cleartext) )
			, @CycleStartDT
			, @AddDT
			, SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @symkeyTRIPLE_DES AS d
	ON a.RowId = d.RowId
	WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
								, 1
								, CAST( d.RowId AS NVARCHAR(58) ) ) AS NVARCHAR(58) ) = a.cleartext

	CLOSE SYMMETRIC KEY #symkeyTRIPLE_DES;

	
	OPEN SYMMETRIC KEY #symkeyTRIPLE_DES_3KEY
	DECRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyTRIPLE_DES_3KEY (RowId, ciphertext)
		SELECT a.RowId
				, ENCRYPTBYKEY ( key_GUID('#symkeyTRIPLE_DES_3KEY'), a.cleartext, 1, CAST( RowId AS NVARCHAR(58) ) ) 
		FROM #sample AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  			( Method
  			, Configurithm  
    	    , Condition  
			, SampleSize
			, TextBytes
			, CycleStartDT
			, AddDT
			, CipherBytes )
		SELECT 'Symmetric Key'
				, 'TRIPLE_DES_3KEY'
				, '@RowId'
				, COUNT(*)
   				, SUM( DATALENGTH(a.cleartext) )
				, @CycleStartDT
				, @AddDT
				, SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample AS a
		JOIN @symkeyTRIPLE_DES_3KEY AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
									, 1
									, CAST( d.RowId AS NVARCHAR(58) ) ) AS NVARCHAR(58) ) = a.cleartext
	CLOSE SYMMETRIC KEY #symkeyTRIPLE_DES_3KEY;
	
	OPEN SYMMETRIC KEY #symkeyRC2
	DECRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyRC2 (RowId, ciphertext)
		SELECT a.RowId
				, ENCRYPTBYKEY ( key_GUID('#symkeyRC2'), a.cleartext, 1, CAST( RowId AS NVARCHAR(58) ) ) 
		FROM #sample AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  			( Method
  			, Configurithm  
   	        , Condition  
			, SampleSize
			, TextBytes
			, CycleStartDT
			, AddDT
			, CipherBytes )
		SELECT 'Symmetric Key'
				, 'RC2'
				, '@RowId'
				, COUNT(*)
   				, SUM( DATALENGTH(a.cleartext) )
				, @CycleStartDT
				, @AddDT
				, SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample AS a
		JOIN @symkeyRC2 AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
									, 1
									, CAST( d.RowId AS NVARCHAR(58) ) ) AS NVARCHAR(58) ) = a.cleartext
	CLOSE SYMMETRIC KEY #symkeyRC2

    -- rejected by sql server
    --SET @Algorithm = 'RC4';
	--SET @Algorithm = 'RC4_128';

	OPEN SYMMETRIC KEY #symkeyDESX
	DECRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyDESX (RowId, ciphertext)
		SELECT a.RowId
				, ENCRYPTBYKEY ( key_GUID('#symkeyDESX'), a.cleartext, 1, CAST( RowId AS NVARCHAR(58) ) ) 
		FROM #sample AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  			( Method
  			, Configurithm  
   	        , Condition  
			, SampleSize
			, TextBytes
			, CycleStartDT
			, AddDT
			, CipherBytes )
		SELECT 'Symmetric Key'
				, 'DESX'
				, '@RowId'
				, COUNT(*)
   				, SUM( DATALENGTH(a.cleartext) )
				, @CycleStartDT
				, @AddDT
				, SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample AS a
		JOIN @symkeyDESX AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
									, 1
									, CAST( d.RowId AS NVARCHAR(58) ) ) AS NVARCHAR(58) ) = a.cleartext
	CLOSE SYMMETRIC KEY #symkeyDESX

	OPEN SYMMETRIC KEY #symkeyAES_128
	DECRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyAES_128 (RowId, ciphertext)
		SELECT a.RowId
				, ENCRYPTBYKEY ( key_GUID('#symkeyAES_128'), a.cleartext, 1, CAST( RowId AS NVARCHAR(58) ) ) 
		FROM #sample AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  			( Method
  			, Configurithm  
   	        , Condition  
			, SampleSize
			, TextBytes
			, CycleStartDT
			, AddDT
			, CipherBytes )
		SELECT 'Symmetric Key'
				, 'AES_128'
				, '@RowId'
				, COUNT(*)
   				, SUM( DATALENGTH(a.cleartext) )
				, @CycleStartDT
				, @AddDT
				, SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample AS a
		JOIN @symkeyAES_128 AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
									, 1
									, CAST( d.RowId AS NVARCHAR(58) ) ) AS NVARCHAR(58) ) = a.cleartext
	CLOSE SYMMETRIC KEY #symkeyAES_128

	OPEN SYMMETRIC KEY #symkeyAES_192
	DECRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyAES_192 (RowId, ciphertext)
		SELECT a.RowId
				, ENCRYPTBYKEY ( key_GUID('#symkeyAES_192'), a.cleartext, 1, CAST( RowId AS NVARCHAR(58) ) ) 
		FROM #sample AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  			( Method
  			, Configurithm  
   	        , Condition  
			, SampleSize
			, TextBytes
			, CycleStartDT
			, AddDT
			, CipherBytes )
		SELECT 'Symmetric Key'
				, 'AES_192'
				, '@RowId'
				, COUNT(*)
   				, SUM( DATALENGTH(a.cleartext) )
				, @CycleStartDT
				, @AddDT
				, SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample AS a
		JOIN @symkeyAES_192 AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
									, 1
									, CAST( d.RowId AS NVARCHAR(58) ) ) AS NVARCHAR(58) ) = a.cleartext
	CLOSE SYMMETRIC KEY #symkeyAES_192

	OPEN SYMMETRIC KEY #symkeyAES_256
	DECRYPTION BY PASSWORD = '$(SYMKEY_PHRASE)';
		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyAES_256 (RowId, ciphertext)
		SELECT a.RowId
				, ENCRYPTBYKEY ( key_GUID('#symkeyAES_256'), a.cleartext, 1, CAST( RowId AS NVARCHAR(58) ) ) 
		FROM #sample AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  			( Method
  			, Configurithm  
   	        , Condition  
			, SampleSize
			, TextBytes
			, CycleStartDT
			, AddDT
			, CipherBytes )
		SELECT 'Symmetric Key'
				, 'AES_256'
				, 'none'
				, COUNT(*)
   				, SUM( DATALENGTH(a.cleartext) )
				, @CycleStartDT
				, @AddDT
				, SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample AS a
		JOIN @symkeyAES_256 AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
									, 1
									, CAST( d.RowId AS NVARCHAR(58) ) ) AS NVARCHAR(58) ) = a.cleartext

        DELETE @symkeyAES_256;

		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyAES_256 (RowId, ciphertext)
		SELECT a.RowId
				, ENCRYPTBYKEY ( key_GUID('#symkeyAES_256'), a.cleartext, 1, CAST( RowId AS NVARCHAR(58) ) ) 
		FROM #sample AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  			( Method
  			, Configurithm  
   	        , Condition  
			, SampleSize
			, TextBytes
			, CycleStartDT
			, AddDT
			, CipherBytes )
		SELECT 'Symmetric Key'
				, 'AES_256'
				, '@RowId'
				, COUNT(*)
   				, SUM( DATALENGTH(a.cleartext) )
				, @CycleStartDT
				, @AddDT
				, SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample AS a
		JOIN @symkeyAES_256 AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
									, 1
									, CAST( d.RowId AS NVARCHAR(58) ) ) AS NVARCHAR(58) ) = a.cleartext

        DELETE @symkeyAES_256;

		SET @CycleStartDT = CURRENT_TIMESTAMP;
		INSERT @symkeyAES_256 (RowId, ciphertext)
		SELECT a.RowId
				, ENCRYPTBYKEY ( key_GUID('#symkeyAES_256')
				               , a.cleartext, 1, CAST( a.RowGUID AS NCHAR(36) ) ) 
		FROM #sample2 AS a; 
		SET @AddDT = CURRENT_TIMESTAMP;
		INSERT dbo.TestTimes 
  			( Method
  			, Configurithm  
   	        , Condition  
			, SampleSize
			, TextBytes
			, CycleStartDT
			, AddDT
			, CipherBytes )
		SELECT 'Symmetric Key'
			 , 'AES_256'
			 , '@RowGUID'
			 , COUNT(*)
   			 , SUM( DATALENGTH(a.cleartext) )
			 , @CycleStartDT
			 , @AddDT
			 , SUM( DATALENGTH(d.ciphertext) )
   		FROM #sample2 AS a
		JOIN @symkeyAES_256 AS d
		ON a.RowId = d.RowId
		WHERE CAST ( DECRYPTBYKEY ( d.ciphertext
								  , 1
								  , CAST( a.RowGUID AS NCHAR(36) ) ) 
					AS NVARCHAR(58) ) = a.cleartext
	CLOSE SYMMETRIC KEY #symkeyAES_256;

	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @cert (RowId, ciphertext)
	SELECT a.RowId
		 , ENCRYPTBYCERT ( CERT_ID( 'cert' ), a.cleartext )
	FROM #sample AS a; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  		( Method
  		, Configurithm  
   	    , Condition  
		, SampleSize
		, TextBytes
		, CycleStartDT
		, AddDT
		, CipherBytes )
	SELECT 'Certificate'
		 , 'PASSPHRASE'
		 , 'none'
		 , COUNT(*)
   		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @cert AS d
	ON a.RowId = d.RowId
	WHERE CAST ( DECRYPTBYCERT ( CERT_ID ( 'cert' )
								, d.ciphertext 
								, N'$(CERT_PHRASE)' ) 
				AS NVARCHAR(58) ) = a.cleartext;    
	
	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @asymkeyRSA_1024 (RowId, ciphertext)
	SELECT a.RowId
		 , ENCRYPTBYASYMKEY ( ASYMKEY_ID( 'asymkeyRSA_1024' )
							, a.cleartext )
	FROM #sample AS a; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  		( Method
  		, Configurithm  
   	    , Condition  
		, SampleSize
		, TextBytes
		, CycleStartDT
		, AddDT
		, CipherBytes )
	SELECT 'Asymmetric Key'
		 , 'RSA_1024'
		 , 'none'
		 , COUNT(*)
   		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @asymkeyRSA_1024 AS d
	ON a.RowId = d.RowId
	WHERE CAST ( DECRYPTBYASYMKEY ( ASYMKEY_ID( 'asymkeyRSA_1024' )
									, d.ciphertext
									, N'$(ASYMKEY_PHRASE)' ) 
				AS NVARCHAR(58) ) = a.cleartext;    

	SET @CycleStartDT = CURRENT_TIMESTAMP;
	INSERT @asymkeyRSA_2048 (RowId, ciphertext)
	SELECT a.RowId
		 , ENCRYPTBYASYMKEY ( ASYMKEY_ID( 'asymkeyRSA_2048' )
							, a.cleartext )
	FROM #sample AS a; 
	SET @AddDT = CURRENT_TIMESTAMP;
	INSERT dbo.TestTimes 
  		( Method
  		, Configurithm  
	   	, Condition  
	    , SampleSize
		, TextBytes
		, CycleStartDT
		, AddDT
		, CipherBytes )
	SELECT 'Asymmetric Key'
		 , 'RSA_2048'
		 , 'none'
		 , COUNT(*)
   		 , SUM( DATALENGTH(a.cleartext) )
		 , @CycleStartDT
		 , @AddDT
		 , SUM( DATALENGTH(d.ciphertext) )
   	FROM #sample AS a
	JOIN @asymkeyRSA_2048 AS d
	ON a.RowId = d.RowId
	WHERE CAST ( DECRYPTBYASYMKEY ( ASYMKEY_ID( 'asymkeyRSA_2048' )
									, d.ciphertext
									, N'$(ASYMKEY_PHRASE)' ) 
				AS NVARCHAR(58) ) = a.cleartext;    
  END TRY
  BEGIN CATCH
    THROW;
  END CATCH
GO
SET ROWCOUNT 0;
GO
SELECT Method
     , Configurithm
	 , Condition
	 , SUM(SampleSize) AS SampleSize
	 , COUNT(*) AS Test_Cycles
	 , AVG(TextBytes)/CAST( Sum(SampleSize) AS REAL ) AS TextBytes 
	 , SUM(Encode_Duration)/CAST( SUM(SampleSize) AS REAL ) AS EncodeRate
	 , AVG(CipherBytes)/CAST( Sum(SampleSize) AS REAL ) AS CryptoBytes 
	 , SUM(Use_Duration)/CAST( Sum(SampleSize) AS REAL ) AS DecodeRate
FROM dbo.TestTimes
GROUP BY Method
    , Configurithm
	, Condition 
	, SampleSize
ORDER BY Method
    , Configurithm
	, Condition 
	, SampleSize;

GO
SELECT Method
     , Configurithm
     , Condition
     , SampleSize
     , CASE WHEN Method = 'CRYPT_GEN_RANDOM' 
            THEN 0 ELSE (SELECT SUM(DATALENGTH(cleartext))/COUNT(*) from #sample) END AS TextBytes 
     , Encode_Duration/CAST(SampleSize AS REAL) AS EncodeRate
     , CipherBytes/CAST(SampleSize AS REAL) AS CipherBytes
     , Use_Duration/CAST(SampleSize AS REAL) AS DecodeRate
FROM dbo.TestTimes
ORDER BY Method, Configurithm, Condition, SampleSize;

